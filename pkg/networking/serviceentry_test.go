// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networking

import (
	"slices"
	"testing"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	httpstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	networkstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestServiceEntryEndpointBindings(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	for _, legacy := range []bool{false, true} {
		inputs := Inputs{
			LegacyGateway: legacy,
			Gateway: testGateway(&configv1.EgressGateway{ServiceEntries: []*configv1.EgressServiceEntry{
				{
					Hosts:     []string{"a.example"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "192.0.2.1"}, {Address: "192.0.2.2"}},
				},
				{
					Hosts:     []string{"b.example"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "192.0.2.1"}},
				},
			}}),
			GlobalExtProc:    &configv1.ExtProcProvider{Service: "epe", Port: 9002},
			DiscoveryAddress: "agentiod:15012",
			TrustDomain:      "cluster.local",
		}
		resources, err := Build(inputs)
		if err != nil {
			t.Fatal(err)
		}
		listeners := messagesOf(
			t,
			resources,
			model.ListenerType,
			func() *listener.Listener { return &listener.Listener{} },
		)
		internal := listeners[MainInternal]
		endpoints := routingMatcher(internal).GetMatcherTree().GetExactMatchMap().GetMap()
		if len(endpoints) != 2 {
			t.Fatalf("endpoint matches = %d, want 2 distinct IPs", len(endpoints))
		}
		for ip, wantHosts := range map[string][]string{
			"192.0.2.1": {"a.example", "a.example.", "b.example", "b.example."},
			"192.0.2.2": {"a.example", "a.example."},
		} {
			binding := endpoints[ip].GetMatcher().GetMatcherTree().GetExactMatchMap().GetMap()["tls"].GetMatcher()
			if binding.GetOnNoMatch().GetAction().GetName() != serviceEntryDenyChain {
				t.Fatal("unknown/missing SNI must deny without ordinary forwarding fallback")
			}
			domains := &xdsmatcher.ServerNameMatcher{}
			if err := binding.GetMatcherTree().GetCustomMatch().GetTypedConfig().UnmarshalTo(domains); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(domains.DomainMatchers[0].Domains, wantHosts) {
				t.Fatalf("legacy=%t ip=%s hosts=%v, want %v", legacy, ip, domains.DomainMatchers[0].Domains, wantHosts)
			}
			policy := domains.DomainMatchers[0].GetOnMatch().GetMatcher().GetMatcherTree().GetExactMatchMap().GetMap()["tls"].GetMatcher()
			actions := policy.GetMatcherTree().GetExactMatchMap().GetMap()
			passthrough := forwardTCPChain
			if legacy {
				passthrough = "service-entry|" + ip + "|tls"
			}
			if actions["deny"].GetAction().GetName() != sniDenyChain ||
				actions["terminate"].GetAction().GetName() != tlsTerminateChain ||
				actions["passthrough"].GetAction().GetName() != passthrough {
				t.Fatal("endpoint binding bypassed the TLS policy decision")
			}
			for _, name := range []string{MainInternal, MainForward} {
				chain := findFilterChain(t, listeners[name], "service-entry|"+ip+"|http")
				manager := findHCM(t, &listener.Listener{FilterChains: []*listener.FilterChain{chain}})
				names := httpFilterNames(manager)
				if !slices.Equal(names[:2], []string{"agentio.service_entry_host", "agentio.endpoint_upstream"}) ||
					slices.Index(names, "envoy.filters.http.ext_proc") < 2 {
					t.Fatal("Host binding and explicit target must precede EPE")
				}
				wrapper := &matching.ExtensionWithMatcher{}
				if err := manager.HttpFilters[1].GetTypedConfig().UnmarshalTo(wrapper); err != nil {
					t.Fatal(err)
				}
				target := &httpstate.Config{}
				if err := wrapper.ExtensionConfig.GetTypedConfig().UnmarshalTo(target); err != nil {
					t.Fatal(err)
				}
				state := target.OnRequestHeaders[0]
				key := model.FilterStateRouteUpstream
				if state.GetObjectKey() != key || state.ReadOnly != legacy ||
					state.GetFormatString().GetTextFormatSource().GetInlineString() != "%DOWNSTREAM_LOCAL_ADDRESS%" {
					t.Fatal("endpoint target must retain the authenticated original IP:port")
				}
				if !legacy && name == MainForward {
					identity := &matching.ExtensionWithMatcher{}
					if err := manager.HttpFilters[slices.Index(names, connectProxyTLSIdentityFilter)].
						GetTypedConfig().UnmarshalTo(identity); err != nil {
						t.Fatal(err)
					}
					settings := &httpstate.Config{}
					if err := identity.ExtensionConfig.GetTypedConfig().UnmarshalTo(settings); err != nil {
						t.Fatal(err)
					}
					if settings.OnRequestHeaders[2].GetFormatString().GetTextFormatSource().GetInlineString() !=
						"%DOWNSTREAM_LOCAL_ADDRESS%" {
						t.Fatal("CONNECT must preserve the bound proxy endpoint")
					}
				}
			}
			if !legacy {
				clusters := messagesOf(
					t,
					resources,
					model.ClusterType,
					func() *cluster.Cluster { return &cluster.Cluster{} },
				)
				for _, tc := range []struct {
					listener string
					chain    string
					cluster  string
				}{
					{MainInternal, forwardTCPChain, PassthroughCluster},
					{MainForward, serviceEntryTCPChain, TLSEndpointOriginate},
				} {
					chain := findFilterChain(t, listeners[tc.listener], tc.chain)
					for _, filter := range chain.Filters {
						if filter.Name == "envoy.filters.network.sni_dynamic_forward_proxy" {
							t.Fatal("fixed endpoint must not use DFP")
						}
					}
					proxy := &tcp.TcpProxy{}
					if err := chain.Filters[len(chain.Filters)-1].GetTypedConfig().UnmarshalTo(proxy); err != nil {
						t.Fatal(err)
					}
					if proxy.GetCluster() != tc.cluster ||
						clusters[tc.cluster].GetType() != cluster.Cluster_ORIGINAL_DST {
						t.Fatal("fixed endpoint must use ORIGINAL_DST")
					}
					if tc.listener == MainForward {
						identity := &networkstate.Config{}
						if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(identity); err != nil {
							t.Fatal(err)
						}
						if len(identity.OnNewConnection) != 2 {
							t.Fatal("TLS identity must not select a dynamic target")
						}
						context := &tls.UpstreamTlsContext{}
						if err := clusters[tc.cluster].TransportSocket.GetTypedConfig().
							UnmarshalTo(context); err != nil {
							t.Fatal(err)
						}
						if context.CommonTlsContext.GetValidationContext().GetTrustedCa() == nil ||
							len(context.CommonTlsContext.AlpnProtocols) != 0 {
							t.Fatal("endpoint TCP must validate TLS without advertising HTTP")
						}
					}
				}
				forward := routingMatcher(listeners[MainForward]).GetMatcherTree().GetExactMatchMap().GetMap()
				if forward[ip].GetMatcher().GetOnNoMatch().GetAction().GetName() != serviceEntryTCPChain {
					t.Fatal("fixed endpoints must share the original-destination TCP chain after termination")
				}
			}
		}
		if !legacy {
			for _, name := range []string{MainInternal, MainForward} {
				baseChains := 5
				if name == MainForward {
					baseChains = 3
				}
				if got, want := len(listeners[name].FilterChains), baseChains+len(endpoints)+1; got != want {
					t.Fatalf("%s has %d chains, want %d without per-endpoint TCP/TLS copies", name, got, want)
				}
			}
		}
		// Ordinary Host routing settings remain independent of ServiceEntry identity.
		routes := messagesOf(
			t,
			resources,
			model.RouteType,
			func() *route.RouteConfiguration { return &route.RouteConfiguration{} },
		)
		for _, name := range []string{(&resourceBuilder{legacyGateway: legacy}).httpForwardName(), TLSConnectOriginate} {
			if got := routes[name].VirtualHosts; len(got) != 1 || !slices.Equal(got[0].Domains, []string{"*"}) {
				t.Fatalf("ServiceEntries generated host-selected routes: %v", got)
			}
		}
		inputs.Gateway = testGateway(nil)
		baseline, err := Build(inputs)
		if err != nil {
			t.Fatal(err)
		}
		baselineListeners := messagesOf(
			t,
			baseline,
			model.ListenerType,
			func() *listener.Listener { return &listener.Listener{} },
		)
		if !proto.Equal(
			routingMatcher(internal).GetOnNoMatch().GetMatcher(),
			routingMatcher(baselineListeners[MainInternal]),
		) {
			t.Fatal("unmatched IP changed ordinary routing/policy behavior")
		}
	}
}
