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
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	matchinginputv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	ipmatcherv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/input_matchers/ip/v3"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayTCPPassthrough(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		gateway, err := config.Apply(`
tcpPassthrough:
- cidrs: [10.20.1.2/16, '2001:db8::/32']
  ports: [3306, 5432]
- ports: [6379]
- cidrs: [192.168.10.20/32]
tcp:
  idleTimeout: 23s
  maxConnectionDuration: 420s
`, &configv1.EgressGateway{})
		if err != nil {
			t.Fatal(err)
		}
		resources, err := Build(
			Inputs{
				LegacyGateway:    legacy,
				DiscoveryAddress: "agentiod:15012",
				TrustDomain:      "cluster.local",
				Gateway:          testGateway(gateway),
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		listeners := messagesOf(
			t,
			resources,
			model.ListenerType,
			func() *listenerv3.Listener { return &listenerv3.Listener{} },
		)
		for _, filter := range findHCM(t, listeners[ConnectTerminate]).HttpFilters {
			if filter.Name != "agentio.connect_authority" && filter.Name != "connect_authority" {
				continue
			}
			capture := &setstatehttpv3.Config{}
			if err := filter.GetTypedConfig().UnmarshalTo(capture); err != nil {
				t.Fatal(err)
			}
			if !capture.ClearRouteCache {
				t.Fatal("CIDR routing uses a stale route before destination capture")
			}
		}
		listener := listeners[TCPPassthrough]
		if listener == nil || len(listener.ListenerFilters) != 1 ||
			listener.ListenerFilters[0].Name != "envoy.filters.listener.original_dst" {
			t.Fatalf("legacy=%t: passthrough must not run protocol inspectors: %v", legacy, listener)
		}
		chain := listener.FilterChains[0]
		if chain.TransportSocket != nil {
			t.Fatal("TCP passthrough must preserve TLS bytes")
		}
		tcp := &tcpproxyv3.TcpProxy{}
		if err := chain.Filters[len(chain.Filters)-1].GetTypedConfig().UnmarshalTo(tcp); err != nil {
			t.Fatal(err)
		}
		if tcp.GetCluster() != PassthroughCluster || tcp.IdleTimeout.AsDuration() != 23*time.Second ||
			tcp.MaxDownstreamConnectionDuration.AsDuration() != 7*time.Minute {
			t.Fatalf("TCP forwarding lost its target or limits: %v", tcp)
		}
		clusters := messagesOf(
			t,
			resources,
			model.ClusterType,
			func() *clusterv3.Cluster { return &clusterv3.Cluster{} },
		)
		if clusters[TCPPassthrough] == nil {
			t.Fatal("missing internal TCP cluster")
		}
		routes := messagesOf(
			t,
			resources,
			model.RouteType,
			func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} },
		)
		vhost := routes[ConnectTerminate].VirtualHosts[0]
		matches := vhost.GetMatcher().GetMatcherList().GetMatchers()
		if len(vhost.Routes) != 0 || len(matches) != 3 {
			t.Fatalf("CONNECT must use a matcher instead of routes: %v", vhost)
		}
		for _, match := range matches {
			route := &routev3.Route{}
			if err := match.OnMatch.GetAction().TypedConfig.UnmarshalTo(route); err != nil {
				t.Fatal(err)
			}
			if route.GetRoute().GetCluster() != TCPPassthrough || len(route.Match.Headers) != 0 ||
				len(route.Match.FilterState) != 0 {
				t.Fatalf("passthrough route must not reparse authority: %v", route)
			}
		}
		predicates := matches[0].Predicate.GetAndMatcher().Predicate
		address := predicates[1].GetSinglePredicate()
		input := &matchinginputv3.FilterStateInput{}
		if err := address.Input.TypedConfig.UnmarshalTo(input); err != nil {
			t.Fatal(err)
		}
		cidrs := &ipmatcherv3.Ip{}
		if err := address.GetCustomMatch().TypedConfig.UnmarshalTo(cidrs); err != nil {
			t.Fatal(err)
		}
		if input.Key != "envoy.filters.listener.original_dst.local_ip" || input.Field != "ip" ||
			cidrs.CidrRanges[0].AddressPrefix != "10.20.0.0" {
			t.Fatalf("must match normalized original destination: input=%v CIDRs=%v", input, cidrs)
		}
		for index, port := range predicates[2].GetOrMatcher().Predicate {
			value := port.GetSinglePredicate()
			if err := value.Input.TypedConfig.UnmarshalTo(input); err != nil {
				t.Fatal(err)
			}
			if input.Field != "port" || value.GetValueMatch().GetExact() != []string{"3306", "5432"}[index] {
				t.Fatalf("port must use an exact field match: %v", value)
			}
		}
		if len(matches[1].Predicate.GetAndMatcher().Predicate) != 2 ||
			len(matches[2].Predicate.GetAndMatcher().Predicate) != 2 {
			t.Fatal("port-only or CIDR-only matching changed")
		}
	}
}

func TestTCPPassthroughMatcherPreservesAdmission(t *testing.T) {
	b := &resourceBuilder{}
	routes, err := b.buildRoutes(&configv1.EgressGateway{
		TcpPassthrough:          []*configv1.TcpPassthroughMatch{{}},
		BandwidthLimit:          &configv1.BandwidthLimitSettings{},
		ConnectConcurrencyLimit: &configv1.ConnectConcurrencyLimitSettings{},
	})
	if err != nil {
		t.Fatal(err)
	}
	matcher := routes[0].VirtualHosts[0].Matcher
	fallback := &routev3.RouteList{}
	if err := matcher.OnNoMatch.GetAction().TypedConfig.UnmarshalTo(fallback); err != nil {
		t.Fatal(err)
	}
	passthrough := &routev3.Route{}
	if err := matcher.GetMatcherList().Matchers[0].OnMatch.GetAction().TypedConfig.UnmarshalTo(
		passthrough,
	); err != nil {
		t.Fatal(err)
	}
	if fallback.Routes[len(fallback.Routes)-1].GetRoute().GetCluster() != MainInternal {
		t.Fatal("unmatched CONNECT lost its default route")
	}
	for _, name := range []string{bandwidthFilterName, concurrencyFilterName} {
		if passthrough.TypedPerFilterConfig[name] == nil ||
			!proto.Equal(
				passthrough.TypedPerFilterConfig[name],
				fallback.Routes[len(fallback.Routes)-1].TypedPerFilterConfig[name],
			) {
			t.Fatalf("passthrough lost per-route admission: %s", name)
		}
	}
}

func TestGatewayTCPPassthroughOmitted(t *testing.T) {
	resources, err := Build(
		Inputs{DiscoveryAddress: "agentiod:15012", TrustDomain: "cluster.local", Gateway: testGateway(nil)},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range resources {
		if resource.XDSName == TCPPassthrough {
			t.Fatal("omitted tcpPassthrough added a forwarding path")
		}
	}
}
