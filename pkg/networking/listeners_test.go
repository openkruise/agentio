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

	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extensionmatchingv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	localratelimitv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	setstatenetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	rlexprv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/rate_limit_descriptors/expr/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpupstreamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"google.golang.org/protobuf/types/known/durationpb"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayHTTP10(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		accept  bool
	}{
		{name: "default", content: "{}", accept: true},
		{name: "empty-http", content: "http: {}", accept: true},
		{name: "enabled", content: "http: {acceptHttp10: true}", accept: true},
		{name: "disabled", content: "http: {acceptHttp10: false}", accept: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway, err := config.Apply(tc.content, &configv1.EgressGateway{})
			if err != nil {
				t.Fatal(err)
			}
			for _, legacy := range []bool{false, true} {
				resources, err := Build(Inputs{
					LegacyGateway:    legacy,
					DiscoveryAddress: "agentiod.agentio-system.svc:15012",
					TrustDomain:      "cluster.local",
					Gateway:          testGateway(gateway),
				})
				if err != nil {
					t.Fatal(err)
				}
				listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener {
					return &listenerv3.Listener{}
				})
				for _, name := range []string{MainInternal, MainForward} {
					matcher := listeners[name].GetFilterChainMatcher()
					if name == MainInternal {
						matcher = matcher.GetOnNoMatch().GetMatcher()
					}
					if chain := matcher.GetMatcherTree().GetExactMatchMap().GetMap()["'http/1.0'"].
						GetAction().GetName(); chain != forwardHTTPChain {
						t.Errorf(
							"legacy=%v listener=%s: HTTP/1.0 routes to %q, want HTTP enforcement",
							legacy,
							name,
							chain,
						)
					}
					options := findHCM(t, listeners[name]).GetHttpProtocolOptions()
					if options.GetAcceptHttp_10() != tc.accept || options.GetDefaultHostForHttp_10() != "" {
						t.Errorf(
							"legacy=%v listener=%s: HTTP/1 options = %v, want acceptHttp10=%v without default host",
							legacy,
							name,
							options,
							tc.accept,
						)
					}
				}
				if findHCM(t, listeners[ConnectTerminate]).GetHttpProtocolOptions().GetAcceptHttp_10() {
					t.Errorf("legacy=%v: HTTP/1.0 enabled on outer CONNECT listener", legacy)
				}
			}
		})
	}
}

func TestConnectRateLimitPreservesDescriptorGroupsAndValues(t *testing.T) {
	b := &resourceBuilder{}
	bucket := &configv1.TokenBucket{MaxTokens: 10, TokensPerFill: 10, FillInterval: durationpb.New(time.Second)}
	settings := &configv1.LocalRateLimitSettings{Descriptors: []*configv1.RateLimitDescriptor{
		{Entries: []*configv1.RateLimitEntry{{Key: "namespace", Cel: `"demo"`}}, TokenBucket: bucket},
		{
			Entries: []*configv1.RateLimitEntry{
				{Key: "namespace", Cel: `"other"`},
				{Key: "workload", Cel: `"app"`},
				{Key: "scope", Value: "gateway"},
			},
			TokenBucket: bucket,
		},
	}}
	filter, err := b.localRateLimitFilter(settings)
	if err != nil {
		t.Fatal(err)
	}
	config := &localratelimitv3.LocalRateLimit{}
	if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
		t.Fatal(err)
	}
	if len(config.GetRateLimits()) != 2 {
		t.Fatalf("rate limit groups = %d, want 2", len(config.GetRateLimits()))
	}
	for i, descriptor := range settings.GetDescriptors() {
		actions := config.GetRateLimits()[i].GetActions()
		if len(actions) != len(descriptor.GetEntries()) {
			t.Fatalf("descriptor %d: wrong action count %d", i, len(actions))
		}
		for j, entry := range descriptor.GetEntries() {
			if entry.GetCel() == "" {
				generic := actions[j].GetGenericKey()
				if generic.GetDescriptorKey() != entry.GetKey() || generic.GetDescriptorValue() != entry.GetValue() {
					t.Fatalf("static descriptor entry lost: %v", generic)
				}
				continue
			}
			expression := &rlexprv3.Descriptor{}
			if err := actions[j].GetExtension().GetTypedConfig().UnmarshalTo(expression); err != nil {
				t.Fatal(err)
			}
			if expression.GetDescriptorKey() != entry.GetKey() || expression.GetText() != entry.GetCel() {
				t.Fatalf("descriptor %d entry %d changed key, order, or expression: %v", i, j, expression)
			}
		}
	}
}

// Application CONNECT is proxied to the original explicit proxy; it is not the
// HBONE CONNECT terminator.
func TestGatewayForwardProxyConnectSemantics(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	proxyTLS := clusters["tls_proxy_originate"]
	if proxyTLS == nil {
		t.Fatal("TLS proxy origination cluster not found")
	}
	if proxyTLS.GetType() != clusterv3.Cluster_ORIGINAL_DST ||
		proxyTLS.GetLbPolicy() != clusterv3.Cluster_CLUSTER_PROVIDED {
		t.Fatalf(
			"TLS proxy cluster type/lb = %v/%v, want ORIGINAL_DST/CLUSTER_PROVIDED",
			proxyTLS.GetType(),
			proxyTLS.GetLbPolicy(),
		)
	}
	protocol := &httpupstreamv3.HttpProtocolOptions{}
	if err := proxyTLS.GetTypedExtensionProtocolOptions()[httpProtocolOptionsType].UnmarshalTo(protocol); err != nil {
		t.Fatalf("decode TLS proxy HTTP options: %v", err)
	}
	if protocol.GetAutoConfig() == nil || protocol.GetUpstreamHttpProtocolOptions().GetAutoSni() ||
		protocol.GetUpstreamHttpProtocolOptions().GetAutoSanValidation() {
		t.Fatalf("TLS proxy HTTP options = %+v", protocol)
	}
	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := proxyTLS.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("decode TLS proxy transport socket: %v", err)
	}
	if tlsContext.GetCommonTlsContext().
		GetValidationContext().
		GetTrustedCa().
		GetFilename() !=
		features.ResolveGatewayRootCAPath() {
		t.Fatalf("TLS proxy trusted CA = %+v", tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa())
	}

	routes := messagesOf(
		t,
		resources,
		model.RouteType,
		func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} },
	)
	for routeName, clusterName := range map[string]string{
		HTTPDynamicForwardProxy: PassthroughCluster,
		TLSConnectOriginate:     "tls_proxy_originate",
	} {
		for _, virtualHost := range routes[routeName].GetVirtualHosts() {
			got := virtualHost.GetRoutes()
			if len(got) != 2 || got[0].GetName() != "sandbox-connect" || got[1].GetName() != "default" {
				t.Fatalf("route %s virtual host %s routes = %+v", routeName, virtualHost.GetName(), got)
			}
			connect := got[0]
			if connect.GetMatch().GetConnectMatcher() == nil || connect.GetRoute().GetCluster() != clusterName ||
				connect.GetRoute().GetTimeout().AsDuration() != 0 || len(connect.GetRoute().GetUpgradeConfigs()) != 1 ||
				connect.GetRoute().GetUpgradeConfigs()[0].GetUpgradeType() != "CONNECT" ||
				connect.GetRoute().GetUpgradeConfigs()[0].GetConnectConfig() != nil {
				t.Fatalf("route %s CONNECT = %+v", routeName, connect)
			}
		}
	}

	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	clearHCM := findHCM(t, listeners[MainInternal])
	tlsHCM := findHCM(t, listeners[MainForward])
	if !clearHCM.GetHttp2ProtocolOptions().GetAllowConnect() || !tlsHCM.GetHttp2ProtocolOptions().GetAllowConnect() {
		t.Fatal("both forward HCMs must allow HTTP/2 CONNECT")
	}
	if hasHTTPFilter(clearHCM, connectProxyTLSIdentityFilter) {
		t.Fatal("clear HTTP proxy gained TLS identity filter")
	}
	var identity *hcmv3.HttpFilter
	for _, filter := range tlsHCM.GetHttpFilters() {
		if filter.GetName() == connectProxyTLSIdentityFilter {
			identity = filter
			break
		}
	}
	if identity == nil {
		t.Fatal("HTTPS proxy TLS identity filter not found")
	}
	wrapper := &extensionmatchingv3.ExtensionWithMatcher{}
	if err := identity.GetTypedConfig().UnmarshalTo(wrapper); err != nil {
		t.Fatalf("decode TLS identity wrapper: %v", err)
	}
	if err := wrapper.ValidateAll(); err != nil {
		t.Fatalf("validate TLS identity wrapper: %v", err)
	}
	matchers := wrapper.GetXdsMatcher().GetMatcherList().GetMatchers()
	if len(matchers) != 1 {
		t.Fatalf("TLS identity matcher count = %d", len(matchers))
	}
	notConnect := matchers[0].GetPredicate().GetNotMatcher().GetSinglePredicate()
	method := &matcherv3.HttpRequestHeaderMatchInput{}
	if notConnect == nil || notConnect.GetInput().GetTypedConfig().UnmarshalTo(method) != nil ||
		method.GetHeaderName() != ":method" || notConnect.GetValueMatch().GetExact() != "CONNECT" {
		t.Fatalf("TLS identity method matcher = %+v", notConnect)
	}
	setState := &setstatehttpv3.Config{}
	if err := wrapper.GetExtensionConfig().GetTypedConfig().UnmarshalTo(setState); err != nil {
		t.Fatalf("decode TLS identity set-filter-state: %v", err)
	}
	values := setState.GetOnRequestHeaders()
	if len(values) != 2 || values[0].GetObjectKey() != "envoy.network.upstream_server_name" ||
		values[1].GetObjectKey() != "envoy.network.upstream_subject_alt_names" {
		t.Fatalf("TLS identity values = %+v", values)
	}
}

func TestSNIHostMismatchConditionUsesProxyAuthorityForConnect(t *testing.T) {
	environment, err := cel.NewEnv(
		cel.Variable("request", cel.DynType),
		cel.Variable("filter_state", cel.MapType(cel.StringType, cel.BytesType)),
		ext.Strings(),
	)
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := environment.Compile(sniHostMismatchExprText)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile SNI mismatch expression: %v", issues.Err())
	}
	program, err := environment.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, host string
		want               bool
	}{
		{name: "ordinary mismatch denied", method: "GET", host: "target.example:443", want: true},
		{name: "CONNECT target differs from proxy SNI", method: "CONNECT", host: "target.example:443", want: false},
		{name: "ordinary match allowed", method: "GET", host: "proxy.example:8443", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, _, err := program.Eval(map[string]any{
				"request":      map[string]any{"method": tc.method, "host": tc.host},
				"filter_state": map[string][]byte{outerSNIKey: []byte("proxy.example")},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := result.Value().(bool); !ok || got != tc.want {
				t.Fatalf("condition = %v (%T), want %v", result.Value(), result.Value(), tc.want)
			}
		})
	}
}

func TestBuildWithoutSNITrafficPolicyUsesProtocolMatcher(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service: "ext-proc.agentio-system.svc.cluster.local",
			Port:    9002,
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	internal := listeners[MainInternal]
	gotChains := make([]string, 0, len(internal.GetFilterChains()))
	for _, chain := range internal.GetFilterChains() {
		gotChains = append(gotChains, chain.GetName())
	}
	if want := []string{forwardHTTPChain, forwardTCPChain}; !equalStrings(gotChains, want) {
		t.Fatalf("MainInternal filter chains = %v, want %v without SNI policy runtime", gotChains, want)
	}
	tls := internal.GetFilterChainMatcher().GetMatcherTree().GetExactMatchMap().GetMap()["tls"]
	if got := tls.GetAction().GetName(); got != forwardTCPChain {
		t.Fatalf("TLS fallback chain = %q, want %q without SNI policy runtime", got, forwardTCPChain)
	}
}

func TestBuildStaticSNIMatcherOmitsEmptyHostGroups(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway: testGateway(&configv1.EgressGateway{
			TlsTermination: &configv1.TlsTerminationConfig{
				IncludeHosts: []string{"*.example.com"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	domains := &xdsmatcherv3.ServerNameMatcher{}
	if err := listeners[MainInternal].GetFilterChainMatcher().
		GetMatcherTree().
		GetCustomMatch().
		GetTypedConfig().
		UnmarshalTo(domains); err != nil {
		t.Fatalf("unmarshal static SNI matcher: %v", err)
	}
	for _, domain := range domains.GetDomainMatchers() {
		if len(domain.GetDomains()) == 0 {
			t.Fatalf("static SNI matcher contains an empty domain group: %+v", domains)
		}
	}
}

func TestPostTLSForwardingPreservesOuterDestination(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		resources := buildGatewayGraph(t, legacy)
		listeners := messagesOf(
			t,
			resources,
			model.ListenerType,
			func() *listenerv3.Listener { return &listenerv3.Listener{} },
		)
		forward := listeners[MainForward]
		var inspectors []string
		for _, filter := range forward.GetListenerFilters() {
			inspectors = append(inspectors, filter.GetName())
		}
		if !equalStrings(
			inspectors,
			[]string{"envoy.filters.listener.original_dst", "envoy.filters.listener.http_inspector"},
		) {
			t.Errorf("legacy=%v: post-TLS inspectors = %v, want original_dst and HTTP only", legacy, inspectors)
		}
		chain := findFilterChain(t, forward, forwardTCPChain)
		if !equalStrings(
			networkFilterNames(chain),
			[]string{"envoy.filters.network.set_filter_state", "envoy.filters.network.tcp_proxy"},
		) {
			t.Errorf(
				"legacy=%v: TCP filters = %v, want outer TLS identity and TCP proxy",
				legacy,
				networkFilterNames(chain),
			)
			continue
		}
		identity := &setstatenetworkv3.Config{}
		if err := chain.GetFilters()[0].GetTypedConfig().UnmarshalTo(identity); err != nil {
			t.Fatal(err)
		}
		values := identity.GetOnNewConnection()
		if len(values) != 2 {
			t.Fatalf("TCP TLS identity = %v, want SNI and SAN", values)
		}
		wantSNIKey := outerSNIKey
		if legacy {
			wantSNIKey = legacyOuterSNIKey
		}
		for i, key := range []string{upstreamServerNameKey, upstreamSubjectAltNamesKey} {
			if values[i].GetObjectKey() != key || values[i].GetFormatString().GetTextFormatSource().GetInlineString() !=
				"%FILTER_STATE("+wantSNIKey+":PLAIN)%" {
				t.Errorf("legacy=%v: TLS identity %s must use outer SNI: %v", legacy, key, values[i])
			}
		}
		proxy := &tcpproxyv3.TcpProxy{}
		if err := chain.GetFilters()[1].GetTypedConfig().UnmarshalTo(proxy); err != nil {
			t.Fatal(err)
		}
		if proxy.GetCluster() != TLSProxyOriginate {
			t.Errorf("TCP cluster = %q, want original-destination TLS", proxy.GetCluster())
		}
		clusters := messagesOf(
			t,
			resources,
			model.ClusterType,
			func() *clusterv3.Cluster { return &clusterv3.Cluster{} },
		)
		cluster := clusters[TLSProxyOriginate]
		if cluster.GetType() != clusterv3.Cluster_ORIGINAL_DST {
			t.Fatal("TCP must preserve the original destination address and port")
		}
		context := &tlsv3.UpstreamTlsContext{}
		if err := cluster.GetTransportSocket().GetTypedConfig().UnmarshalTo(context); err != nil {
			t.Fatal(err)
		}
		if alpn := context.GetCommonTlsContext().GetAlpnProtocols(); len(alpn) != 0 {
			t.Errorf("TCP must not advertise HTTP ALPN: %v", alpn)
		}
	}
}

func TestGatewayListenersUseSupportedAgentioSemantics(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)

	for name, want := range map[string][]string{
		MainInternal: {"envoy.filters.listener.original_dst", "envoy.filters.listener.http_inspector", "envoy.filters.listener.tls_inspector", "envoy.filters.listener.dynamic_modules"},
		MainForward:  {"envoy.filters.listener.original_dst", "envoy.filters.listener.http_inspector"},
	} {
		listener := listeners[name]
		got := make([]string, 0, len(listener.GetListenerFilters()))
		for _, filter := range listener.GetListenerFilters() {
			got = append(got, filter.GetName())
			if filter.GetName() == "envoy.filters.listener.tls_inspector" {
				config := &tlsinspectorv3.TlsInspector{}
				if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
					t.Fatalf("unmarshal %s TLS inspector: %v", name, err)
				}
				if config.GetInitialReadBufferSize().GetValue() != 16*1024 {
					t.Errorf(
						"listener %s TLS inspector initial read buffer = %d, want 16384",
						name,
						config.GetInitialReadBufferSize().GetValue(),
					)
				}
			}
		}
		if !equalStrings(got, want) {
			t.Errorf("listener %s filters = %v, want %v", name, got, want)
		}
	}

	tlsChain := findFilterChain(t, listeners[MainInternal], tlsTerminateChain)
	if got := tlsChain.GetTransportSocketConnectTimeout().AsDuration(); got != 15*time.Second {
		t.Errorf("TLS termination transport-socket connect timeout = %s, want 15s", got)
	}

	connectHCM := findHCM(t, listeners[ConnectTerminate])
	keepalive := connectHCM.GetHttp2ProtocolOptions().GetConnectionKeepalive()
	if got := keepalive.GetInterval().AsDuration(); got != 10*time.Second {
		t.Errorf("CONNECT keepalive interval = %s, want 10s", got)
	}
	if got := keepalive.GetTimeout().AsDuration(); got != 20*time.Second {
		t.Errorf("CONNECT keepalive timeout = %s, want 20s", got)
	}
	if connectHCM.GetForwardClientCertDetails() != hcmv3.HttpConnectionManager_SANITIZE ||
		connectHCM.GetSetCurrentClientCertDetails() != nil {
		t.Error("CONNECT must not propagate caller-controlled XFCC state")
	}

	for _, name := range []string{MainInternal, MainForward} {
		hcm := findHCM(t, listeners[name])
		if !hcm.Proxy_100Continue {
			t.Errorf("listener %s must proxy 100-continue responses", name)
		}
		if len(hcm.GetUpgradeConfigs()) != 1 || hcm.GetUpgradeConfigs()[0].GetUpgradeType() != "websocket" {
			t.Errorf("listener %s HCM websocket upgrades = %+v", name, hcm.GetUpgradeConfigs())
		}
	}
	for _, name := range []string{ConnectTerminate, MainInternal, MainForward} {
		hcm := findHCM(t, listeners[name])
		if hcm.GetServerName() != "" {
			t.Errorf("listener %s must leave server_name unset", name)
		}
		if hcm.GetServerHeaderTransformation() != hcmv3.HttpConnectionManager_PASS_THROUGH {
			t.Errorf("listener %s must preserve the upstream Server header without adding one", name)
		}
		router := &routerv3.Router{}
		if err := hcm.HttpFilters[len(hcm.HttpFilters)-1].GetTypedConfig().UnmarshalTo(router); err != nil {
			t.Fatal(err)
		}
		if !router.GetSuppressEnvoyHeaders() {
			t.Errorf("listener %s router must suppress generated x-envoy headers", name)
		}
	}
}

// A silent client must be disconnected after inspection expires, including
// when TLS termination or SNI policy changes the listener's matcher tree.
func TestGatewayProtocolDetectionTimeoutClosesConnection(t *testing.T) {
	for _, tc := range []struct {
		name           string
		legacyGateway  bool
		sniPolicy      bool
		tlsTermination *configv1.TlsTerminationConfig
	}{
		{name: "passthrough"},
		{name: "static TLS", tlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"*.example.com"}}},
		{name: "SNI policy", sniPolicy: true},
		{name: "legacy passthrough", legacyGateway: true},
		{name: "legacy static TLS", legacyGateway: true, tlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"*.example.com"}}},
		{name: "legacy SNI policy", legacyGateway: true, sniPolicy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test.SetForTest(t, &features.EnableSNITrafficPolicy, tc.sniPolicy)
			resources, err := Build(Inputs{
				LegacyGateway:    tc.legacyGateway,
				DiscoveryAddress: "agentiod.agentio-system.svc:15012",
				TrustDomain:      "cluster.local",
				Gateway: testGateway(&configv1.EgressGateway{
					TlsTermination: tc.tlsTermination,
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			listeners := messagesOf(
				t,
				resources,
				model.ListenerType,
				func() *listenerv3.Listener { return &listenerv3.Listener{} },
			)
			for _, name := range []string{MainInternal, MainForward} {
				listener := listeners[name]
				if timeout := listener.GetListenerFiltersTimeout(); timeout == nil ||
					timeout.AsDuration() != time.Second {
					t.Errorf("%s inspection timeout = %v, want 1s", name, timeout)
				}
				if listener.GetContinueOnListenerFiltersTimeout() {
					t.Errorf("%s must close the connection when inspection times out", name)
				}
				// Non-HTTP traffic that completes inspection retains TCP forwarding.
				fallback := listener.GetFilterChainMatcher().GetOnNoMatch()
				for fallback.GetMatcher() != nil {
					fallback = fallback.GetMatcher().GetOnNoMatch()
				}
				if got := fallback.GetAction().GetName(); got != forwardTCPChain {
					t.Fatalf("%s TCP fallback chain = %q, want %q", name, got, forwardTCPChain)
				}
				chain := findFilterChain(t, listener, forwardTCPChain)
				if got := chain.GetFilters()[len(chain.GetFilters())-1].GetName(); got != "envoy.filters.network.tcp_proxy" {
					t.Errorf("%s fallback ends with %q, want TCP proxy", name, got)
				}
			}
		})
	}
}
