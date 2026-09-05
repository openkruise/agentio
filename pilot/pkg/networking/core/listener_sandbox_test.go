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

package core

import (
	"slices"
	"testing"
	"time"

	typedstruct "github.com/cncf/xds/go/udpa/type/v1"
	matcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	extensionmatching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	dfphttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	localratelimit "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	sfshttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	sfsnetwork "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	httpmatcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/core/match"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/xds"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/wellknown"
)

func sandboxEgressNode() *model.Proxy {
	return &model.Proxy{
		Labels: map[string]string{
			agentio.LabelSandboxEgress: "true",
		},
		ID:              "egress-gw-0.istio-system",
		ConfigNamespace: "istio-system",
		Metadata: &model.NodeMetadata{
			Namespace:                 "istio-system",
			MetadataDiscovery:         ptr.Of(model.StringBool(true)),
			PolicyRuntimeCapabilities: []string{"sni_traffic_policy"},
		},
		VerifiedIdentity: &spiffe.Identity{
			ServiceAccount: "egress-gw",
			Namespace:      "istio-system",
		},
	}
}

func nonSandboxNode() *model.Proxy {
	return &model.Proxy{
		Labels:          map[string]string{},
		ID:              "sidecar-0.default",
		ConfigNamespace: "default",
		Metadata:        &model.NodeMetadata{Namespace: "default"},
	}
}

func makeConnPool(opts ...func(*extensions.ConnectionPoolSettings)) *extensions.ConnectionPoolSettings {
	cp := &extensions.ConnectionPoolSettings{}
	for _, o := range opts {
		o(cp)
	}
	return cp
}

func withStreamIdleTimeout(d time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Http == nil {
			cp.Http = &extensions.ConnectionPoolHttpSettings{}
		}
		cp.Http.StreamIdleTimeout = durationpb.New(d)
	}
}

func withTCPIdleTimeout(d time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Tcp == nil {
			cp.Tcp = &extensions.TcpSettings{}
		}
		cp.Tcp.IdleTimeout = durationpb.New(d)
	}
}

func withTCPMaxConnDuration(d time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Tcp == nil {
			cp.Tcp = &extensions.TcpSettings{}
		}
		cp.Tcp.MaxConnectionDuration = durationpb.New(d)
	}
}

func withDefaultRoute(timeout time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Http == nil {
			cp.Http = &extensions.ConnectionPoolHttpSettings{}
		}
		cp.Http.DefaultRoute = &extensions.HttpRouteSettings{
			Timeout: durationpb.New(timeout),
		}
	}
}

func withRouteOverride(hosts []string, timeout time.Duration) func(*extensions.ConnectionPoolSettings) {
	return func(cp *extensions.ConnectionPoolSettings) {
		if cp.Http == nil {
			cp.Http = &extensions.ConnectionPoolHttpSettings{}
		}
		cp.Http.RouteOverrides = append(cp.Http.RouteOverrides, &extensions.HttpRouteOverride{
			Hosts: hosts,
			Settings: &extensions.HttpRouteSettings{
				Timeout: durationpb.New(timeout),
			},
		})
	}
}

func testInboundChainConfig(clusterName string) inboundChainConfig {
	return inboundChainConfig{
		clusterName: clusterName,
		port: model.ServiceInstancePort{
			ServicePort: &model.Port{
				Name:     "http",
				Protocol: protocol.HTTP,
				Port:     8080,
			},
		},
	}
}

func TestApplySandboxInternalChains_RoutesHTTPThroughDFPAndTCPToOriginalDestination(t *testing.T) {
	cg := NewConfigGenTest(t, TestOptions{})
	lb := &ListenerBuilder{
		node: cg.SetupProxy(sandboxEgressNode()),
		push: cg.PushContext(),
	}

	chains := applySandboxInternalChains(lb, nil, &matcher.Matcher{})
	if len(chains) != 2 {
		t.Fatalf("catch-all chains = %d, want HTTP and TCP chains", len(chains))
	}

	httpConfig := &hcm.HttpConnectionManager{}
	if err := chains[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(httpConfig); err != nil {
		t.Fatalf("decode HTTP connection manager: %v", err)
	}
	httpRoutes := httpConfig.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	var defaultHTTPRouteCluster string
	for _, r := range httpRoutes {
		if r.GetMatch().GetPrefix() == "/" {
			defaultHTTPRouteCluster = r.GetRoute().GetCluster()
			break
		}
	}
	if got, want := defaultHTTPRouteCluster, "http_dynamic_forward_proxy"; got != want {
		t.Fatalf("HTTP route cluster = %q, want %q", got, want)
	}

	var tcpConfig *tcp.TcpProxy
	for _, filter := range chains[1].GetFilters() {
		if filter.GetName() != wellknown.TCPProxy {
			continue
		}
		tcpConfig = &tcp.TcpProxy{}
		if err := filter.GetTypedConfig().UnmarshalTo(tcpConfig); err != nil {
			t.Fatalf("decode TCP proxy: %v", err)
		}
		break
	}
	if tcpConfig == nil {
		t.Fatal("TCP proxy filter not found")
	}
	if got, want := tcpConfig.GetCluster(), "PassthroughCluster"; got != want {
		t.Fatalf("TCP route cluster = %q, want %q", got, want)
	}
}

func TestBuildMainForwardFilters_ProxiesConnect(t *testing.T) {
	cg := NewConfigGenTest(t, TestOptions{})
	lb := &ListenerBuilder{
		node: cg.SetupProxy(sandboxEgressNode()),
		push: cg.PushContext(),
	}

	tests := []struct {
		name               string
		inner              bool
		httpCluster        string
		tcpCluster         string
		wantConnectCluster string
	}{
		{
			name:               "clear HTTP proxy",
			httpCluster:        httpForwardCluster,
			tcpCluster:         util.PassthroughCluster,
			wantConnectCluster: util.PassthroughCluster,
		},
		{
			name:               "TLS-terminated HTTPS proxy",
			inner:              true,
			httpCluster:        tlsOriginateCluster,
			tcpCluster:         tlsOriginateCluster,
			wantConnectCluster: "tls_proxy_originate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chains := lb.buildMainForwardFilters(tt.httpCluster, tt.tcpCluster, tt.inner)
			h := &hcm.HttpConnectionManager{}
			if err := chains[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(h); err != nil {
				t.Fatalf("decode HTTP connection manager: %v", err)
			}

			vhost := h.GetRouteConfig().GetVirtualHosts()[0]
			if got, want := vhost.GetName(), "inbound|http|0"; got != want {
				t.Fatalf("default virtual host name = %q, want preserved sidecar inbound name %q", got, want)
			}
			routes := vhost.GetRoutes()
			if got, want := len(routes), 2; got != want {
				t.Fatalf("routes = %d, want CONNECT followed by default HTTP route (%d)", got, want)
			}
			connectRoute := routes[0]
			if connectRoute.GetMatch().GetConnectMatcher() == nil {
				t.Fatal("first route must use connect_matcher")
			}
			connectAction := connectRoute.GetRoute()
			if got := connectAction.GetCluster(); got != tt.wantConnectCluster {
				t.Fatalf("CONNECT cluster = %q, want original proxy cluster %q", got, tt.wantConnectCluster)
			}
			if connectAction.GetTimeout() == nil || connectAction.GetTimeout().AsDuration() != 0 {
				t.Fatalf("CONNECT timeout = %v, want disabled (0s)", connectAction.GetTimeout())
			}
			upgrades := connectAction.GetUpgradeConfigs()
			if got, want := len(upgrades), 1; got != want {
				t.Fatalf("CONNECT upgrade configs = %d, want %d", got, want)
			}
			if got := upgrades[0].GetUpgradeType(); got != ConnectUpgradeType {
				t.Fatalf("upgrade type = %q, want %q", got, ConnectUpgradeType)
			}
			if upgrades[0].GetConnectConfig() != nil {
				t.Fatal("application CONNECT must be proxied upstream, not terminated by Envoy")
			}

			defaultRoute := routes[1]
			if got := defaultRoute.GetMatch().GetPrefix(); got != "/" {
				t.Fatalf("default HTTP route prefix = %q, want /", got)
			}
			if got := defaultRoute.GetRoute().GetCluster(); got != tt.httpCluster {
				t.Fatalf("default HTTP cluster = %q, want %q", got, tt.httpCluster)
			}
			if got, want := defaultRoute.GetDecorator().GetOperation(), ":0/*"; got != want {
				t.Fatalf("default HTTP trace operation = %q, want preserved sidecar inbound operation %q", got, want)
			}
			if !h.GetHttp2ProtocolOptions().GetAllowConnect() {
				t.Fatal("forward-http HCM must allow HTTP/2 CONNECT")
			}
		})
	}
}

func TestBuildMainForwardFilters_ServiceEntryEndpoints(t *testing.T) {
	cg := NewConfigGenTest(t, TestOptions{})
	node := cg.SetupProxy(sandboxEgressNode())
	push := cg.PushContext()
	push.AgentioConfig = &model.AgentioConfig{AgentioConfig: &extensions.AgentioConfig{
		EgressGateways: []*extensions.EgressGateway{{
			Name:      "egress-gw",
			Namespace: "istio-system",
			ServiceEntries: []*extensions.EgressServiceEntry{{
				Hosts: []string{"api.example.com"},
				Endpoints: []*extensions.EgressServiceEntryEndpoint{
					{Address: "10.10.20.30"},
					{Address: "10.10.20.31"},
				},
			}},
		}},
	}}
	lb := &ListenerBuilder{node: node, push: push}

	for _, tt := range []struct {
		name        string
		httpCluster string
		tcpCluster  string
		inner       bool
	}{
		{name: "forward-http", httpCluster: httpForwardCluster, tcpCluster: util.PassthroughCluster},
		{name: "main_forward", httpCluster: tlsOriginateCluster, tcpCluster: tlsOriginateCluster, inner: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			chains := lb.buildMainForwardFilters(tt.httpCluster, tt.tcpCluster, tt.inner)
			h := &hcm.HttpConnectionManager{}
			if err := chains[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(h); err != nil {
				t.Fatalf("decode HTTP connection manager: %v", err)
			}
			vhosts := h.GetRouteConfig().GetVirtualHosts()
			if got, want := len(vhosts), 2; got != want {
				t.Fatalf("virtual hosts = %d, want service entry and fallback (%d)", got, want)
			}
			if got, want := vhosts[0].GetDomains(), []string{"api.example.com", "api.example.com:*"}; !slices.Equal(got, want) {
				t.Fatalf("service-entry domains = %v, want %v", got, want)
			}
			ordinaryRoute := vhosts[0].GetRoutes()[1]
			weighted := ordinaryRoute.GetRoute().GetWeightedClusters().GetClusters()
			if got, want := len(weighted), 2; got != want {
				t.Fatalf("weighted clusters = %d, want %d", got, want)
			}
			for index, entry := range weighted {
				if got := entry.GetName(); got != tt.httpCluster {
					t.Fatalf("weighted cluster %d = %q, want %q", index, got, tt.httpCluster)
				}
			}

			var dfpConfig *dfphttp.FilterConfig
			for _, filter := range h.GetHttpFilters() {
				if filter.GetName() != "envoy.filters.http.dynamic_forward_proxy" {
					continue
				}
				dfpConfig = &dfphttp.FilterConfig{}
				if err := filter.GetTypedConfig().UnmarshalTo(dfpConfig); err != nil {
					t.Fatalf("decode DFP filter config: %v", err)
				}
			}
			if dfpConfig == nil || !dfpConfig.GetAllowDynamicHostFromFilterState() {
				t.Fatal("DFP filter does not accept the selected static endpoint")
			}
		})
	}
}

func TestBuildMainForwardFilters_AppliesEnvoyFilterToConnectRoute(t *testing.T) {
	const envoyFilter = `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: patch-sandbox-connect
  namespace: istio-system
spec:
  configPatches:
  - applyTo: HTTP_ROUTE
    match:
      context: SIDECAR_INBOUND
      routeConfiguration:
        vhost:
          route:
            name: sandbox-connect
    patch:
      operation: MERGE
      value:
        route:
          timeout: 17s
  - applyTo: HTTP_ROUTE
    match:
      context: SIDECAR_INBOUND
      routeConfiguration:
        vhost:
          route:
            name: default
    patch:
      operation: INSERT_FIRST
      value:
        name: connect-guard
        match:
          connect_matcher: {}
        direct_response:
          status: 403
`

	tests := []struct {
		name     string
		connPool *extensions.ConnectionPoolSettings
	}{
		{name: "default routes"},
		{
			name: "connection pool routes",
			connPool: makeConnPool(
				withRouteOverride([]string{"proxy.example"}, 23*time.Second),
				withDefaultRoute(31*time.Second),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cg := NewConfigGenTest(t, TestOptions{ConfigString: envoyFilter})
			node := cg.SetupProxy(sandboxEgressNode())
			push := cg.PushContext()
			if tt.connPool != nil {
				push.AgentioConfig = &model.AgentioConfig{
					AgentioConfig: &extensions.AgentioConfig{
						EgressGateways: []*extensions.EgressGateway{{
							Name:           "egress-gw",
							Namespace:      "istio-system",
							ConnectionPool: tt.connPool,
						}},
					},
				}
			}
			lb := &ListenerBuilder{node: node, push: push}

			chains := lb.buildMainForwardFilters(httpForwardCluster, util.PassthroughCluster, false)
			h := &hcm.HttpConnectionManager{}
			if err := chains[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(h); err != nil {
				t.Fatalf("decode HTTP connection manager: %v", err)
			}

			vhosts := h.GetRouteConfig().GetVirtualHosts()
			wantVHosts := 1
			if tt.connPool != nil {
				wantVHosts = 2
			}
			if got := len(vhosts); got != wantVHosts {
				t.Fatalf("virtual hosts = %d, want %d", got, wantVHosts)
			}
			for _, vhost := range vhosts {
				routes := vhost.GetRoutes()
				if got := len(routes); got != 3 {
					t.Fatalf("virtual host %q routes = %d, want guard, CONNECT, and ordinary route", vhost.GetName(), got)
				}
				if got := routes[0].GetName(); got != "connect-guard" {
					t.Fatalf("virtual host %q first route = %q, want EnvoyFilter guard", vhost.GetName(), got)
				}
				if got := routes[0].GetDirectResponse().GetStatus(); got != 403 {
					t.Fatalf("virtual host %q guard status = %d, want 403", vhost.GetName(), got)
				}
				if got := routes[1].GetName(); got != "sandbox-connect" {
					t.Fatalf("virtual host %q second route = %q, want sandbox-connect", vhost.GetName(), got)
				}
				if got := routes[1].GetRoute().GetTimeout().AsDuration(); got != 17*time.Second {
					t.Fatalf("virtual host %q CONNECT timeout = %v, want EnvoyFilter value 17s", vhost.GetName(), got)
				}
				ordinary := routes[2]
				if got := ordinary.GetMatch().GetPrefix(); got != "/" {
					t.Fatalf("virtual host %q ordinary route prefix = %q, want /", vhost.GetName(), got)
				}
				if got := ordinary.GetRoute().GetCluster(); got != httpForwardCluster {
					t.Fatalf("virtual host %q ordinary route cluster = %q, want %q", vhost.GetName(), got, httpForwardCluster)
				}
			}
		})
	}
}

func TestBuildCaptureSNIFilter_OuterSNISeparatesInternalConnectionPools(t *testing.T) {
	cfg := &sfsnetwork.Config{}
	if err := buildCaptureSNIFilter().GetTypedConfig().UnmarshalTo(cfg); err != nil {
		t.Fatalf("decode network set_filter_state: %v", err)
	}

	values := cfg.GetOnNewConnection()
	if got, want := len(values), 1; got != want {
		t.Fatalf("captured SNI values = %d, want only the request-neutral outer SNI (%d)", got, want)
	}
	value := values[0]
	if got, want := value.GetObjectKey(), outerSNIFilterStateKey; got != want {
		t.Fatalf("captured SNI key = %q, want %q", got, want)
	}
	// Shared state must implement Hashable to separate the internal upstream
	// pools; a plain string can carry another connection's SNI into RBAC.
	if got, want := value.GetFactoryKey(), "istio.hashable_string"; got != want {
		t.Fatalf("factory for %q = %q, want %q", value.GetObjectKey(), got, want)
	}
	if got, want := value.GetFormatString().GetTextFormatSource().GetInlineString(), "%REQUESTED_SERVER_NAME%"; got != want {
		t.Fatalf("format for %q = %q, want %q", value.GetObjectKey(), got, want)
	}
	if !value.GetSkipIfEmpty() {
		t.Fatalf("captured SNI key %q must skip empty values", value.GetObjectKey())
	}
	if got, want := value.GetSharedWithUpstream().String(), "ONCE"; got != want {
		t.Fatalf("sharing for %q = %s, want %s", value.GetObjectKey(), got, want)
	}
}

func TestBuildMainForwardFilters_SetsProxyTLSIdentityOnlyForConnect(t *testing.T) {
	cg := NewConfigGenTest(t, TestOptions{})
	lb := &ListenerBuilder{
		node: cg.SetupProxy(sandboxEgressNode()),
		push: cg.PushContext(),
	}

	getHCM := func(inner bool) *hcm.HttpConnectionManager {
		httpCluster := httpForwardCluster
		tcpCluster := util.PassthroughCluster
		if inner {
			httpCluster = tlsOriginateCluster
			tcpCluster = tlsOriginateCluster
		}
		chains := lb.buildMainForwardFilters(httpCluster, tcpCluster, inner)
		h := &hcm.HttpConnectionManager{}
		if err := chains[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(h); err != nil {
			t.Fatalf("decode HTTP connection manager: %v", err)
		}
		return h
	}
	findTLSIdentityFilter := func(h *hcm.HttpConnectionManager) *hcm.HttpFilter {
		for _, filter := range h.GetHttpFilters() {
			if filter.GetName() == "connect-proxy-tls-identity" {
				return filter
			}
		}
		return nil
	}

	if got := findTLSIdentityFilter(getHCM(false)); got != nil {
		t.Fatal("clear HTTP proxy must not install upstream TLS identity filter")
	}

	filter := findTLSIdentityFilter(getHCM(true))
	if filter == nil {
		t.Fatal("HTTPS proxy must install CONNECT-scoped upstream TLS identity filter")
	}
	wrapped := &extensionmatching.ExtensionWithMatcher{}
	if err := filter.GetTypedConfig().UnmarshalTo(wrapped); err != nil {
		t.Fatalf("decode CONNECT matcher wrapper: %v", err)
	}
	if err := wrapped.ValidateAll(); err != nil {
		t.Fatalf("validate CONNECT matcher wrapper: %v", err)
	}

	matchers := wrapped.GetXdsMatcher().GetMatcherList().GetMatchers()
	if got, want := len(matchers), 1; got != want {
		t.Fatalf("CONNECT matcher rules = %d, want %d", got, want)
	}
	// ExtensionWithMatcher runs the wrapped filter by default. Its sole rule
	// skips the filter when the request method is not CONNECT.
	notConnect := matchers[0].GetPredicate().GetNotMatcher().GetSinglePredicate()
	if notConnect == nil {
		t.Fatal("TLS identity filter must skip non-CONNECT requests")
	}
	methodInput := &httpmatcher.HttpRequestHeaderMatchInput{}
	if err := notConnect.GetInput().GetTypedConfig().UnmarshalTo(methodInput); err != nil {
		t.Fatalf("decode request method matcher input: %v", err)
	}
	if got, want := methodInput.GetHeaderName(), ":method"; got != want {
		t.Fatalf("matcher header = %q, want %q", got, want)
	}
	if got, want := notConnect.GetValueMatch().GetExact(), "CONNECT"; got != want {
		t.Fatalf("matcher method = %q, want %q", got, want)
	}
	if got, want := matchers[0].GetOnMatch().GetAction().GetTypedConfig().GetTypeUrl(), "type.googleapis.com/envoy.extensions.filters.common.matcher.action.v3.SkipFilter"; got != want {
		t.Fatalf("non-CONNECT action type = %q, want %q", got, want)
	}

	if got, want := wrapped.GetExtensionConfig().GetName(), "envoy.filters.http.set_filter_state"; got != want {
		t.Fatalf("wrapped filter name = %q, want %q", got, want)
	}
	setState := &sfshttp.Config{}
	if err := wrapped.GetExtensionConfig().GetTypedConfig().UnmarshalTo(setState); err != nil {
		t.Fatalf("decode HTTP set_filter_state: %v", err)
	}
	values := setState.GetOnRequestHeaders()
	if got, want := len(values), 2; got != want {
		t.Fatalf("CONNECT TLS identity values = %d, want upstream SNI and SAN (%d)", got, want)
	}
	wantKeys := map[string]struct{}{
		upstreamServerNameFilterStateKey:      {},
		upstreamSubjectAltNamesFilterStateKey: {},
	}
	for _, value := range values {
		if _, found := wantKeys[value.GetObjectKey()]; !found {
			t.Fatalf("unexpected CONNECT TLS identity key %q", value.GetObjectKey())
		}
		if got, want := value.GetFormatString().GetTextFormatSource().GetInlineString(), "%FILTER_STATE(io.kruise.outer_sni:PLAIN)%"; got != want {
			t.Fatalf("format for %q = %q, want %q", value.GetObjectKey(), got, want)
		}
		if !value.GetSkipIfEmpty() {
			t.Fatalf("CONNECT TLS identity key %q must skip empty values", value.GetObjectKey())
		}
		if got := value.GetSharedWithUpstream(); got != 0 {
			t.Fatalf("sharing for %q = %s, want request-local NONE", value.GetObjectKey(), got)
		}
		delete(wantKeys, value.GetObjectKey())
	}
	if len(wantKeys) != 0 {
		t.Fatalf("missing CONNECT TLS identity keys: %v", wantKeys)
	}
}

func TestSNIHostMismatchCondition_CONNECTUsesProxyAuthoritySemantics(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Variable("request", cel.DynType),
		cel.Variable("filter_state", cel.MapType(cel.StringType, cel.BytesType)),
		ext.Strings(),
	)
	if err != nil {
		t.Fatalf("create CEL environment: %v", err)
	}
	ast, issues := env.Compile(sniHostMismatchCondition)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile SNI/host mismatch condition: %v", issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("create CEL program: %v", err)
	}

	tests := []struct {
		name   string
		method string
		host   string
		want   bool
	}{
		{name: "ordinary mismatch denied", method: "GET", host: "target.example:443", want: true},
		{name: "CONNECT target differs from proxy SNI", method: "CONNECT", host: "target.example:443", want: false},
		{name: "ordinary matching host allowed", method: "GET", host: "proxy.example:8443", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := program.Eval(map[string]any{
				"request": map[string]any{
					"method": tt.method,
					"host":   tt.host,
				},
				"filter_state": map[string][]byte{
					outerSNIFilterStateKey: []byte("proxy.example"),
				},
			})
			if err != nil {
				t.Fatalf("evaluate SNI/host mismatch condition: %v", err)
			}
			got, ok := result.Value().(bool)
			if !ok {
				t.Fatalf("condition result type = %T, want bool", result.Value())
			}
			if got != tt.want {
				t.Fatalf("condition = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildSandboxSNITrafficPolicyMatcherPreservesExcludeHosts(t *testing.T) {
	previousFailureModeAllow := features.SniTrafficPolicyFailureModeAllow
	features.SniTrafficPolicyFailureModeAllow = false
	t.Cleanup(func() { features.SniTrafficPolicyFailureModeAllow = previousFailureModeAllow })

	const excluded = "*.legacy.example.com"
	result := buildSandboxSNITrafficPolicyMatcher([]string{excluded}, buildSandboxProtocolMatcher())

	sniMatcher := &matcher.ServerNameMatcher{}
	typedConfig := result.GetMatcher().GetMatcherTree().GetCustomMatch().GetTypedConfig()
	if typedConfig == nil {
		t.Fatal("SNI policy matcher must check legacy exclude_hosts first")
	}
	if err := typedConfig.UnmarshalTo(sniMatcher); err != nil {
		t.Fatalf("decode SNI matcher: %v", err)
	}
	domainMatchers := sniMatcher.GetDomainMatchers()
	if got, want := len(domainMatchers), 1; got != want {
		t.Fatalf("exclude host matchers = %d, want %d", got, want)
	}
	assert.Equal(t, domainMatchers[0].GetDomains(), []string{excluded})
	if got, want := domainMatchers[0].GetOnMatch().GetAction().GetName(), forwardTcpFilterChain; got != want {
		t.Fatalf("exclude_hosts route = %q, want %q", got, want)
	}

	transportMatcher := result.GetMatcher().GetOnNoMatch().GetMatcher()
	tlsRoute := transportMatcher.GetMatcherTree().GetExactMatchMap().GetMap()["tls"]
	policyMatcher := tlsRoute.GetMatcher()
	if policyMatcher == nil {
		t.Fatal("non-excluded TLS traffic must use the SNI policy matcher")
	}
	if got, want := policyMatcher.GetMatcherTree().GetCustomMatch().GetName(),
		"kruise.matching.custom_matchers.sni_traffic_policy"; got != want {
		t.Fatalf("SNI traffic policy matcher name = %q, want %q", got, want)
	}
	if got, want := policyMatcher.GetOnNoMatch().GetAction().GetName(), forwardTcpFilterChain; got != want {
		t.Fatalf("SNI policy matcher on_no_match = %q, want passthrough chain %q for no-SNI connections", got, want)
	}
	policyConfig := &typedstruct.TypedStruct{}
	if err := policyMatcher.GetMatcherTree().GetCustomMatch().GetTypedConfig().UnmarshalTo(policyConfig); err != nil {
		t.Fatalf("decode SNI policy matcher: %v", err)
	}
	if got, want := policyConfig.GetTypeUrl(),
		"type.googleapis.com/kruise.networking.policy_runtime.v1alpha1.SniTrafficPolicyMatcher"; got != want {
		t.Fatalf("SNI policy matcher type URL = %q, want %q", got, want)
	}
	for field, want := range map[string]string{
		"on_tls_termination": tlsTerminateFilterChain,
		"on_passthrough":     forwardTcpFilterChain,
		"on_deny":            sniTrafficPolicyDenyFilterChain,
	} {
		action := policyConfig.GetValue().GetFields()[field].GetStructValue().GetFields()["action"].GetStructValue()
		if got := action.GetFields()["name"].GetStringValue(); got != want {
			t.Errorf("SNI policy matcher %s action = %q, want %q", field, got, want)
		}
	}
	failureModeAllow := policyConfig.GetValue().GetFields()["failure_mode_allow"].GetStructValue().GetFields()
	if got, want := failureModeAllow["runtime_key"].GetStringValue(),
		"kruise.sni_traffic_policy.failure_mode_allow"; got != want {
		t.Errorf("SNI policy matcher failure_mode_allow runtime key = %q, want %q", got, want)
	}
	defaultValue, found := failureModeAllow["default_value"]
	if !found {
		t.Fatal("SNI policy matcher failure_mode_allow must set default_value explicitly")
	}
	if defaultValue.GetBoolValue() {
		t.Error("SNI policy matcher failure_mode_allow must default to false")
	}
}

func TestSniTrafficPolicyMatcherFailureModeAllowDefault(t *testing.T) {
	previous := features.SniTrafficPolicyFailureModeAllow
	features.SniTrafficPolicyFailureModeAllow = true
	t.Cleanup(func() { features.SniTrafficPolicyFailureModeAllow = previous })

	result := match.NewSniTrafficPolicyMatcher(
		tlsTerminateFilterChain, forwardTcpFilterChain, sniTrafficPolicyDenyFilterChain)
	policyConfig := &typedstruct.TypedStruct{}
	if err := result.GetMatcherTree().GetCustomMatch().GetTypedConfig().UnmarshalTo(policyConfig); err != nil {
		t.Fatalf("decode SNI policy matcher: %v", err)
	}
	failureModeAllow := policyConfig.GetValue().GetFields()["failure_mode_allow"].GetStructValue().GetFields()
	if !failureModeAllow["default_value"].GetBoolValue() {
		t.Error("SNI policy matcher failure_mode_allow must use the control-plane default")
	}
}

func TestSniTrafficPolicyFeatureAddsMatcherOutcomeChains(t *testing.T) {
	previous := features.EnableSniTrafficPolicy
	features.EnableSniTrafficPolicy = true
	t.Cleanup(func() { features.EnableSniTrafficPolicy = previous })

	cg := NewConfigGenTest(t, TestOptions{})
	lb := &ListenerBuilder{
		node: cg.SetupProxy(sandboxEgressNode()),
		push: cg.PushContext(),
	}
	chains := applySandboxInternalChains(lb, nil, &matcher.Matcher{})
	if got, want := len(chains), 4; got != want {
		t.Fatalf("feature-enabled catch-all chains = %d, want HTTP, TCP, TLS termination, and deny", got)
	}
	if got, want := chains[2].GetName(), tlsTerminateFilterChain; got != want {
		t.Fatalf("TLS termination chain name = %q, want %q", got, want)
	}
	if got, want := chains[3].GetName(), "sni-traffic-policy-deny"; got != want {
		t.Fatalf("deny chain name = %q, want %q", got, want)
	}

	listeners := sandboxListeners(lb)
	if got, want := len(listeners), 1; got != want {
		t.Fatalf("feature-enabled sandbox listeners = %d, want main-forward only", got)
	}
}

func TestSniTrafficPolicyRequiresNodeCapability(t *testing.T) {
	previous := features.EnableSniTrafficPolicy
	features.EnableSniTrafficPolicy = true
	t.Cleanup(func() { features.EnableSniTrafficPolicy = previous })

	tests := []struct {
		name                string
		workloadDiscovery   bool
		runtimeCapabilities []string
		wantEnabled         bool
	}{
		{
			name:                "workload discovery and matcher capability",
			workloadDiscovery:   true,
			runtimeCapabilities: []string{"sni_traffic_policy"},
			wantEnabled:         true,
		},
		{
			name:                "matcher without policy store",
			runtimeCapabilities: []string{"sni_traffic_policy"},
		},
		{
			name:              "workload discovery without matcher",
			workloadDiscovery: true,
		},
		{
			name:                "unrelated policy matcher",
			workloadDiscovery:   true,
			runtimeCapabilities: []string{"type.googleapis.com/example.OtherPolicyMatcher"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cg := NewConfigGenTest(t, TestOptions{})
			node := sandboxEgressNode()
			node.Metadata.MetadataDiscovery = ptr.Of(model.StringBool(tt.workloadDiscovery))
			node.Metadata.PolicyRuntimeCapabilities = tt.runtimeCapabilities
			lb := &ListenerBuilder{node: cg.SetupProxy(node), push: cg.PushContext()}
			chains := applySandboxInternalChains(lb, nil, &matcher.Matcher{})
			wantChains := 2
			if tt.wantEnabled {
				wantChains = 4
			}
			if got := len(chains); got != wantChains {
				t.Fatalf("catch-all chains = %d, want %d", got, wantChains)
			}
		})
	}
}

func TestBuildWaypointInboundHTTPRouteConfig_SandboxUnboundRespectsConfiguredCluster(t *testing.T) {
	cg := NewConfigGenTest(t, TestOptions{})
	lb := &ListenerBuilder{
		node: cg.SetupProxy(sandboxEgressNode()),
		push: cg.PushContext(),
	}
	cc := testInboundChainConfig(EncapClusterName)

	routeConfig := buildWaypointInboundHTTPRouteConfig(lb, nil, cc)
	route := routeConfig.GetVirtualHosts()[0].GetRoutes()[0]
	if got := route.GetRoute().GetCluster(); got != EncapClusterName {
		t.Fatalf("unbound HTTP route cluster = %q, want configured %q", got, EncapClusterName)
	}
}

func TestBuildWaypointInboundHTTPRouteConfig_SandboxServicePreservesServiceRoute(t *testing.T) {
	cg := NewConfigGenTest(t, TestOptions{})
	lb := &ListenerBuilder{
		node: cg.SetupProxy(sandboxEgressNode()),
		push: cg.PushContext(),
	}
	const serviceCluster = "inbound-vip|http|service.default.svc.cluster.local"
	cc := testInboundChainConfig(serviceCluster)
	svc := &model.Service{
		Hostname: "service.default.svc.cluster.local",
		Attributes: model.ServiceAttributes{
			Name:      "service",
			Namespace: "default",
		},
	}

	routeConfig := buildWaypointInboundHTTPRouteConfig(lb, svc, cc)
	checked := 0
	for _, virtualHost := range routeConfig.GetVirtualHosts() {
		for _, route := range virtualHost.GetRoutes() {
			checked++
			if got := route.GetRoute().GetCluster(); got != serviceCluster {
				t.Fatalf("sandbox service HTTP route cluster = %q, want %q", got, serviceCluster)
			}
		}
	}
	if checked == 0 {
		t.Fatal("sandbox service HTTP route config contains no routes")
	}
}

// --- buildSandboxHTTPRouteConfig ---

func TestBuildSandboxHTTPRouteConfig_NoOverrides(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")
	connPool := makeConnPool()

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, len(rc.VirtualHosts), 1)
	assert.Equal(t, rc.VirtualHosts[0].Domains, []string{"*"})
	assert.Equal(t, rc.VirtualHosts[0].Name, "sandbox|default|8080")
}

func TestBuildSandboxHTTPRouteConfig_WithOverrides(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")
	connPool := makeConnPool(
		withRouteOverride([]string{"api.example.com"}, 60*time.Second),
		withRouteOverride([]string{"*.internal.com", "db.local"}, 10*time.Second),
		withDefaultRoute(300*time.Second),
	)

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, len(rc.VirtualHosts), 3)

	assert.Equal(t, rc.VirtualHosts[0].Domains, []string{"api.example.com"})
	assert.Equal(t, rc.VirtualHosts[0].Routes[0].GetRoute().Timeout.AsDuration(), 60*time.Second)

	assert.Equal(t, rc.VirtualHosts[1].Domains, []string{"*.internal.com", "db.local"})
	assert.Equal(t, rc.VirtualHosts[1].Routes[0].GetRoute().Timeout.AsDuration(), 10*time.Second)

	assert.Equal(t, rc.VirtualHosts[2].Domains, []string{"*"})
	assert.Equal(t, rc.VirtualHosts[2].Routes[0].GetRoute().Timeout.AsDuration(), 300*time.Second)
}

func TestBuildSandboxHTTPRouteConfig_EmptyHostsSkipped(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")
	connPool := makeConnPool()
	connPool.Http = &extensions.ConnectionPoolHttpSettings{
		RouteOverrides: []*extensions.HttpRouteOverride{
			{Hosts: []string{}, Settings: &extensions.HttpRouteSettings{Timeout: durationpb.New(10 * time.Second)}},
			{Hosts: []string{"valid.com"}, Settings: &extensions.HttpRouteSettings{Timeout: durationpb.New(20 * time.Second)}},
		},
	}

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, len(rc.VirtualHosts), 2)
	assert.Equal(t, rc.VirtualHosts[0].Domains, []string{"valid.com"})
}

func TestBuildSandboxHTTPRouteConfig_ServiceEntryEndpoints(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	gateway := &extensions.EgressGateway{
		ConnectionPool: makeConnPool(withRouteOverride([]string{"api.example.com"}, 17*time.Second)),
		ServiceEntries: []*extensions.EgressServiceEntry{{
			Hosts: []string{"api.example.com"},
			Endpoints: []*extensions.EgressServiceEntryEndpoint{
				{Address: "10.10.20.30"},
				{Address: "10.10.20.31"},
			},
		}},
	}

	for _, clusterName := range []string{httpForwardCluster, tlsOriginateCluster} {
		t.Run(clusterName, func(t *testing.T) {
			cc := testInboundChainConfig(clusterName)
			cc.connectProxyCluster = tlsProxyOriginateCluster
			rc := buildSandboxHTTPRouteConfigForGateway(lb, cc, gateway)
			if err := rc.Validate(); err != nil {
				t.Fatalf("generated route configuration is invalid: %v", err)
			}

			if got, want := len(rc.GetVirtualHosts()), 2; got != want {
				t.Fatalf("virtual hosts = %d, want service entry and fallback (%d)", got, want)
			}
			serviceVHost := rc.GetVirtualHosts()[0]
			if got, want := serviceVHost.GetDomains(), []string{"api.example.com", "api.example.com:*"}; !slices.Equal(got, want) {
				t.Fatalf("domains = %v, want %v", got, want)
			}
			if got, want := len(serviceVHost.GetRoutes()), 2; got != want {
				t.Fatalf("routes = %d, want CONNECT and service entry (%d)", got, want)
			}
			if config := serviceVHost.GetRoutes()[0].GetTypedPerFilterConfig(); len(config) != 0 {
				t.Fatalf("CONNECT route unexpectedly contains endpoint config: %v", config)
			}

			serviceRoute := serviceVHost.GetRoutes()[1]
			if got := serviceRoute.GetRoute().GetTimeout().AsDuration(); got != 17*time.Second {
				t.Fatalf("service route timeout = %v, want route override 17s", got)
			}
			weighted := serviceRoute.GetRoute().GetWeightedClusters().GetClusters()
			if got, want := len(weighted), 2; got != want {
				t.Fatalf("weighted clusters = %d, want %d", got, want)
			}
			for index, wantAddress := range []string{"10.10.20.30", "10.10.20.31"} {
				entry := weighted[index]
				if got := entry.GetName(); got != clusterName {
					t.Fatalf("weighted cluster %d name = %q, want %q", index, got, clusterName)
				}
				if got := entry.GetWeight().GetValue(); got != 1 {
					t.Fatalf("weighted cluster %d weight = %d, want 1", index, got)
				}
				if got := staticEndpointFromFilterConfig(t, entry.GetTypedPerFilterConfig()); got != wantAddress {
					t.Fatalf("weighted cluster %d endpoint = %q, want %q", index, got, wantAddress)
				}
			}
		})
	}
}

func TestBuildSandboxHTTPRouteConfig_SingleServiceEntryEndpoint(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig(httpForwardCluster)
	gateway := &extensions.EgressGateway{ServiceEntries: []*extensions.EgressServiceEntry{{
		Hosts:     []string{"api.example.com"},
		Endpoints: []*extensions.EgressServiceEntryEndpoint{{Address: "10.10.20.30"}},
	}}}

	serviceRoute := buildSandboxHTTPRouteConfigForGateway(lb, cc, gateway).GetVirtualHosts()[0].GetRoutes()[0]
	if got := serviceRoute.GetRoute().GetCluster(); got != httpForwardCluster {
		t.Fatalf("cluster = %q, want %q", got, httpForwardCluster)
	}
	if got := staticEndpointFromFilterConfig(t, serviceRoute.GetTypedPerFilterConfig()); got != "10.10.20.30" {
		t.Fatalf("endpoint = %q, want 10.10.20.30", got)
	}
}

func staticEndpointFromFilterConfig(t *testing.T, config map[string]*anypb.Any) string {
	t.Helper()
	typedConfig := config[staticEndpointFilterStateFilter]
	if typedConfig == nil {
		t.Fatal("static endpoint set-filter-state config not found")
	}
	filterStateConfig := &sfshttp.Config{}
	if err := typedConfig.UnmarshalTo(filterStateConfig); err != nil {
		t.Fatalf("decode endpoint set-filter-state config: %v", err)
	}
	values := filterStateConfig.GetOnRequestHeaders()
	if got, want := len(values), 2; got != want {
		t.Fatalf("filter-state values = %d, want %d", got, want)
	}
	if got, want := values[0].GetObjectKey(), dynamicHostFilterStateKey; got != want {
		t.Fatalf("host filter-state key = %q, want %q", got, want)
	}
	if !values[0].GetReadOnly() {
		t.Fatal("host filter-state value must be read-only")
	}
	if got, want := values[1].GetObjectKey(), dynamicPortFilterStateKey; got != want {
		t.Fatalf("port filter-state key = %q, want %q", got, want)
	}
	if got, want := values[1].GetFormatString().GetTextFormatSource().GetInlineString(),
		"%FILTER_STATE(envoy.filters.listener.original_dst.local_ip:FIELD:port)%"; got != want {
		t.Fatalf("port filter-state value format = %q, want %q", got, want)
	}
	if !values[1].GetReadOnly() || !values[1].GetSkipIfEmpty() {
		t.Fatal("port filter-state value must be read-only and skip empty values")
	}
	return values[0].GetFormatString().GetTextFormatSource().GetInlineString()
}

func TestAppendSandboxHTTPFilters_ServiceEntries(t *testing.T) {
	push := &model.PushContext{AgentioConfig: &model.AgentioConfig{AgentioConfig: &extensions.AgentioConfig{
		EgressGateways: []*extensions.EgressGateway{{
			Name:      "egress-gw",
			Namespace: "istio-system",
			ServiceEntries: []*extensions.EgressServiceEntry{{
				Hosts:     []string{"api.example.com"},
				Endpoints: []*extensions.EgressServiceEntryEndpoint{{Address: "10.10.20.30"}, {Address: "10.10.20.31"}},
			}},
		}},
	}}}
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: push}

	filters := appendSandboxHTTPFilters(lb, nil, false)
	wantNames := []string{
		staticEndpointFilterStateFilter,
		"envoy.filters.http.dynamic_forward_proxy",
	}
	if got := len(filters); got != len(wantNames) {
		t.Fatalf("filters = %d, want %d: %v", got, len(wantNames), filters)
	}
	for index, want := range wantNames {
		if got := filters[index].GetName(); got != want {
			t.Fatalf("filter %d = %q, want %q", index, got, want)
		}
	}

	dfpConfig := &dfphttp.FilterConfig{}
	if err := filters[len(filters)-1].GetTypedConfig().UnmarshalTo(dfpConfig); err != nil {
		t.Fatalf("decode DFP filter config: %v", err)
	}
	if !dfpConfig.GetAllowDynamicHostFromFilterState() {
		t.Fatal("DFP filter must allow service-entry endpoint selection from filter state")
	}

	filterStateConfig := &sfshttp.Config{}
	if err := filters[0].GetTypedConfig().UnmarshalTo(filterStateConfig); err != nil {
		t.Fatalf("decode listener set-filter-state config: %v", err)
	}
	if got := len(filterStateConfig.GetOnRequestHeaders()); got != 0 {
		t.Fatalf("listener set-filter-state values = %d, want route-only configuration", got)
	}
}

func TestBuildSandboxHTTPRouteConfig_AppliesInboundEnvoyFilterPatches(t *testing.T) {
	patchValue, err := xds.BuildXDSObjectFromStruct(
		networking.EnvoyFilter_ROUTE_CONFIGURATION,
		buildPatchStruct(`{"request_headers_to_remove":["x-sandbox-test"]}`),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	lb := &ListenerBuilder{
		node: sandboxEgressNode(),
		push: &model.PushContext{},
		envoyFilterWrapper: &model.MergedEnvoyFilterWrapper{
			Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
				networking.EnvoyFilter_ROUTE_CONFIGURATION: {{
					Operation: networking.EnvoyFilter_Patch_MERGE,
					Match: &networking.EnvoyFilter_EnvoyConfigObjectMatch{
						Context: networking.EnvoyFilter_SIDECAR_INBOUND,
					},
					Value: patchValue,
				}},
			},
		},
	}
	cc := testInboundChainConfig("passthrough")
	connPool := makeConnPool()

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, rc.RequestHeadersToRemove, []string{"x-sandbox-test"})
}

// --- buildSandboxRoute ---

func TestBuildSandboxRoute_NilSettings(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	r := buildSandboxRoute(lb, cc, nil)

	assert.Equal(t, r.GetRoute().Timeout.AsDuration(), time.Duration(0))
}

func TestBuildSandboxRoute_WithTimeout(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	r := buildSandboxRoute(lb, cc, &extensions.HttpRouteSettings{
		Timeout: durationpb.New(30 * time.Second),
	})

	assert.Equal(t, r.GetRoute().Timeout.AsDuration(), 30*time.Second)
}

func TestBuildSandboxRoute_WithRetry(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	r := buildSandboxRoute(lb, cc, &extensions.HttpRouteSettings{
		Retries: &networking.HTTPRetry{
			Attempts:      3,
			PerTryTimeout: durationpb.New(5 * time.Second),
			RetryOn:       "connect-failure,refused-stream",
		},
	})

	rp := r.GetRoute().GetRetryPolicy()
	assert.Equal(t, rp.PerTryTimeout.AsDuration(), 5*time.Second)
	assert.Equal(t, rp.NumRetries.GetValue(), uint32(3))
	assert.Equal(t, rp.RetryOn, "connect-failure,refused-stream")
}

func TestBuildSandboxRoute_RouteMatch(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	r := buildSandboxRoute(lb, cc, nil)

	assert.Equal(t, r.GetMatch().GetPrefix(), "/")
	assert.Equal(t, r.Name, "default")
}

func TestBuildSandboxRoute_ClusterMatchesChainConfig(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("tls_connect_originate")

	r := buildSandboxRoute(lb, cc, &extensions.HttpRouteSettings{
		Timeout: durationpb.New(60 * time.Second),
	})

	assert.Equal(t, r.GetRoute().GetCluster(), "tls_connect_originate")
}

// --- applySandboxStreamIdleTimeout ---

func TestApplySandboxStreamIdleTimeout_Default(t *testing.T) {
	lb := &ListenerBuilder{
		node: sandboxEgressNode(),
		push: &model.PushContext{
			AgentioConfig: &model.AgentioConfig{
				AgentioConfig: &extensions.AgentioConfig{
					EgressGateways: []*extensions.EgressGateway{{
						Name:      "egress-gw",
						Namespace: "istio-system",
					}},
				},
			},
		},
	}
	h := &hcm.HttpConnectionManager{StreamIdleTimeout: durationpb.New(0)}

	applySandboxStreamIdleTimeout(lb, h)

	assert.Equal(t, h.StreamIdleTimeout.AsDuration(), 30*time.Minute)
}

func TestApplySandboxStreamIdleTimeout_Configured(t *testing.T) {
	lb := &ListenerBuilder{
		node: sandboxEgressNode(),
		push: &model.PushContext{
			AgentioConfig: &model.AgentioConfig{
				AgentioConfig: &extensions.AgentioConfig{
					EgressGateways: []*extensions.EgressGateway{{
						Name:      "egress-gw",
						Namespace: "istio-system",
						ConnectionPool: makeConnPool(
							withStreamIdleTimeout(10 * time.Minute),
						),
					}},
				},
			},
		},
	}
	h := &hcm.HttpConnectionManager{StreamIdleTimeout: durationpb.New(0)}

	applySandboxStreamIdleTimeout(lb, h)

	assert.Equal(t, h.StreamIdleTimeout.AsDuration(), 10*time.Minute)
}

func TestApplySandboxStreamIdleTimeout_NonSandboxNoop(t *testing.T) {
	lb := &ListenerBuilder{
		node: nonSandboxNode(),
		push: &model.PushContext{},
	}
	h := &hcm.HttpConnectionManager{StreamIdleTimeout: durationpb.New(0)}

	applySandboxStreamIdleTimeout(lb, h)

	assert.Equal(t, h.StreamIdleTimeout.AsDuration(), time.Duration(0))
}

// --- applySandboxTCPTimeouts ---

func TestApplySandboxTCPTimeouts_Defaults(t *testing.T) {
	tp := &tcp.TcpProxy{}

	applySandboxTCPTimeouts(nil, tp)

	assert.Equal(t, tp.IdleTimeout.AsDuration(), 1*time.Hour)
	assert.Equal(t, tp.MaxDownstreamConnectionDuration == nil, true)
}

func TestApplySandboxTCPTimeouts_Configured(t *testing.T) {
	tp := &tcp.TcpProxy{}
	connPool := makeConnPool(
		withTCPIdleTimeout(30*time.Minute),
		withTCPMaxConnDuration(24*time.Hour),
	)

	applySandboxTCPTimeouts(connPool, tp)

	assert.Equal(t, tp.IdleTimeout.AsDuration(), 30*time.Minute)
	assert.Equal(t, tp.MaxDownstreamConnectionDuration.AsDuration(), 24*time.Hour)
}

func TestApplySandboxTCPTimeouts_PartialConfig(t *testing.T) {
	tp := &tcp.TcpProxy{}
	connPool := makeConnPool(withTCPMaxConnDuration(2 * time.Hour))

	applySandboxTCPTimeouts(connPool, tp)

	assert.Equal(t, tp.IdleTimeout.AsDuration(), 1*time.Hour)
	assert.Equal(t, tp.MaxDownstreamConnectionDuration.AsDuration(), 2*time.Hour)
}

func TestApplySandboxTCPTimeouts_EmptyConnPool(t *testing.T) {
	tp := &tcp.TcpProxy{}
	connPool := makeConnPool()

	applySandboxTCPTimeouts(connPool, tp)

	assert.Equal(t, tp.IdleTimeout.AsDuration(), 1*time.Hour)
	assert.Equal(t, tp.MaxDownstreamConnectionDuration == nil, true)
}

// --- Error state / validation ---

func TestBuildSandboxRoute_DecoratorNonEmpty(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}

	for _, cluster := range []string{"passthrough", "encap", "tls_connect_originate"} {
		t.Run(cluster, func(t *testing.T) {
			cc := testInboundChainConfig(cluster)
			r := buildSandboxRoute(lb, cc, nil)
			op := r.GetDecorator().GetOperation()
			if op == "" {
				t.Fatalf("decorator operation must be non-empty (Envoy requires >= 1 char), got empty for cluster %q", cluster)
			}
		})
	}
}

func TestBuildSandboxRoute_DecoratorNonEmptyWithSettings(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("encap")

	r := buildSandboxRoute(lb, cc, &extensions.HttpRouteSettings{
		Timeout: durationpb.New(30 * time.Second),
	})

	if r.GetDecorator().GetOperation() == "" {
		t.Fatal("decorator operation must be non-empty with settings")
	}
}

func TestBuildSandboxHTTPRouteConfig_AllRoutesHaveValidDecorator(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("encap")
	connPool := makeConnPool(
		withRouteOverride([]string{"a.com"}, 10*time.Second),
		withDefaultRoute(60*time.Second),
	)

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	for _, vh := range rc.VirtualHosts {
		for _, r := range vh.Routes {
			if r.GetDecorator().GetOperation() == "" {
				t.Fatalf("VirtualHost %q route has empty decorator operation", vh.Name)
			}
		}
	}
}

func TestBuildSandboxHTTPRouteConfig_ValidateClustersDisabled(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	rc := buildSandboxHTTPRouteConfig(lb, cc, makeConnPool())

	if rc.ValidateClusters == nil || rc.ValidateClusters.Value {
		t.Fatal("ValidateClusters must be false for sandbox DFP routes")
	}
}

func TestBuildSandboxHTTPRouteConfig_FallbackAlwaysPresent(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("passthrough")

	cases := []struct {
		name     string
		connPool *extensions.ConnectionPoolSettings
	}{
		{"nil http", makeConnPool()},
		{"empty overrides", makeConnPool(withDefaultRoute(30 * time.Second))},
		{"only overrides", makeConnPool(withRouteOverride([]string{"a.com"}, 10*time.Second))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := buildSandboxHTTPRouteConfig(lb, cc, tc.connPool)
			last := rc.VirtualHosts[len(rc.VirtualHosts)-1]
			assert.Equal(t, last.Domains, []string{"*"})
		})
	}
}

func TestApplySandboxTCPTimeouts_NilConnPool_NeverPanics(t *testing.T) {
	tp := &tcp.TcpProxy{}
	applySandboxTCPTimeouts(nil, tp)
	if tp.IdleTimeout == nil {
		t.Fatal("IdleTimeout must be set to default even with nil connPool")
	}
}

// --- Full scenario ---

func sandboxLBWithRateLimit(rl *extensions.LocalRateLimitSettings) *ListenerBuilder {
	return &ListenerBuilder{
		node: sandboxEgressNode(),
		push: &model.PushContext{
			AgentioConfig: &model.AgentioConfig{
				AgentioConfig: &extensions.AgentioConfig{
					EgressGateways: []*extensions.EgressGateway{{
						Name:             "egress-gw",
						Namespace:        "istio-system",
						ConnectRateLimit: rl,
					}},
				},
			},
		},
	}
}

func parseRateLimitFilter(f *hcm.HttpFilter) *localratelimit.LocalRateLimit {
	if f == nil {
		return nil
	}
	cfg := &localratelimit.LocalRateLimit{}
	if err := proto.Unmarshal(f.GetTypedConfig().GetValue(), cfg); err != nil {
		return nil
	}
	return cfg
}

// --- buildSandboxConnectTerminateRateLimitFilter ---

func TestRateLimit_NilWhenNotConfigured(t *testing.T) {
	lb := sandboxLBWithRateLimit(nil)

	f := buildSandboxConnectTerminateRateLimitFilter(lb)

	assert.Equal(t, f == nil, true)
}

func TestRateLimit_NilForNonSandbox(t *testing.T) {
	lb := &ListenerBuilder{
		node: nonSandboxNode(),
		push: &model.PushContext{},
	}

	f := buildSandboxConnectTerminateRateLimitFilter(lb)

	assert.Equal(t, f == nil, true)
}

func TestRateLimit_GlobalBucketOnly(t *testing.T) {
	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		TokenBucket: &extensions.TokenBucket{
			MaxTokens:     100,
			TokensPerFill: 50,
			FillInterval:  durationpb.New(time.Second),
		},
	})

	f := buildSandboxConnectTerminateRateLimitFilter(lb)

	assert.Equal(t, f != nil, true)
	cfg := parseRateLimitFilter(f)
	assert.Equal(t, cfg.StatPrefix, "connect_rate_limit")
	assert.Equal(t, cfg.TokenBucket.MaxTokens, uint32(100))
	assert.Equal(t, cfg.TokenBucket.TokensPerFill.GetValue(), uint32(50))
	assert.Equal(t, cfg.TokenBucket.FillInterval.AsDuration(), time.Second)
	assert.Equal(t, cfg.FilterEnabled.DefaultValue.Numerator, uint32(100))
	assert.Equal(t, cfg.FilterEnforced.DefaultValue.Numerator, uint32(100))
	assert.Equal(t, len(cfg.Descriptors), 0)
	assert.Equal(t, len(cfg.RateLimits), 0)
}

func TestRateLimit_PerDownstreamConnection(t *testing.T) {
	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		TokenBucket: &extensions.TokenBucket{
			MaxTokens:     10,
			TokensPerFill: 10,
			FillInterval:  durationpb.New(time.Second),
		},
		PerDownstreamConnection: true,
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, cfg.LocalRateLimitPerDownstreamConnection, true)
}

func TestRateLimit_WithDescriptors(t *testing.T) {
	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		TokenBucket: &extensions.TokenBucket{
			MaxTokens:     100,
			TokensPerFill: 100,
			FillInterval:  durationpb.New(time.Second),
		},
		Descriptors: []*extensions.RateLimitDescriptor{
			{
				Entries: []*extensions.RateLimitEntry{
					{Key: "client_ip", Cel: `source.address`},
				},
				TokenBucket: &extensions.TokenBucket{
					MaxTokens:     10,
					TokensPerFill: 10,
					FillInterval:  durationpb.New(time.Second),
				},
			},
		},
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, len(cfg.Descriptors), 1)
	assert.Equal(t, cfg.Descriptors[0].Entries[0].Key, "client_ip")
	assert.Equal(t, cfg.Descriptors[0].TokenBucket.MaxTokens, uint32(10))

	assert.Equal(t, len(cfg.RateLimits), 1)
	assert.Equal(t, cfg.RateLimits[0].Actions[0].GetExtension() != nil, true)
}

func TestRateLimit_MultipleDescriptorKeys(t *testing.T) {
	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		Descriptors: []*extensions.RateLimitDescriptor{
			{
				Entries: []*extensions.RateLimitEntry{
					{Key: "peer_ns", Cel: `filter_state["downstream_peer"].namespace`},
					{Key: "peer_name", Cel: `filter_state["downstream_peer"].name`},
				},
				TokenBucket: &extensions.TokenBucket{
					MaxTokens: 5, TokensPerFill: 5,
					FillInterval: durationpb.New(time.Second),
				},
			},
		},
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, len(cfg.Descriptors), 1)
	assert.Equal(t, len(cfg.Descriptors[0].Entries), 2)

	assert.Equal(t, len(cfg.RateLimits), 1)
	assert.Equal(t, len(cfg.RateLimits[0].Actions), 2)
}

func TestRateLimit_DescriptorWithoutCEL_NoAction(t *testing.T) {
	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		TokenBucket: &extensions.TokenBucket{
			MaxTokens: 100, TokensPerFill: 100,
			FillInterval: durationpb.New(time.Second),
		},
		Descriptors: []*extensions.RateLimitDescriptor{
			{
				Entries: []*extensions.RateLimitEntry{
					{Key: "static_key", Value: "static_value"},
				},
				TokenBucket: &extensions.TokenBucket{
					MaxTokens: 20, TokensPerFill: 20,
					FillInterval: durationpb.New(time.Second),
				},
			},
		},
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, len(cfg.Descriptors), 1)
	assert.Equal(t, len(cfg.RateLimits), 0)
}

func TestRateLimit_CELExpression(t *testing.T) {
	lb := sandboxLBWithRateLimit(&extensions.LocalRateLimitSettings{
		Descriptors: []*extensions.RateLimitDescriptor{
			{
				Entries: []*extensions.RateLimitEntry{
					{
						Key: "downstream_name",
						Cel: `filter_state["downstream_peer"].name`,
					},
				},
				TokenBucket: &extensions.TokenBucket{
					MaxTokens: 5, TokensPerFill: 5,
					FillInterval: durationpb.New(time.Second),
				},
			},
		},
	})

	cfg := parseRateLimitFilter(buildSandboxConnectTerminateRateLimitFilter(lb))

	assert.Equal(t, len(cfg.Descriptors), 1)
	assert.Equal(t, cfg.Descriptors[0].Entries[0].Key, "downstream_name")

	action := cfg.RateLimits[0].Actions[0]
	assert.Equal(t, action.GetExtension() != nil, true)
	assert.Equal(t, action.GetExtension().Name, "envoy.rate_limit_descriptors.expr")
}

// --- toEnvoyTokenBucket ---

func TestToEnvoyTokenBucket_Nil(t *testing.T) {
	assert.Equal(t, toEnvoyTokenBucket(nil) == nil, true)
}

func TestToEnvoyTokenBucket_Full(t *testing.T) {
	tb := toEnvoyTokenBucket(&extensions.TokenBucket{
		MaxTokens:     200,
		TokensPerFill: 50,
		FillInterval:  durationpb.New(500 * time.Millisecond),
	})
	assert.Equal(t, tb.MaxTokens, uint32(200))
	assert.Equal(t, tb.TokensPerFill.GetValue(), uint32(50))
	assert.Equal(t, tb.FillInterval.AsDuration(), 500*time.Millisecond)
}

func TestToEnvoyTokenBucket_ZeroTokensPerFill(t *testing.T) {
	tb := toEnvoyTokenBucket(&extensions.TokenBucket{
		MaxTokens:    10,
		FillInterval: durationpb.New(time.Second),
	})
	assert.Equal(t, tb.TokensPerFill == nil, true)
}

// --- Full scenario ---

func TestBuildSandboxHTTPRouteConfig_FullScenario(t *testing.T) {
	lb := &ListenerBuilder{node: sandboxEgressNode(), push: &model.PushContext{}}
	cc := testInboundChainConfig("tls_connect_originate")

	connPool := makeConnPool(
		withRouteOverride([]string{"ws.example.com"}, 0),
		withRouteOverride([]string{"api.example.com", "api2.example.com"}, 60*time.Second),
		withDefaultRoute(120*time.Second),
	)
	connPool.Http.RouteOverrides[1].Settings.Retries = &networking.HTTPRetry{
		Attempts:      3,
		PerTryTimeout: durationpb.New(10 * time.Second),
		RetryOn:       "connect-failure,refused-stream",
	}

	rc := buildSandboxHTTPRouteConfig(lb, cc, connPool)

	assert.Equal(t, rc.Name, "tls_connect_originate")
	assert.Equal(t, len(rc.VirtualHosts), 3)

	// ws.example.com: timeout=0 (disabled for websocket)
	wsVH := rc.VirtualHosts[0]
	assert.Equal(t, wsVH.Domains, []string{"ws.example.com"})
	assert.Equal(t, wsVH.Routes[0].GetRoute().Timeout.AsDuration(), time.Duration(0))

	// api: timeout=60s, per_try=10s, retries=3
	apiVH := rc.VirtualHosts[1]
	assert.Equal(t, apiVH.Domains, []string{"api.example.com", "api2.example.com"})
	assert.Equal(t, apiVH.Routes[0].GetRoute().Timeout.AsDuration(), 60*time.Second)
	assert.Equal(t, apiVH.Routes[0].GetRoute().GetRetryPolicy().PerTryTimeout.AsDuration(), 10*time.Second)
	assert.Equal(t, apiVH.Routes[0].GetRoute().GetRetryPolicy().NumRetries.GetValue(), uint32(3))
	assert.Equal(t, apiVH.Routes[0].GetRoute().GetRetryPolicy().RetryOn, "connect-failure,refused-stream")

	// fallback: timeout=120s
	fallbackVH := rc.VirtualHosts[2]
	assert.Equal(t, fallbackVH.Domains, []string{"*"})
	assert.Equal(t, fallbackVH.Routes[0].GetRoute().Timeout.AsDuration(), 120*time.Second)

	for _, vh := range rc.VirtualHosts {
		for _, r := range vh.Routes {
			assert.Equal(t, r.GetRoute().GetCluster(), "tls_connect_originate")
		}
	}
}
