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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	dfpclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	setstatenetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	dfpnetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/retry/host/previous_hosts/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	meshv1alpha1 "istio.io/api/mesh/v1alpha1"
	networkingv1alpha3 "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

const legacyAgentioGatewayOracleCommit = "4e6107d0444555a193b1a9224626a0e59d79b34c"

type gatewayGolden struct {
	Source       string                  `json:"source"`
	SourceCommit string                  `json:"source_commit,omitempty"`
	Fixture      string                  `json:"fixture"`
	Notes        []string                `json:"notes,omitempty"`
	Resources    []gatewayGoldenResource `json:"resources"`
}

type gatewayGoldenResource struct {
	TypeURL  string          `json:"type_url"`
	Name     string          `json:"name"`
	Resource json.RawMessage `json:"resource"`
}

func TestSupportedGatewayGraphParity(t *testing.T) {
	got := normalizeGatewayResources(buildCompleteGatewayGraph(t))
	expected := readNormalizedGatewayGolden(t, "testdata/agentio-supported-gateway.json")
	if diff := semanticGatewayDiff(expected, got); len(diff) != 0 {
		t.Fatalf("Agentio gateway golden is stale:\n%s", strings.Join(diff, "\n"))
	}

	legacy := readNormalizedGatewayGolden(t, "testdata/legacy-agentio-supported-gateway.json")
	if diff := semanticGatewayDiff(legacy, got); len(diff) != 0 {
		t.Logf("Legacy Agentio supported-gateway differences:\n%s", strings.Join(diff, "\n"))
	}
}

func TestSupportedGatewayClusterParity(t *testing.T) {
	got := normalizeGatewayResources(buildCompleteGatewayGraph(t))
	want := readNormalizedGatewayGolden(t, "testdata/legacy-agentio-supported-gateway.json")
	for key, message := range got {
		if !strings.HasPrefix(key, model.ClusterType+"\x00") {
			delete(got, key)
			continue
		}
		// The gateway connect timeout belongs only to Passthrough and the two
		// DFP clusters; internal hops keep their explicit in-memory timeout.
		if cluster, ok := message.(*clusterv3.Cluster); ok &&
			(cluster.GetName() == MainInternal || cluster.GetName() == MainForward) {
			cluster.ConnectTimeout = nil
		}
	}
	for key := range want {
		if !strings.HasPrefix(key, model.ClusterType+"\x00") {
			delete(want, key)
		}
	}
	// Retained as a fail-closed default-route cluster.
	delete(got, gatewayResourceKey(model.ClusterType, BlackHoleCluster))
	if diff := semanticGatewayDiff(want, got); len(diff) != 0 {
		t.Fatalf("supported gateway cluster differences:\n%s", strings.Join(diff, "\n"))
	}
}

func TestSupportedGatewayListenerRouteParity(t *testing.T) {
	got := supportedListenerRouteParityView(t, normalizeGatewayResources(buildCompleteGatewayGraph(t)))
	want := supportedListenerRouteParityView(t, readNormalizedGatewayGolden(t, "testdata/legacy-agentio-supported-gateway.json"))
	if diff := semanticGatewayDiff(want, got); len(diff) != 0 {
		t.Fatalf("supported gateway listener/route differences:\n%s", strings.Join(diff, "\n"))
	}
}

func TestTLSOuterSNISeparatesInternalConnectionPools(t *testing.T) {
	resources := buildCompleteGatewayGraph(t)
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	chain := findFilterChain(t, listeners[MainInternal], tlsTerminateChain)
	config := &setstatenetworkv3.Config{}
	if err := chain.GetFilters()[0].GetTypedConfig().UnmarshalTo(config); err != nil {
		t.Fatalf("decode SNI capture before TCP proxy: %v", err)
	}
	values := config.GetOnNewConnection()
	if len(values) != 1 || values[0].GetObjectKey() != "io.kruise.outer_sni" {
		t.Fatalf("SNI capture must propagate exactly the outer SNI: %v", values)
	}
	state := values[0]
	// Envoy only includes Hashable shared state in the upstream pool key.
	// A plain string allows another SNI to inherit this connection's identity.
	if got := state.GetFactoryKey(); got != "istio.hashable_string" {
		t.Errorf("outer SNI factory = %q, want istio.hashable_string for pool isolation", got)
	}
	if got := state.GetSharedWithUpstream().String(); got != "ONCE" {
		t.Errorf("outer SNI sharing = %q, want ONCE for the internal listener hop", got)
	}
	if got := state.GetFormatString().GetTextFormatSource().GetInlineString(); got != "%REQUESTED_SERVER_NAME%" {
		t.Errorf("outer SNI format = %q, want ClientHello server name", got)
	}
}

func TestSupportedGatewayRuntimeInvariants(t *testing.T) {
	resources := buildCompleteGatewayGraph(t)
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener { return &listenerv3.Listener{} })
	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} })

	for listenerName, routeName := range map[string]string{
		ConnectTerminate: ConnectTerminate,
		MainInternal:     HTTPDynamicForwardProxy,
		MainForward:      TLSConnectOriginate,
	} {
		if got := findHCM(t, listeners[listenerName]).GetRds().GetRouteConfigName(); got != routeName {
			t.Errorf("listener %s RDS name = %q, want %q", listenerName, got, routeName)
		}
	}
	for listenerName, want := range map[string][]string{
		MainInternal: {"envoy.filters.http.ext_proc", "envoy.filters.http.dynamic_forward_proxy", "envoy.filters.http.router"},
		MainForward:  {"envoy.filters.http.rbac", "envoy.filters.http.ext_proc", "envoy.filters.http.dynamic_forward_proxy", "connect-proxy-tls-identity", "envoy.filters.http.router"},
	} {
		if got := httpFilterNames(findHCM(t, listeners[listenerName])); !equalStrings(got, want) {
			t.Errorf("listener %s HTTP filter order = %v, want %v", listenerName, got, want)
		}
	}

	connect := listeners[ConnectTerminate]
	if got := connect.GetFilterChains()[0].GetTransportSocket().GetName(); got != "envoy.transport_sockets.tls" {
		t.Errorf("CONNECT transport socket = %q, want envoy.transport_sockets.tls", got)
	}
	connectTLS := &tlsv3.DownstreamTlsContext{}
	if err := connect.GetFilterChains()[0].GetTransportSocket().GetTypedConfig().UnmarshalTo(connectTLS); err != nil {
		t.Fatalf("decode CONNECT TLS context: %v", err)
	}
	sans := connectTLS.GetCommonTlsContext().GetCombinedValidationContext().GetDefaultValidationContext().GetMatchTypedSubjectAltNames()
	if len(sans) != 1 || sans[0].GetSanType() != tlsv3.SubjectAltNameMatcher_URI ||
		sans[0].GetMatcher().GetPrefix() != "spiffe://cluster.local/" {
		t.Errorf("CONNECT strict SPIFFE SAN matchers = %+v", sans)
	}
	connectHCM := findHCM(t, connect)
	for _, filter := range connectHCM.GetHttpFilters() {
		if filter.GetName() != "connect_authority" {
			continue
		}
		config := &setstatehttpv3.Config{}
		if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
			t.Fatalf("decode CONNECT filter state: %v", err)
		}
		for _, state := range config.GetOnRequestHeaders() {
			if !state.GetFormatString().GetOmitEmptyValues() {
				t.Errorf("CONNECT filter-state key %q does not omit empty values", state.GetObjectKey())
			}
		}
	}
	tlsChain := findFilterChain(t, listeners[MainInternal], tlsTerminateChain)
	for _, filter := range tlsChain.GetFilters()[:2] {
		config := &setstatenetworkv3.Config{}
		if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
			t.Fatalf("decode TLS relay filter %s: %v", filter.GetName(), err)
		}
		for _, state := range config.GetOnNewConnection() {
			if !state.GetSkipIfEmpty() || !state.GetFormatString().GetOmitEmptyValues() {
				t.Errorf("TLS relay key %q must skip and omit empty values", state.GetObjectKey())
			}
		}
	}
	rawTCP := findFilterChain(t, listeners[MainForward], forwardTCPChain)
	if got, want := networkFilterNames(rawTCP), []string{
		"envoy.filters.network.sni_dynamic_forward_proxy", "envoy.filters.network.tcp_proxy",
	}; !equalStrings(got, want) {
		t.Errorf("MainForward raw-TCP filter order = %v, want %v", got, want)
	}
	rawDFP := &dfpnetworkv3.FilterConfig{}
	if err := rawTCP.GetFilters()[0].GetTypedConfig().UnmarshalTo(rawDFP); err != nil {
		t.Fatalf("decode MainForward raw-TCP SNI DFP: %v", err)
	}
	tlsDFP := &dfpclusterv3.ClusterConfig{}
	if err := clusters[TLSConnectOriginate].GetClusterType().GetTypedConfig().UnmarshalTo(tlsDFP); err != nil {
		t.Fatalf("decode TLS DFP cluster config: %v", err)
	}
	if !proto.Equal(rawDFP.GetDnsCacheConfig(), tlsDFP.GetDnsCacheConfig()) {
		t.Errorf("MainForward raw-TCP DNS cache differs from TLS DFP cluster: raw=%v cluster=%v",
			rawDFP.GetDnsCacheConfig(), tlsDFP.GetDnsCacheConfig())
	}
	if got := rawDFP.GetPortValue(); got != 443 {
		t.Errorf("MainForward raw-TCP SNI DFP port = %d, want 443", got)
	}

	forwardMatcher := listeners[MainForward].GetFilterChainMatcher()
	forwardTree := forwardMatcher.GetMatcherTree()
	forwardApp := forwardMatcher.GetOnNoMatch().GetMatcher()
	const (
		transportProtocolInputType   = "type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.TransportProtocolInput"
		applicationProtocolInputType = "type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.ApplicationProtocolInput"
		serverNameInputType          = "type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.ServerNameInput"
	)
	if got := forwardTree.GetInput().GetTypedConfig().GetTypeUrl(); got != transportProtocolInputType {
		t.Errorf("MainForward outer matcher input = %q, want %q", got, transportProtocolInputType)
	}
	if got := forwardApp.GetMatcherTree().GetInput().GetTypedConfig().GetTypeUrl(); got != applicationProtocolInputType {
		t.Errorf("MainForward application fallback input = %q, want %q", got, applicationProtocolInputType)
	}
	decisions := []struct{ name, got, want string }{
		{"MainForward TLS", forwardTree.GetExactMatchMap().GetMap()["tls"].GetAction().GetName(), forwardTCPChain},
		{"MainForward HTTP/1.1", forwardApp.GetMatcherTree().GetExactMatchMap().GetMap()["'http/1.1'"].GetAction().GetName(), forwardHTTPChain},
		{"MainForward h2c", forwardApp.GetMatcherTree().GetExactMatchMap().GetMap()["'h2c'"].GetAction().GetName(), forwardHTTPChain},
		{"MainForward TCP fallback", forwardApp.GetOnNoMatch().GetAction().GetName(), forwardTCPChain},
	}

	internalMatcher := listeners[MainInternal].GetFilterChainMatcher()
	internalTree := internalMatcher.GetMatcherTree()
	if got := internalTree.GetInput().GetTypedConfig().GetTypeUrl(); got != transportProtocolInputType {
		t.Errorf("MainInternal outer matcher input = %q, want %q", got, transportProtocolInputType)
	}
	excludeMatcher := internalTree.GetExactMatchMap().GetMap()["tls"].GetMatcher()
	if got := excludeMatcher.GetMatcherTree().GetInput().GetTypedConfig().GetTypeUrl(); got != serverNameInputType {
		t.Errorf("MainInternal exclusion matcher input = %q, want %q", got, serverNameInputType)
	}
	excludes := &xdsmatcherv3.ServerNameMatcher{}
	if err := excludeMatcher.GetMatcherTree().GetCustomMatch().GetTypedConfig().UnmarshalTo(excludes); err != nil {
		t.Fatalf("decode MainInternal SNI exclusions: %v", err)
	}
	if len(excludes.GetDomainMatchers()) != 1 || !equalStrings(excludes.GetDomainMatchers()[0].GetDomains(), []string{"legacy.example.com"}) {
		t.Fatalf("MainInternal SNI exclusions = %+v", excludes.GetDomainMatchers())
	}
	decisions = append(decisions, struct{ name, got, want string }{
		"MainInternal excluded SNI", excludes.GetDomainMatchers()[0].GetOnMatch().GetAction().GetName(), forwardTCPChain,
	})
	policyMatcher := excludeMatcher.GetOnNoMatch().GetMatcher()
	if got := policyMatcher.GetMatcherTree().GetInput().GetTypedConfig().GetTypeUrl(); got != serverNameInputType {
		t.Errorf("MainInternal SNI policy matcher input = %q, want %q", got, serverNameInputType)
	}
	policyConfig := &udpatypev1.TypedStruct{}
	if err := policyMatcher.GetMatcherTree().GetCustomMatch().GetTypedConfig().UnmarshalTo(policyConfig); err != nil {
		t.Fatalf("decode MainInternal SNI policy: %v", err)
	}
	failureMode := policyConfig.GetValue().GetFields()["failure_mode_allow"].GetStructValue().GetFields()
	defaultValue, hasDefault := failureMode["default_value"]
	defaultBool, isBool := defaultValue.GetKind().(*structpb.Value_BoolValue)
	if failureMode["runtime_key"].GetStringValue() != "kruise.sni_traffic_policy.failure_mode_allow" ||
		!hasDefault || !isBool || defaultBool.BoolValue {
		t.Errorf("MainInternal SNI failure mode = %+v, want runtime key with false default", failureMode)
	}
	for field, chain := range map[string]string{
		"on_tls_termination": tlsTerminateChain,
		"on_passthrough":     forwardTCPChain,
		"on_deny":            sniDenyChain,
	} {
		action := policyConfig.GetValue().GetFields()[field].GetStructValue().GetFields()["action"].GetStructValue()
		decisions = append(decisions, struct{ name, got, want string }{
			"MainInternal " + field, action.GetFields()["name"].GetStringValue(), chain,
		})
	}
	internalApp := internalMatcher.GetOnNoMatch().GetMatcher()
	if got := internalApp.GetMatcherTree().GetInput().GetTypedConfig().GetTypeUrl(); got != applicationProtocolInputType {
		t.Errorf("MainInternal application fallback input = %q, want %q", got, applicationProtocolInputType)
	}
	decisions = append(decisions,
		struct{ name, got, want string }{"MainInternal HTTP/1.1", internalApp.GetMatcherTree().GetExactMatchMap().GetMap()["'http/1.1'"].GetAction().GetName(), forwardHTTPChain},
		struct{ name, got, want string }{"MainInternal h2c", internalApp.GetMatcherTree().GetExactMatchMap().GetMap()["'h2c'"].GetAction().GetName(), forwardHTTPChain},
		struct{ name, got, want string }{"MainInternal TCP fallback", internalApp.GetOnNoMatch().GetAction().GetName(), forwardTCPChain},
	)
	for _, decision := range decisions {
		if decision.got != decision.want {
			t.Errorf("%s decision = %q, want %q", decision.name, decision.got, decision.want)
		}
	}

	for _, routeName := range []string{HTTPDynamicForwardProxy, TLSConnectOriginate} {
		for _, virtualHost := range routes[routeName].GetVirtualHosts() {
			for _, route := range virtualHost.GetRoutes() {
				action := route.GetRoute()
				if action.GetTimeout() == nil {
					t.Errorf("route %s/%s leaves timeout unset, falling back to Envoy's default 15s", routeName, virtualHost.GetName())
				}
				if grpc := action.GetMaxGrpcTimeout(); grpc != nil && !proto.Equal(grpc, action.GetTimeout()) {
					t.Errorf("route %s/%s max_grpc_timeout = %v, want %v", routeName, virtualHost.GetName(), grpc, action.GetTimeout())
				}
				if stream := action.GetMaxStreamDuration(); stream != nil &&
					(stream.GetMaxStreamDuration().AsDuration() != 0 || stream.GetGrpcTimeoutHeaderMax().AsDuration() != 0) {
					t.Errorf("route %s/%s max_stream_duration = %v, want zero-valued no-timeout", routeName, virtualHost.GetName(), stream)
				}
			}
		}
	}

	blackHole := clusters[BlackHoleCluster]
	if blackHole == nil {
		t.Fatal("BlackHole cluster is missing")
	}
	if got := blackHole.GetType(); got != clusterv3.Cluster_STATIC {
		t.Errorf("BlackHole cluster type = %v, want STATIC", got)
	}
	if endpoints := blackHole.GetLoadAssignment().GetEndpoints(); len(endpoints) != 0 {
		t.Errorf("BlackHole cluster endpoints = %v, want none", endpoints)
	}
	denyProxy := &tcpproxyv3.TcpProxy{}
	denyChain := findFilterChain(t, listeners[MainInternal], sniDenyChain)
	if err := denyChain.GetFilters()[0].GetTypedConfig().UnmarshalTo(denyProxy); err != nil {
		t.Fatalf("decode SNI deny TCP proxy: %v", err)
	}
	if got := denyProxy.GetCluster(); got != BlackHoleCluster {
		t.Errorf("SNI deny chain cluster = %q, want %q", got, BlackHoleCluster)
	}
}

func supportedListenerRouteParityView(t *testing.T, resources map[string]proto.Message) map[string]proto.Message {
	t.Helper()
	result := make(map[string]proto.Message, len(resources))
	for key, resource := range resources {
		switch resource.(type) {
		case *listenerv3.Listener, *routev3.RouteConfiguration:
			result[key] = proto.Clone(resource)
		}
	}

	for _, resource := range result {
		switch value := resource.(type) {
		case *listenerv3.Listener:
			switch value.GetName() {
			case ConnectTerminate:
				// Keep the current Agentio graph's canonical socket label, strict SPIFFE SAN,
				// omit-empty filter state, and refusal to propagate caller XFCC.
				chain := value.GetFilterChains()[0]
				chain.GetTransportSocket().Name = ""
				tlsContext := &tlsv3.DownstreamTlsContext{}
				if err := chain.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
					t.Fatalf("decode CONNECT TLS context: %v", err)
				}
				tlsContext.GetCommonTlsContext().GetCombinedValidationContext().GetDefaultValidationContext().MatchTypedSubjectAltNames = nil
				chain.GetTransportSocket().ConfigType = &corev3.TransportSocket_TypedConfig{TypedConfig: mustGatewayAny(t, tlsContext)}

				hcmFilter := chain.GetFilters()[0]
				hcm := &hcmv3.HttpConnectionManager{}
				if err := hcmFilter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
					t.Fatalf("decode CONNECT HCM: %v", err)
				}
				hcm.ForwardClientCertDetails = hcmv3.HttpConnectionManager_SANITIZE
				hcm.SetCurrentClientCertDetails = nil
				for _, filter := range hcm.GetHttpFilters() {
					if filter.GetName() != "connect_authority" {
						continue
					}
					config := &setstatehttpv3.Config{}
					if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
						t.Fatalf("decode CONNECT filter state: %v", err)
					}
					for _, state := range config.GetOnRequestHeaders() {
						state.GetFormatString().OmitEmptyValues = false
					}
					filter.ConfigType = &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustGatewayAny(t, config)}
				}
				hcmFilter.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: mustGatewayAny(t, hcm)}
			case MainInternal, MainForward:
				// The two builders start from different matcher-tree bases but select
				// the same supported chains. Compare every other listener field.
				value.FilterChainMatcher = nil
				for _, chain := range value.GetFilterChains() {
					if value.GetName() == MainForward && chain.GetName() == forwardTCPChain {
						filters := chain.GetFilters()[:0]
						for _, filter := range chain.GetFilters() {
							if filter.GetName() != "envoy.filters.network.sni_dynamic_forward_proxy" {
								filters = append(filters, filter)
							}
						}
						chain.Filters = filters
					}
					if value.GetName() == MainInternal && chain.GetName() == tlsTerminateChain {
						chain.GetFilters()[0].Name = ""
						// Legacy captures SNI as a non-hashable string. Pool isolation
						// intentionally differs and is checked by the runtime contract test.
						capture := chain.GetFilters()[0]
						config := &setstatenetworkv3.Config{}
						if err := capture.GetTypedConfig().UnmarshalTo(config); err != nil {
							t.Fatalf("decode outer SNI capture: %v", err)
						}
						for _, state := range config.GetOnNewConnection() {
							if state.GetObjectKey() == "io.kruise.outer_sni" {
								state.FactoryKey = ""
							}
						}
						capture.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: mustGatewayAny(t, config)}
					}
				}
			}
		case *routev3.RouteConfiguration:
			// The legacy Agentio graph left the outer CONNECT timeout unset.
			// Current Agentio explicitly disables it so Envoy's request timeout cannot
			// cap a long-lived tunnel; the dedicated route contract test pins that
			// safety behavior outside the upstream parity comparison.
			if value.GetName() == ConnectTerminate {
				for _, virtualHost := range value.GetVirtualHosts() {
					for _, route := range virtualHost.GetRoutes() {
						route.GetRoute().Timeout = nil
					}
				}
			}
			// Nil out max_grpc_timeout: only meaningful when an inherited
			// MaxStreamDuration is cleared.
			for _, virtualHost := range value.GetVirtualHosts() {
				for _, route := range virtualHost.GetRoutes() {
					route.GetRoute().MaxGrpcTimeout = nil
				}
			}
		}
	}
	return result
}

func mustGatewayAny(t *testing.T, message proto.Message) *anypb.Any {
	t.Helper()
	result, err := anypb.New(message)
	if err != nil {
		t.Fatalf("encode parity message: %v", err)
	}
	return result
}

func TestSemanticGatewayDiffReportsFieldsAndDirection(t *testing.T) {
	key := gatewayResourceKey(model.ClusterType, "example")
	want := map[string]proto.Message{key: &clusterv3.Cluster{
		Name: "example", ConnectTimeout: durationpb.New(7 * time.Second),
	}}
	got := map[string]proto.Message{key: &clusterv3.Cluster{
		Name: "example", ConnectTimeout: durationpb.New(10 * time.Second),
	}}

	diff := strings.Join(semanticGatewayDiff(want, got), "\n")
	for _, fragment := range []string{
		"~ protobuf diff (-expected +actual): " + displayGatewayResourceKey(key),
		`"connect_timeout"`,
	} {
		if !strings.Contains(diff, fragment) {
			t.Fatalf("semantic diff does not contain %q:\n%s", fragment, diff)
		}
	}
	for _, line := range []struct {
		prefix string
		value  string
	}{
		{prefix: "-", value: `"seconds": int64(7)`},
		{prefix: "+", value: `"seconds": int64(10)`},
	} {
		if !diffHasLine(diff, line.prefix, line.value) {
			t.Fatalf("semantic diff does not contain %sexpected/actual value %s:\n%s", line.prefix, line.value, diff)
		}
	}
}

func diffHasLine(diff, prefix, value string) bool {
	for line := range strings.SplitSeq(diff, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) && strings.Contains(line, value) {
			return true
		}
	}
	return false
}

func TestGatewayResourcesValidate(t *testing.T) {
	for _, path := range []string{
		"testdata/agentio-supported-gateway.json",
		"testdata/legacy-agentio-supported-gateway.json",
	} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			for key, message := range readNormalizedGatewayGolden(t, path) {
				var err error
				switch resource := message.(type) {
				case *clusterv3.Cluster:
					err = resource.ValidateAll()
				case *listenerv3.Listener:
					err = resource.ValidateAll()
				case *routev3.RouteConfiguration:
					err = resource.ValidateAll()
				}
				if err != nil {
					t.Errorf("%s: %v", key, err)
				}
			}
		})
	}
}

func buildCompleteGatewayGraph(t *testing.T) []model.Resource {
	t.Helper()
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	test.SetForTest(t, &features.GatewayConnectTimeout, 7*time.Second)
	test.SetForTest(t, &features.GatewayRootCAPath, "/etc/ssl/cert.pem")
	resources, err := Build(Inputs{
		Gateway: model.Gateway{
			Namespace: "agentio-system",
			Name:      "egress",
			Config: &configv1.EgressGateway{
				TlsTermination: &configv1.TlsTerminationConfig{
					IncludeHosts: []string{"*.example.com"},
					ExcludeHosts: []string{"legacy.example.com"},
				},
				ConnectionPool: &configv1.ConnectionPoolSettings{
					Tcp: &configv1.TcpSettings{
						IdleTimeout:           durationpb.New(2 * time.Minute),
						MaxConnectionDuration: durationpb.New(10 * time.Minute),
					},
					Http: &configv1.ConnectionPoolHttpSettings{
						StreamIdleTimeout: durationpb.New(3 * time.Minute),
						DefaultRoute: &configv1.HttpRouteSettings{
							Timeout: durationpb.New(12 * time.Second),
						},
						RouteOverrides: []*configv1.HttpRouteOverride{{
							Hosts: []string{"api.example.com", "*.api.example.com"},
							Settings: &configv1.HttpRouteSettings{
								Timeout: durationpb.New(4 * time.Second),
								Retries: &networkingv1alpha3.HTTPRetry{
									Attempts:      3,
									PerTryTimeout: durationpb.New(time.Second),
									RetryOn:       "connect-failure,refused-stream",
								},
							},
						}},
					},
				},
				ConnectRateLimit: &configv1.LocalRateLimitSettings{
					TokenBucket: &configv1.TokenBucket{
						MaxTokens:     20,
						TokensPerFill: 5,
						FillInterval:  durationpb.New(time.Second),
					},
					Descriptors: []*configv1.RateLimitDescriptor{{
						Entries: []*configv1.RateLimitEntry{{
							Key: "peer",
							Cel: `string(filter_state["io.istio.peer_principal"])`,
						}},
						TokenBucket: &configv1.TokenBucket{
							MaxTokens:     2,
							TokensPerFill: 1,
							FillInterval:  durationpb.New(time.Second),
						},
					}},
				},
			},
		},
		GlobalExtProc: &configv1.ExtProcProvider{
			Service:          "epe.agentio-system.svc",
			Port:             9002,
			MessageTimeout:   "350ms",
			FailureModeAllow: true,
			Request: &configv1.ProcessingModeOptions{
				HeaderMode: configv1.HeaderSendMode_SEND,
				Attributes: []string{"request.id"},
			},
			Response: &configv1.ProcessingModeOptions{
				HeaderMode: configv1.HeaderSendMode_SEND,
				Attributes: []string{"response.code"},
			},
			ClusterSettings: &configv1.ClusterSettings{
				Http: &configv1.HttpSettings{
					MaxConcurrentStreams:     73,
					MaxRequestsPerConnection: 41,
				},
			},
		},
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	})
	if err != nil {
		t.Fatalf("build complete gateway graph: %v", err)
	}
	return resources
}

func normalizeGatewayResources(resources []model.Resource) map[string]proto.Message {
	result := make(map[string]proto.Message, len(resources))
	for _, resource := range resources {
		var message proto.Message
		switch resource.Key.TypeURL {
		case model.ClusterType:
			message = &clusterv3.Cluster{}
		case model.ListenerType:
			message = &listenerv3.Listener{}
		case model.RouteType:
			message = &routev3.RouteConfiguration{}
		case model.ProxyConfigType:
			message = &meshv1alpha1.ProxyConfig{}
		default:
			continue
		}
		if err := resource.Value.UnmarshalTo(message); err != nil {
			panic(fmt.Sprintf("unmarshal gateway resource %s: %v", resource.Key.Name, err))
		}
		result[gatewayResourceKey(resource.Key.TypeURL, resource.XDSName)] = message
	}
	return result
}

func readNormalizedGatewayGolden(t *testing.T, path string) map[string]proto.Message {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read gateway golden %s: %v", path, err)
	}
	var golden gatewayGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("decode gateway golden %s: %v", path, err)
	}
	if filepath.Base(path) == "legacy-agentio-supported-gateway.json" && golden.SourceCommit != legacyAgentioGatewayOracleCommit {
		t.Fatalf("legacy Agentio gateway golden source commit = %q, want %q", golden.SourceCommit, legacyAgentioGatewayOracleCommit)
	}
	result := make(map[string]proto.Message, len(golden.Resources))
	for _, resource := range golden.Resources {
		message := newGatewayMessage(t, resource.TypeURL)
		if err := protojson.Unmarshal(resource.Resource, message); err != nil {
			t.Fatalf("decode %s %s: %v", resource.TypeURL, resource.Name, err)
		}
		result[gatewayResourceKey(resource.TypeURL, resource.Name)] = message
	}
	return result
}

func newGatewayMessage(t *testing.T, typeURL string) proto.Message {
	t.Helper()
	switch typeURL {
	case model.ClusterType:
		return &clusterv3.Cluster{}
	case model.ListenerType:
		return &listenerv3.Listener{}
	case model.RouteType:
		return &routev3.RouteConfiguration{}
	case model.ProxyConfigType:
		return &meshv1alpha1.ProxyConfig{}
	default:
		t.Fatalf("unsupported gateway golden type %q", typeURL)
		return nil
	}
}

func semanticGatewayDiff(want, got map[string]proto.Message) []string {
	keys := sets.NewWithLength[string](len(want) + len(got))
	for key := range want {
		keys.Insert(key)
	}
	for key := range got {
		keys.Insert(key)
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)

	var result []string
	for _, key := range ordered {
		left, wantFound := want[key]
		right, gotFound := got[key]
		switch {
		case !wantFound:
			result = append(result, "+ actual only: "+displayGatewayResourceKey(key))
		case !gotFound:
			result = append(result, "- expected only: "+displayGatewayResourceKey(key))
		case !cmp.Equal(left, right, protocmp.Transform()):
			result = append(result, fmt.Sprintf(
				"~ protobuf diff (-expected +actual): %s\n%s",
				displayGatewayResourceKey(key),
				cmp.Diff(left, right, protocmp.Transform()),
			))
		}
	}
	return result
}

func gatewayResourceKey(typeURL, name string) string {
	return typeURL + "\x00" + name
}

func displayGatewayResourceKey(key string) string {
	typeURL, name, _ := strings.Cut(key, "\x00")
	return typeURL + "/" + name
}
