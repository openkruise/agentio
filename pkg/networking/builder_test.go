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
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fileaccesslogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	celv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	dfpclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfpcommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	dfphttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	setstatenetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking/telemetry"
)

func TestBuildProducesProductionGatewayGraph(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	resources, err := Build(Inputs{
		Gateway: testGateway(&configv1.EgressGateway{
			ConnectionPool: &configv1.ConnectionPoolSettings{
				Tcp: &configv1.TcpSettings{IdleTimeout: durationpb.New(2 * time.Minute)},
				Http: &configv1.ConnectionPoolHttpSettings{
					StreamIdleTimeout: durationpb.New(3 * time.Minute),
					RouteOverrides: []*configv1.HttpRouteOverride{{
						Hosts:    []string{"api.example.com"},
						Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(4 * time.Second)},
					}},
				},
			},
			ConnectRateLimit: &configv1.LocalRateLimitSettings{TokenBucket: &configv1.TokenBucket{
				MaxTokens:     20,
				TokensPerFill: 5,
				FillInterval:  durationpb.New(time.Second),
			}},
		}),
		GlobalExtProc: &configv1.ExtProcProvider{
			Service:          "epe.agentio-system.svc",
			Port:             9002,
			MessageTimeout:   "350ms",
			FailureModeAllow: true,
		},
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	for _, name := range []string{MainInternal, MainForward, PassthroughCluster, BlackHoleCluster,
		HTTPDynamicForwardProxy, TLSConnectOriginate, ExtProcCluster} {
		cluster := clusters[name]
		if cluster == nil {
			t.Errorf("cluster %q not found", name)
			continue
		}
		if err := cluster.ValidateAll(); err != nil {
			t.Errorf("cluster %q invalid: %v", name, err)
		}
	}
	httpDFP := &dfpclusterv3.ClusterConfig{}
	if err := clusters[HTTPDynamicForwardProxy].GetClusterType().GetTypedConfig().UnmarshalTo(httpDFP); err != nil {
		t.Fatalf("unmarshal HTTP DFP cluster: %v", err)
	}
	if httpDFP.GetDnsCacheConfig().GetName() != DNSCacheName {
		t.Fatalf("HTTP DFP cache = %q", httpDFP.GetDnsCacheConfig().GetName())
	}
	for name, cluster := range clusters {
		if _, found := cluster.GetTypedExtensionProtocolOptions()["type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]; found {
			t.Fatalf("cluster %s uses an Any type URL as protocol-options map key", name)
		}
	}

	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	for _, name := range []string{ConnectTerminate, MainInternal, MainForward} {
		listener := listeners[name]
		if listener == nil {
			t.Errorf("listener %q not found", name)
			continue
		}
		if err := listener.ValidateAll(); err != nil {
			t.Errorf("listener %q invalid: %v", name, err)
		}
	}
	tlsChain := findFilterChain(t, listeners[MainInternal], tlsTerminateChain)
	if got, want := networkFilterNames(tlsChain), []string{
		"envoy.filters.network.set_filter_state",
		"agentio.connect_downstream_peer",
		"envoy.filters.network.tcp_proxy",
	}; !equalStrings(got, want) {
		t.Fatalf("TLS termination filter order = %v, want %v", got, want)
	}
	connectHCM := findHCM(t, listeners[ConnectTerminate])
	if connectHCM.GetRds().GetRouteConfigName() != ConnectTerminate {
		t.Fatalf("connect RDS name = %q", connectHCM.GetRds().GetRouteConfigName())
	}
	if got, want := httpFilterNames(connectHCM), []string{
		"agentio.connect_authority",
		"envoy.filters.http.ext_proc",
		"agentio.connect_workload",
		"agentio.connect_sni_policy",
		"envoy.filters.http.local_ratelimit",
		"envoy.filters.http.router",
	}; !equalStrings(got, want) {
		t.Fatalf("CONNECT filter order = %v, want %v", got, want)
	}
	if !hasHTTPFilter(connectHCM, "envoy.filters.http.local_ratelimit") {
		t.Error("CONNECT local rate-limit filter not found")
	}
	forwardHCM := findHCM(t, listeners[MainForward])
	if hasHTTPFilter(forwardHCM, staticEndpointCandidateFilter) {
		t.Fatalf("main_forward without service entries gained static endpoint filter: %v", httpFilterNames(forwardHCM))
	}
	if !hasHTTPFilter(forwardHCM, "envoy.filters.http.rbac") ||
		!hasHTTPFilter(forwardHCM, "envoy.filters.http.ext_proc") ||
		!hasHTTPFilter(forwardHCM, "envoy.filters.http.dynamic_forward_proxy") {
		t.Fatalf("main_forward filters = %v", httpFilterNames(forwardHCM))
	}
	for _, filter := range forwardHCM.GetHttpFilters() {
		if filter.GetName() == "envoy.filters.http.ext_proc" {
			cfg := &extprocv3.ExternalProcessor{}
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetGrpcService().GetEnvoyGrpc().GetClusterName() != ExtProcCluster ||
				cfg.GetMessageTimeout().AsDuration() != 350*time.Millisecond {
				t.Fatalf("ext_proc config = %+v", cfg)
			}
		}
		if filter.GetName() == "envoy.filters.http.dynamic_forward_proxy" {
			cfg := &dfphttpv3.FilterConfig{}
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetDnsCacheConfig().GetName() != DNSCacheName {
				t.Fatalf("HTTP filter DFP cache = %q", cfg.GetDnsCacheConfig().GetName())
			}
			if !cfg.GetAllowDynamicHostFromFilterState() {
				t.Fatal("HTTP filter DFP must accept explicit target state by default")
			}
		}
	}

	routes := messagesOf(
		t,
		resources,
		model.RouteType,
		func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} },
	)
	for _, name := range []string{ConnectTerminate, HTTPDynamicForwardProxy, TLSConnectOriginate} {
		if routes[name] == nil {
			t.Errorf("route %q not found", name)
			continue
		}
		if err := routes[name].ValidateAll(); err != nil {
			t.Errorf("route %q invalid: %v", name, err)
		}
	}
	tlsRoute := routes[TLSConnectOriginate]
	if len(tlsRoute.GetVirtualHosts()) != 2 || tlsRoute.GetVirtualHosts()[0].GetDomains()[0] != "api.example.com" {
		t.Fatalf("TLS route virtual hosts = %+v", tlsRoute.GetVirtualHosts())
	}
	if got := tlsRoute.GetVirtualHosts()[0].GetRoutes()[1].GetRoute().GetTimeout().AsDuration(); got != 4*time.Second {
		t.Fatalf("route override timeout = %s", got)
	}

	for _, resource := range resources {
		if resource.XDSName == "" {
			t.Errorf("resource %s has no wire name", resource.Key.Name)
		}
		if resource.Key.Name == resource.XDSName {
			t.Errorf("resource %s is not gateway-scoped internally", resource.Key.Name)
		}
		if resource.Facts.GatewayOwner != "agentio-system/egress" {
			t.Errorf("resource %s facts = %+v", resource.Key.Name, resource.Facts)
		}
	}
}

func TestBuildConnectTerminateRouteDisablesRequestTimeout(t *testing.T) {
	resources, err := Build(Inputs{
		Gateway:          testGateway(nil),
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration {
		return &routev3.RouteConfiguration{}
	})
	connect := routes[ConnectTerminate].GetVirtualHosts()[0].GetRoutes()[0].GetRoute()
	if connect.GetTimeout() == nil {
		t.Fatal("CONNECT termination route timeout is unset; Envoy's request timeout would cap the tunnel lifetime")
	}
	if got := connect.GetTimeout().AsDuration(); got != 0 {
		t.Fatalf("CONNECT termination route timeout = %s, want disabled", got)
	}
}

func TestBuildStaticEgressServiceEntriesPreserveDestinationPort(t *testing.T) {
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway: testGateway(&configv1.EgressGateway{
			ConnectionPool: &configv1.ConnectionPoolSettings{Http: &configv1.ConnectionPoolHttpSettings{
				RouteOverrides: []*configv1.HttpRouteOverride{{
					Hosts:    []string{"api.example.com", "other.example.com"},
					Settings: &configv1.HttpRouteSettings{Timeout: durationpb.New(17 * time.Second)},
				}},
			}},
			ServiceEntries: []*configv1.EgressServiceEntry{
				{
					Hosts: []string{"api.example.com"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{
						{Address: "10.10.20.30"},
						{Address: "10.10.20.31"},
					},
				},
				{
					Hosts:     []string{"single.example.com"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "10.10.20.40"}},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("Build(): %v", err)
	}

	routes := messagesOf(
		t,
		resources,
		model.RouteType,
		func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} },
	)
	for _, routeName := range []string{HTTPDynamicForwardProxy, TLSConnectOriginate} {
		routeConfig := routes[routeName]
		if got, want := len(routeConfig.GetVirtualHosts()), 4; got != want {
			t.Fatalf(
				"%s virtual hosts = %d, want two static services, remaining override, and fallback (%d)",
				routeName,
				got,
				want,
			)
		}
		apiHost := routeConfig.GetVirtualHosts()[0]
		if got, want := apiHost.GetDomains(), []string{
			"api.example.com",
			"api.example.com:*",
		}; !slices.Equal(
			got,
			want,
		) {
			t.Fatalf("%s static domains = %v, want %v", routeName, got, want)
		}
		apiRoute := apiHost.GetRoutes()[1]
		if got := apiRoute.GetRoute().GetTimeout().AsDuration(); got != 17*time.Second {
			t.Fatalf("%s static route timeout = %s, want matching override 17s", routeName, got)
		}
		weighted := apiRoute.GetRoute().GetWeightedClusters().GetClusters()
		if got, want := len(weighted), 2; got != want {
			t.Fatalf("%s static weighted endpoints = %d, want %d", routeName, got, want)
		}
		for index, wantAddress := range []string{"10.10.20.30", "10.10.20.31"} {
			entry := weighted[index]
			if entry.GetName() != routeName || entry.GetWeight().GetValue() != 1 {
				t.Fatalf(
					"%s weighted endpoint %d = name %q weight %d",
					routeName,
					index,
					entry.GetName(),
					entry.GetWeight().GetValue(),
				)
			}
			assertStaticEndpointState(t, entry.GetTypedPerFilterConfig(), wantAddress)
		}

		singleRoute := routeConfig.GetVirtualHosts()[1].GetRoutes()[1]
		if got := singleRoute.GetRoute().GetCluster(); got != routeName {
			t.Fatalf("%s single endpoint cluster = %q, want existing DFP cluster", routeName, got)
		}
		assertStaticEndpointState(t, singleRoute.GetTypedPerFilterConfig(), "10.10.20.40")

		remainingOverride := routeConfig.GetVirtualHosts()[2]
		if got, want := remainingOverride.GetDomains(), []string{"other.example.com"}; !slices.Equal(got, want) {
			t.Fatalf("%s remaining override domains = %v, want %v", routeName, got, want)
		}
		if config := remainingOverride.GetRoutes()[1].GetTypedPerFilterConfig(); len(config) != 0 {
			t.Fatalf("%s ordinary override gained static endpoint state: %v", routeName, config)
		}
		fallback := routeConfig.GetVirtualHosts()[3]
		if got := fallback.GetDomains(); !slices.Equal(got, []string{"*"}) {
			t.Fatalf("%s fallback domains = %v", routeName, got)
		}
	}

	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	for _, listenerName := range []string{MainInternal, MainForward} {
		hcm := findHCM(t, listeners[listenerName])
		filterNames := httpFilterNames(hcm)
		stateIndex := slices.Index(filterNames, staticEndpointCandidateFilter)
		dfpIndex := slices.Index(filterNames, "envoy.filters.http.dynamic_forward_proxy")
		if stateIndex < 0 || dfpIndex != stateIndex+2 || filterNames[stateIndex+1] != "agentio.route_upstream" {
			t.Fatalf(
				"%s HTTP filters = %v, want endpoint capture and target consumption before DFP",
				listenerName,
				filterNames,
			)
		}
		stateConfig := &setstatehttpv3.Config{}
		if err := hcm.GetHttpFilters()[stateIndex].GetTypedConfig().UnmarshalTo(stateConfig); err != nil {
			t.Fatalf("decode %s listener set-filter-state: %v", listenerName, err)
		}
		if got := len(stateConfig.GetOnRequestHeaders()); got != 0 {
			t.Fatalf("%s listener static state values = %d, want route-only configuration", listenerName, got)
		}
		dfpConfig := &dfphttpv3.FilterConfig{}
		if err := hcm.GetHttpFilters()[dfpIndex].GetTypedConfig().UnmarshalTo(dfpConfig); err != nil {
			t.Fatalf("decode %s DFP filter: %v", listenerName, err)
		}
		if !dfpConfig.GetAllowDynamicHostFromFilterState() {
			t.Fatalf("%s DFP filter does not allow route-selected static endpoints", listenerName)
		}
	}
}

func TestBuildGatewayFormatWithoutTelemetryInputs(t *testing.T) {
	format := "%REQ(:SCHEME)% %PROTOCOL%"
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway: testGateway(&configv1.EgressGateway{
			AccessLogFormat: &configv1.AccessLogFormat{Text: &format},
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
	logs := findHCM(t, listeners[MainForward]).GetAccessLog()
	if len(logs) != 2 {
		t.Fatalf("HTTP logs = %d, want 2", len(logs))
	}
	fileLog := &fileaccesslogv3.FileAccessLog{}
	if err := logs[1].GetTypedConfig().UnmarshalTo(fileLog); err != nil {
		t.Fatal(err)
	}
	if got := fileLog.GetLogFormat().GetTextFormatSource().GetInlineString(); got != format+"\n" {
		t.Fatalf("text format = %q", got)
	}
}

func TestBuildInstallsTelemetryOnForwardAndConnectTerminationPaths(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	resources, err := Build(Inputs{
		DiscoveryAddress:       "agentiod.agentio-system.svc:15012",
		TrustDomain:            "cluster.local",
		Gateway:                testGateway(nil),
		TelemetryRootNamespace: "agentio-system",
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

	for name, want := range map[string]string{MainInternal: "", MainForward: "https"} {
		if got := findHCM(t, listeners[name]).GetSchemeHeaderTransformation().GetSchemeToOverwrite(); got != want {
			t.Errorf("%s scheme override = %q, want %q", name, got, want)
		}
	}
	connect := findHCM(t, listeners[ConnectTerminate])
	if slices.Contains(httpFilterNames(connect), "istio.stats") {
		t.Fatalf("CONNECT Telemetry filters = %v", httpFilterNames(connect))
	}
	// CONNECT termination mirrors release-0.1 setHboneTerminationAccessLog: a
	// single access log restricted to status >= 400 responses.
	connectLogs := connect.GetAccessLog()
	if len(connectLogs) != 1 {
		t.Fatalf("CONNECT Telemetry logs = %d, want 1", len(connectLogs))
	}
	statusFilter := connectLogs[0].GetFilter().GetStatusCodeFilter()
	if statusFilter.GetComparison().GetOp() != accesslogv3.ComparisonFilter_GE ||
		statusFilter.GetComparison().GetValue().GetDefaultValue() != 400 {
		t.Fatalf("CONNECT Telemetry log filter = %v, want status >= 400", connectLogs[0].GetFilter())
	}
	for _, listenerName := range []string{MainInternal, MainForward} {
		hcm := findHCM(t, listeners[listenerName])
		filters := httpFilterNames(hcm)
		routerIndex := slices.Index(filters, "envoy.filters.http.router")
		if slices.Contains(filters, "istio.stats") || routerIndex != len(filters)-1 || len(hcm.GetAccessLog()) != 2 ||
			hcm.GetAccessLog()[0].Name != "envoy.access_loggers.dynamic_modules" {
			t.Fatalf("%s HTTP telemetry = %v", listenerName, hcm)
		}
		if listenerName == MainForward && slices.Index(filters, connectProxyTLSIdentityFilter) != routerIndex-1 {
			t.Fatal("TLS identity must precede router")
		}
	}

	for _, listenerName := range []string{MainInternal, MainForward} {
		chain := findFilterChain(t, listeners[listenerName], forwardTCPChain)
		filters := networkFilterNames(chain)
		statsIndex := slices.Index(filters, "istio.stats")
		proxyIndex := slices.Index(filters, "envoy.filters.network.tcp_proxy")
		if statsIndex >= 0 || proxyIndex != len(filters)-1 {
			t.Fatalf("%s application TCP filters = %v", listenerName, filters)
		}
		proxy := new(tcpproxyv3.TcpProxy)
		if err := chain.Filters[proxyIndex].GetTypedConfig().UnmarshalTo(proxy); err != nil {
			t.Fatal(err)
		}
		if len(proxy.GetAccessLog()) != 1 {
			t.Fatalf("%s TCP access logs = %d", listenerName, len(proxy.GetAccessLog()))
		}
	}

	tlsRelay := findFilterChain(t, listeners[MainInternal], tlsTerminateChain)
	if slices.Contains(networkFilterNames(tlsRelay), "istio.stats") {
		t.Fatalf("TLS relay filters = %v", networkFilterNames(tlsRelay))
	}
	proxy := new(tcpproxyv3.TcpProxy)
	last := tlsRelay.Filters[len(tlsRelay.Filters)-1]
	if err := last.GetTypedConfig().UnmarshalTo(proxy); err != nil {
		t.Fatal(err)
	}
	if len(proxy.GetAccessLog()) != 0 {
		t.Fatalf("TLS relay access logs = %d", len(proxy.GetAccessLog()))
	}
}

func TestBuildInstallsNoRouteListenerAccessLogs(t *testing.T) {
	filter := "response.code >= 500"
	policy, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "agentio-system",
		Name:      "listener-logs",
		Source:    "agentio-system/source",
	}, []string{"agentio-system/egress"}, nil, nil, []model.TelemetryAccessLogging{{
		Mode:      model.TelemetryModeServer,
		Providers: []string{"envoy"},
		Filter:    &filter,
	}})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := Build(Inputs{
		DiscoveryAddress:       "agentiod.agentio-system.svc:15012",
		TrustDomain:            "cluster.local",
		Gateway:                testGateway(nil),
		TelemetryRootNamespace: "agentio-system",
		Telemetry:              []model.Telemetry{policy},
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
	for _, name := range []string{ConnectTerminate, MainInternal, MainForward} {
		logs := listeners[name].GetAccessLog()
		if len(logs) != 1 {
			t.Errorf("listener %s access logs = %d, want 1", name, len(logs))
			continue
		}
		filters := logs[0].GetFilter().GetAndFilter().GetFilters()
		if len(filters) != 2 || !slices.Equal(filters[0].GetResponseFlagFilter().GetFlags(), []string{"NR"}) {
			t.Errorf("listener %s access-log filter = %v, want NR AND CEL", name, logs[0].GetFilter())
			continue
		}
		extension := filters[1].GetExtensionFilter()
		celFilter := new(celv3.ExpressionFilter)
		if extension.GetName() != "envoy.access_loggers.extension_filters.cel" ||
			extension.GetTypedConfig().UnmarshalTo(celFilter) != nil || celFilter.GetExpression() != filter {
			t.Errorf("listener %s CEL filter = %v, want %q", name, extension, filter)
		}
	}
}

func TestBuildAppliesEnvoyFilterAfterTelemetry(t *testing.T) {
	emptyAny, err := anypb.New(&emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	patch, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system",
		Name:      "telemetry-patch",
		Source:    "agentio-system/config-source",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{{
		Operation: model.PatchInsertBefore,
		Target: model.HTTPFilterPatch{
			Match: &model.ListenerMatch{
				Name: MainForward,
				FilterChain: &model.FilterChainMatch{
					Filter: &model.FilterMatch{
						Name:      "envoy.filters.network.http_connection_manager",
						SubFilter: &model.SubFilterMatch{Name: "envoy.filters.http.router"},
					},
				},
			},
			Value: &hcmv3.HttpFilter{
				Name:       "example.before-router",
				ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: emptyAny},
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := Build(Inputs{
		DiscoveryAddress:       "agentiod.agentio-system.svc:15012",
		TrustDomain:            "cluster.local",
		Gateway:                testGateway(nil),
		GatewayPatches:         []model.GatewayPatch{patch},
		TelemetryRootNamespace: "agentio-system",
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
	filters := httpFilterNames(findHCM(t, listeners[MainForward]))
	if before, stats := slices.Index(
		filters,
		"example.before-router",
	), slices.Index(
		filters,
		"envoy.filters.http.router",
	); before < 0 ||
		before+1 != stats {
		t.Fatalf("patched Telemetry filter order = %v", filters)
	}
}

func TestBuildClustersRejectsTelemetryNameCollision(t *testing.T) {
	_, err := (&resourceBuilder{}).clusters(effectiveConfig{
		gateway:   &configv1.EgressGateway{},
		telemetry: &telemetry.Output{Clusters: []*clusterv3.Cluster{{Name: MainForward}}},
	})
	if err == nil {
		t.Fatal("expected Telemetry cluster collision failure")
	}
}

func TestBuildAppliesGatewayEnvoyFilterTransactionally(t *testing.T) {
	emptyAny, err := anypb.New(&emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	filter, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system",
		Name:      "egress-patches",
		Source:    "agentio-system/config-sources",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{
		{
			Operation: model.PatchMerge,
			Target: model.ClusterPatch{
				Match: &model.ClusterMatch{Name: MainForward},
				Value: &clusterv3.Cluster{AltStatName: "envoy-filter-patched"},
			},
		},
		{
			Operation: model.PatchInsertBefore,
			Target: model.HTTPFilterPatch{
				Match: &model.ListenerMatch{
					Name: MainForward,
					FilterChain: &model.FilterChainMatch{
						Filter: &model.FilterMatch{
							Name:      "envoy.filters.network.http_connection_manager",
							SubFilter: &model.SubFilterMatch{Name: "envoy.filters.http.router"},
						},
					},
				},
				Value: &hcmv3.HttpFilter{
					Name:       "envoy.filters.http.gateway-patch",
					ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: emptyAny},
				},
			},
		},
		{
			Operation: model.PatchAdd,
			Target: model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{
				Name:        "gateway-extension",
				TypedConfig: emptyAny,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GatewayPatches:   []model.GatewayPatch{filter},
	})
	if err != nil {
		t.Fatal(err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	if got := clusters[MainForward].GetAltStatName(); got != "envoy-filter-patched" {
		t.Fatalf("patched cluster alt stat name = %q", got)
	}
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	if filters := httpFilterNames(
		findHCM(t, listeners[MainForward]),
	); !slices.Contains(
		filters,
		"envoy.filters.http.gateway-patch",
	) {
		t.Fatalf("patched HTTP filters = %v", filters)
	}
	extensions := messagesOf(
		t,
		resources,
		model.ExtensionConfigurationType,
		func() *corev3.TypedExtensionConfig { return &corev3.TypedExtensionConfig{} },
	)
	if extensions["gateway-extension"] == nil {
		t.Fatalf("extension resources = %+v", extensions)
	}
	for _, resource := range resources {
		if resource.XDSName == "gateway-extension" && resource.Facts.GatewayOwner != "agentio-system/egress" {
			t.Fatalf("extension facts = %+v", resource.Facts)
		}
	}
}

func TestBuildSupportsDeployedIPv4DynamicForwardProxyPatches(t *testing.T) {
	cache := &dfpcommonv3.DnsCacheConfig{Name: "agentio_dns_cache", DnsLookupFamily: clusterv3.Cluster_V4_ONLY}
	clusterTyped, err := anypb.New(&dfpclusterv3.ClusterConfig{
		ClusterImplementationSpecifier: &dfpclusterv3.ClusterConfig_DnsCacheConfig{DnsCacheConfig: cache},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpTyped, err := anypb.New(&dfphttpv3.FilterConfig{
		ImplementationSpecifier: &dfphttpv3.FilterConfig_DnsCacheConfig{DnsCacheConfig: cache},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system",
		Name:      "egress-gateway-dfp-ipv4-only",
		Source:    "agentio-system/config-source",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{
		{
			Operation: model.PatchMerge,
			Target: model.ClusterPatch{
				Match: &model.ClusterMatch{Name: TLSConnectOriginate},
				Value: &clusterv3.Cluster{ClusterDiscoveryType: &clusterv3.Cluster_ClusterType{
					ClusterType: &clusterv3.Cluster_CustomClusterType{
						Name:        "envoy.clusters.dynamic_forward_proxy",
						TypedConfig: clusterTyped,
					},
				}},
			},
		},
		{
			Operation: model.PatchMerge,
			Target: model.HTTPFilterPatch{
				Match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{Filter: &model.FilterMatch{
					Name:      "envoy.filters.network.http_connection_manager",
					SubFilter: &model.SubFilterMatch{Name: "envoy.filters.http.dynamic_forward_proxy"},
				}}},
				Value: &hcmv3.HttpFilter{
					Name:       "envoy.filters.http.dynamic_forward_proxy",
					ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: httpTyped},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GatewayPatches:   []model.GatewayPatch{policy},
	})
	if err != nil {
		t.Fatal(err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	gotCluster := &dfpclusterv3.ClusterConfig{}
	if err := clusters[TLSConnectOriginate].GetClusterType().GetTypedConfig().UnmarshalTo(gotCluster); err != nil {
		t.Fatal(err)
	}
	if got := gotCluster.GetDnsCacheConfig(); got.GetName() != "agentio_dns_cache" ||
		got.GetDnsLookupFamily() != clusterv3.Cluster_V4_ONLY {
		t.Fatalf("cluster DNS cache = %+v", got)
	}

	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	manager := findHCM(t, listeners[MainForward])
	var dynamicForwardProxy *hcmv3.HttpFilter
	for _, filter := range manager.GetHttpFilters() {
		if filter.GetName() == "envoy.filters.http.dynamic_forward_proxy" {
			dynamicForwardProxy = filter
			break
		}
	}
	if dynamicForwardProxy == nil {
		t.Fatal("dynamic forward proxy HTTP filter not found")
	}
	gotHTTP := &dfphttpv3.FilterConfig{}
	if err := dynamicForwardProxy.GetTypedConfig().UnmarshalTo(gotHTTP); err != nil {
		t.Fatal(err)
	}
	if got := gotHTTP.GetDnsCacheConfig(); got.GetName() != "agentio_dns_cache" ||
		got.GetDnsLookupFamily() != clusterv3.Cluster_V4_ONLY {
		t.Fatalf("HTTP DNS cache = %+v", got)
	}
}

func TestBuildSupportsDeployedSandboxConnectPatch(t *testing.T) {
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system",
		Name:      "enable-sandbox-connect",
		Source:    "agentio-system/config-source",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{{
		Operation: model.PatchInsertBefore,
		Target: model.HTTPRoutePatch{
			Match: &model.RouteConfigurationMatch{
				Name:        HTTPDynamicForwardProxy,
				VirtualHost: &model.VirtualHostMatch{Route: &model.RouteMatch{Name: "default"}},
			},
			Value: &routev3.Route{
				Name: "sandbox-connect",
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_ConnectMatcher_{
					ConnectMatcher: &routev3.RouteMatch_ConnectMatcher{},
				}},
				Action: &routev3.Route_Route{Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: PassthroughCluster},
					Timeout:          durationpb.New(0),
					UpgradeConfigs: []*routev3.RouteAction_UpgradeConfig{{
						UpgradeType:   "CONNECT",
						ConnectConfig: &routev3.RouteAction_UpgradeConfig_ConnectConfig{},
					}},
				}},
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}

	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		GatewayPatches:   []model.GatewayPatch{policy},
	})
	if err != nil {
		t.Fatal(err)
	}
	routes := messagesOf(
		t,
		resources,
		model.RouteType,
		func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} },
	)
	got := routes[HTTPDynamicForwardProxy].GetVirtualHosts()[0].GetRoutes()
	if len(got) != 3 || got[0].GetName() != "sandbox-connect" || got[1].GetName() != "sandbox-connect" ||
		got[2].GetName() != "default" {
		t.Fatalf("HTTP DFP routes = %+v", got)
	}
	if got[1].GetMatch().GetConnectMatcher() == nil || got[1].GetRoute().GetCluster() != PassthroughCluster ||
		got[1].GetRoute().GetTimeout().AsDuration() != 0 || len(got[1].GetRoute().GetUpgradeConfigs()) != 1 ||
		got[1].GetRoute().GetUpgradeConfigs()[0].GetUpgradeType() != "CONNECT" ||
		got[1].GetRoute().GetUpgradeConfigs()[0].GetConnectConfig() == nil {
		t.Fatalf("deployed sandbox CONNECT route = %+v", got[1])
	}
}

func TestGatewayExtProcOverride(t *testing.T) {
	global := &configv1.ExtProcProvider{Service: "global-ext-proc.agentio-system.svc", Port: 9002}
	override := &configv1.ExtProcProvider{Service: "gateway-ext-proc.agentio-system.svc", Port: 9003}
	for _, tt := range []struct {
		name     string
		global   *configv1.ExtProcProvider
		override *configv1.ExtProcProvider
		want     *configv1.ExtProcProvider
	}{
		{name: "unconfigured"},
		{name: "inherit", global: global, want: global},
		{name: "disable global", global: global, override: &configv1.ExtProcProvider{}},
		{name: "disable without global", override: &configv1.ExtProcProvider{}},
		// release-0.1 treats an empty service as disabled, even with other fields set.
		{name: "empty service with settings", global: global, override: &configv1.ExtProcProvider{Port: 9003, MessageTimeout: "unused"}},
		{name: "override global", global: global, override: override, want: override},
		{name: "override without global", override: override, want: override},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resources, err := Build(Inputs{
				DiscoveryAddress: "agentiod.agentio-system.svc:15012",
				TrustDomain:      "cluster.local",
				Gateway:          testGateway(&configv1.EgressGateway{ExtProc: tt.override}),
				GlobalExtProc:    tt.global,
			})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			cluster := messagesOf(t, resources, model.ClusterType,
				func() *clusterv3.Cluster { return &clusterv3.Cluster{} })[ExtProcCluster]
			if (cluster != nil) != (tt.want != nil) {
				t.Fatalf("ext_proc cluster present = %v, want %v", cluster != nil, tt.want != nil)
			}
			if tt.want != nil {
				socket := cluster.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].
					GetEndpoint().GetAddress().GetSocketAddress()
				if socket.GetAddress() != tt.want.GetService() || socket.GetPortValue() != tt.want.GetPort() {
					t.Errorf(
						"ext_proc endpoint = %s:%d, want %s:%d",
						socket.GetAddress(),
						socket.GetPortValue(),
						tt.want.GetService(),
						tt.want.GetPort(),
					)
				}
			}
			listeners := messagesOf(
				t,
				resources,
				model.ListenerType,
				func() *listenerv3.Listener { return &listenerv3.Listener{} },
			)
			for _, name := range []string{MainInternal, MainForward} {
				if got := hasHTTPFilter(
					findHCM(t, listeners[name]),
					"envoy.filters.http.ext_proc",
				); got != (tt.want != nil) {
					t.Errorf("listener %s ext_proc filter present = %v, want %v", name, got, tt.want != nil)
				}
			}
		})
	}
}

func TestBuildRejectsConflictingGateway(t *testing.T) {
	gateway := testGateway(nil)
	gateway.Source = model.GatewaySourceConflict
	_, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          gateway,
	})
	if err == nil || err.Error() != "gateway agentio-system/egress has conflicting declarations" {
		t.Fatalf("Build() error = %v", err)
	}
}

func TestBuildRejectsRelativeGatewayRootCAPath(t *testing.T) {
	test.SetForTest(t, &features.GatewayRootCAPath, "certs/root.pem")
	_, err := Build(Inputs{
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
	})
	if err == nil || err.Error() != "gateway root CA path must be absolute" {
		t.Fatalf("Build() error = %v, want gateway root CA path must be absolute", err)
	}
}

func TestSNIDenyAccessLogsHonorTelemetry(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	expression := "connection.requested_server_name != 'skip.example.com'"
	for _, tt := range []struct {
		name     string
		disabled bool
		filter   *string
		want     int
	}{
		{name: "default", want: 1},
		{name: "filtered", filter: &expression, want: 1},
		{name: "disabled", disabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var policies []model.Telemetry
			if tt.disabled || tt.filter != nil {
				policy, err := model.NewTelemetry(model.TelemetryMetadata{
					Namespace: "agentio-system", Name: "logs", Source: "agentio-system/logs",
				}, []string{"agentio-system/egress"}, nil, nil, []model.TelemetryAccessLogging{{
					Mode: model.TelemetryModeServer, Disabled: &tt.disabled, Filter: tt.filter,
				}})
				if err != nil {
					t.Fatal(err)
				}
				policies = append(policies, policy)
			}
			resources, err := Build(Inputs{
				DiscoveryAddress: "agentiod.agentio-system.svc:15012", TrustDomain: "cluster.local",
				Gateway: testGateway(nil), TelemetryRootNamespace: "agentio-system", Telemetry: policies,
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
			chain := findFilterChain(t, listeners[MainInternal], sniDenyChain)
			deny := &tcpproxyv3.TcpProxy{}
			filters := chain.GetFilters()
			if len(filters) != tt.want+1 {
				t.Fatalf("deny chain filters = %d, want %d", len(filters), tt.want+1)
			}
			if err := filters[len(filters)-1].GetTypedConfig().UnmarshalTo(deny); err != nil {
				t.Fatal(err)
			}
			if chain.GetTransportSocket() != nil || deny.GetCluster() != BlackHoleCluster {
				t.Fatal("denial must remain a raw black-hole connection")
			}
			if len(deny.GetAccessLog()) != tt.want {
				t.Fatalf("deny logs = %d, want %d", len(deny.GetAccessLog()), tt.want)
			}
			if tt.want == 0 {
				return
			}
			state := &setstatenetworkv3.Config{}
			if err := filters[0].GetTypedConfig().UnmarshalTo(state); err != nil {
				t.Fatal(err)
			}
			if err := state.ValidateAll(); err != nil {
				t.Fatal(err)
			}
			values := state.GetOnNewConnection()
			if len(values) != 1 || values[0].GetObjectKey() != telemetry.DenialReasonFilterStateKey ||
				values[0].GetFactoryKey() != "envoy.string" || !values[0].GetReadOnly() ||
				values[0].GetSharedWithUpstream() != 0 ||
				values[0].GetFormatString().GetTextFormatSource().GetInlineString() != "sni_policy_denied" {
				t.Fatalf("denial reason must be set locally before the proxy: %v", values)
			}
			fileLog := &fileaccesslogv3.FileAccessLog{}
			if err := deny.AccessLog[0].GetTypedConfig().UnmarshalTo(fileLog); err != nil {
				t.Fatal(err)
			}
			if got := fileLog.GetLogFormat().GetJsonFormat().GetFields()["denial_reason"].GetStringValue(); got != "%FILTER_STATE("+values[0].GetObjectKey()+":PLAIN)%" {
				t.Fatalf("denial log does not read the captured reason: %q", got)
			}
			if tt.filter == nil {
				if deny.AccessLog[0].GetFilter() != nil {
					t.Fatal("default deny log must not be restricted to NR")
				}
			} else {
				filter := &celv3.ExpressionFilter{}
				if err := deny.AccessLog[0].GetFilter().
					GetExtensionFilter().
					GetTypedConfig().
					UnmarshalTo(filter); err != nil {
					t.Fatal(err)
				}
				if filter.GetExpression() != expression {
					t.Fatalf("deny filter = %q, want %q", filter.GetExpression(), expression)
				}
			}
		})
	}
}

func TestSandboxHeaderFilterState(t *testing.T) {
	resources := buildCompleteGatewayGraph(t)
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	hcm := findHCM(t, listeners[ConnectTerminate])
	var states []*setstatecommonv3.FilterStateValue
	for _, filter := range hcm.GetHttpFilters() {
		if filter.GetName() != "agentio.connect_authority" {
			continue
		}
		config := &setstatehttpv3.Config{}
		if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
			t.Fatal(err)
		}
		states = config.GetOnRequestHeaders()
	}
	for key, header := range map[string]string{
		"sandbox.id":               "X-AGENTIO-SANDBOX-ID",
		"sandbox.token":            "X-AGENTIO-SANDBOX-TOKEN",
		"agentio.sandbox.metadata": "X-AGENTIO-SANDBOX-METADATA",
	} {
		index := slices.IndexFunc(
			states,
			func(state *setstatecommonv3.FilterStateValue) bool { return state.GetObjectKey() == key },
		)
		if index < 0 {
			t.Fatalf("CONNECT did not capture %s", key)
		}
		state := states[index]
		if got := state.GetFormatString().GetTextFormatSource().GetInlineString(); got != "%REQ("+header+")%" {
			t.Errorf("%s capture = %q", key, got)
		}
		if !state.GetFormatString().GetOmitEmptyValues() {
			t.Errorf("%s must preserve missing headers as empty values", key)
		}
		if state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_ONCE {
			t.Errorf("%s must be shared only with the next internal hop", key)
		}
		if state.GetFactoryKey() != "envoy.hashable_string" {
			t.Errorf("%s must distinguish upstream pools", key)
		}
		if key == "agentio.sandbox.metadata" && !state.GetSkipIfEmpty() {
			t.Error("absent metadata must not mask a legacy sandbox token")
		}
	}
}
