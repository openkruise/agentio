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

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func buildUDPGateway(t *testing.T, enabled bool) (
	map[string]*clusterv3.Cluster,
	map[string]*listenerv3.Listener,
	map[string]*routev3.RouteConfiguration,
) {
	t.Helper()
	test.SetForTest(t, &features.EnableUDPProxy, enabled)
	resources, err := Build(Inputs{
		Gateway:          testGateway(nil),
		GlobalExtProc:    &configv1.ExtProcProvider{Service: "epe.demo.svc", Port: 9002},
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	clusters := messagesOf(t, resources, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
	listeners := messagesOf(t, resources, model.ListenerType, func() *listenerv3.Listener {
		return &listenerv3.Listener{}
	})
	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration {
		return &routev3.RouteConfiguration{}
	})
	return clusters, listeners, routes
}

func TestUDPProxyDisabledByDefault(t *testing.T) {
	clusters, listeners, routes := buildUDPGateway(t, false)
	if clusters[UDPPassthroughCluster] != nil {
		t.Fatal("UDP cluster must not exist without udp_proxy")
	}
	for _, upgrade := range findHCM(t, listeners[ConnectTerminate]).GetUpgradeConfigs() {
		if upgrade.GetUpgradeType() == connectUDPUpgradeType {
			t.Fatal("connect-udp upgrade must not exist without udp_proxy")
		}
	}
	if got := len(routes[ConnectTerminate].GetVirtualHosts()[0].GetRoutes()); got != 1 {
		t.Fatalf("connect routes = %d, want 1", got)
	}
}

func TestUDPProxyGraph(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	clusters, listeners, routes := buildUDPGateway(t, true)

	udp := clusters[UDPPassthroughCluster]
	if udp == nil {
		t.Fatal("UDP cluster not found")
	}
	if udp.GetType() != clusterv3.Cluster_ORIGINAL_DST || udp.GetLbPolicy() != clusterv3.Cluster_CLUSTER_PROVIDED {
		t.Fatalf("UDP cluster type/lb = %v/%v", udp.GetType(), udp.GetLbPolicy())
	}
	if len(udp.GetTypedExtensionProtocolOptions()) != 0 || udp.GetTransportSocket() != nil {
		t.Fatalf("UDP cluster must stay free of HTTP protocol options and TLS: %v", udp)
	}

	hcm := findHCM(t, listeners[ConnectTerminate])
	if !hasHTTPFilter(hcm, "envoy.filters.http.ext_proc") {
		t.Fatalf("TCP CONNECT chain must resolve identity with Porter: %v", httpFilterNames(hcm))
	}
	var upgrade *hcmv3.HttpConnectionManager_UpgradeConfig
	for _, candidate := range hcm.GetUpgradeConfigs() {
		if candidate.GetUpgradeType() == connectUDPUpgradeType {
			upgrade = candidate
		}
	}
	if upgrade == nil {
		t.Fatalf("connect-udp upgrade not found in %v", hcm.GetUpgradeConfigs())
	}
	names := make([]string, 0, len(upgrade.GetFilters()))
	for _, filter := range upgrade.GetFilters() {
		names = append(names, filter.GetName())
	}
	// Resolve identity once at tunnel establishment; do not transfer TCP SNI policy.
	want := []string{
		"agentio.connect_authority",
		"agentio.egress_authorization",
		"envoy.filters.http.ext_proc",
		"agentio.connect_workload",
		"agentio.udp_target",
		"agentio.udp_target_state",
		"envoy.filters.http.router",
	}
	if !equalStrings(names, want) {
		t.Fatalf("connect-udp filters = %v, want %v", names, want)
	}
	state := &setstatehttpv3.Config{}
	if err := upgrade.GetFilters()[len(upgrade.GetFilters())-2].GetTypedConfig().UnmarshalTo(state); err != nil {
		t.Fatalf("decode udp target state: %v", err)
	}
	values := state.GetOnRequestHeaders()
	if len(values) != 1 || values[0].GetObjectKey() != originalDstAddressKey ||
		values[0].GetFormatString().GetTextFormatSource().GetInlineString() != "%REQ(:AUTHORITY)%" {
		t.Fatalf("udp target state = %v", values)
	}

	connect := routes[ConnectTerminate].GetVirtualHosts()[0].GetRoutes()
	if len(connect) != 2 {
		t.Fatalf("connect routes = %d, want udp before tcp", len(connect))
	}
	udpRoute := connect[0]
	if udpRoute.GetMatch().GetConnectMatcher() == nil || len(udpRoute.GetMatch().GetHeaders()) != 1 ||
		udpRoute.GetMatch().GetHeaders()[0].GetName() != "upgrade" ||
		udpRoute.GetMatch().GetHeaders()[0].GetExactMatch() != connectUDPUpgradeType {
		t.Fatalf("UDP route match = %v", udpRoute.GetMatch())
	}
	action := udpRoute.GetRoute()
	if action.GetCluster() != UDPPassthroughCluster {
		t.Fatalf("UDP route cluster = %q", action.GetCluster())
	}
	if len(action.GetUpgradeConfigs()) != 1 ||
		action.GetUpgradeConfigs()[0].GetUpgradeType() != connectUDPUpgradeType ||
		action.GetUpgradeConfigs()[0].GetConnectConfig() == nil {
		t.Fatalf("UDP route must terminate connect-udp: %v", action.GetUpgradeConfigs())
	}
	if connect[1].GetRoute().GetCluster() != MainInternal {
		t.Fatalf("TCP CONNECT route cluster = %q", connect[1].GetRoute().GetCluster())
	}
}

func TestLegacyUDPIdentityChainPreserved(t *testing.T) {
	test.SetForTest(t, &features.EnableUDPProxy, true)
	listeners := messagesOf(
		t,
		buildGatewayGraph(t, true),
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	for _, upgrade := range findHCM(t, listeners[ConnectTerminate]).GetUpgradeConfigs() {
		if upgrade.GetUpgradeType() != connectUDPUpgradeType {
			continue
		}
		var names []string
		for _, filter := range upgrade.GetFilters() {
			names = append(names, filter.GetName())
		}
		want := []string{
			"waypoint_downstream_peer_metadata",
			"connect_authority",
			"envoy.filters.http.local_ratelimit",
			"agentio.udp_target",
			"agentio.udp_target_state",
			"envoy.filters.http.router",
		}
		if !equalStrings(names, want) {
			t.Fatalf("legacy UDP filters=%v, want %v", names, want)
		}
		return
	}
	t.Fatal("missing legacy CONNECT-UDP upgrade")
}
