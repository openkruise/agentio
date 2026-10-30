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

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestBandwidthOnlyShapesTCPConnect(t *testing.T) {
	test.SetForTest(t, &features.EnableUDPProxy, true)
	settings := new(configv1.EgressGateway)
	if err := protojson.Unmarshal([]byte(`{
      "http":{"routing":{"fallback":{"retries":{"attempts":3,"retryOn":"5xx"}}}},
      "bandwidthLimit":{
      "rateLimits":[{"actions":[{"filterState":{"key":"sandbox.id","descriptorKey":"sandbox"}}]}],
      "descriptors":[{"entries":[{"key":"sandbox"}],"bandwidthLimit":{"downloadBytesPerSecond":100}}]
    }}`), settings); err != nil {
		t.Fatal(err)
	}
	inputs := Inputs{Gateway: testGateway(settings), DiscoveryAddress: "agentiod:15012", TrustDomain: "cluster.local"}
	resources, err := Build(inputs)
	if err != nil {
		t.Fatal(err)
	}
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return new(listenerv3.Listener) },
	)
	hcm := findHCM(t, listeners[ConnectTerminate])
	if !hasHTTPFilter(hcm, bandwidthFilterName) {
		t.Fatal("TCP CONNECT has no bandwidth filter")
	}
	routes := messagesOf(t, resources, model.RouteType, func() *routev3.RouteConfiguration {
		return new(routev3.RouteConfiguration)
	})
	for _, virtualHost := range routes[ConnectTerminate].GetVirtualHosts() {
		if virtualHost.GetRetryPolicy() != nil {
			t.Fatal("CONNECT inherited a virtual-host retry policy incompatible with bandwidth shaping")
		}
		for _, route := range virtualHost.GetRoutes() {
			if route.GetRoute().GetRetryPolicy() != nil || route.GetRoute().GetRetryPolicyTypedConfig() != nil {
				t.Fatal("CONNECT inherited a retry policy incompatible with bandwidth shaping")
			}
		}
	}
	inner := routes[HTTPDynamicForwardProxy].GetVirtualHosts()[0].GetRoutes()
	if inner[len(inner)-1].GetRoute().GetRetryPolicy().GetRetryOn() != "5xx" {
		t.Fatal("bandwidth shaping changed retries on the separate inner HTTP chain")
	}
	for _, upgrade := range hcm.UpgradeConfigs {
		if upgrade.UpgradeType == connectUDPUpgradeType {
			for _, filter := range upgrade.Filters {
				if filter.Name == bandwidthFilterName {
					t.Fatal("TCP byte shaping leaked into CONNECT-UDP")
				}
			}
		}
	}
	inputs.LegacyGateway = true
	if _, err := Build(inputs); err == nil {
		t.Fatal("legacy gateway accepted unsupported bandwidth module")
	}
	inputs.LegacyGateway = false
	inputs.Gateway.Config.BandwidthLimit = nil
	resources, err = Build(inputs)
	if err != nil {
		t.Fatal(err)
	}
	listeners = messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return new(listenerv3.Listener) },
	)
	if !proto.Equal(hcm, findHCM(t, listeners[ConnectTerminate])) {
		t.Fatal("policy removal changed the listener")
	}
	if modulePolicy(networkLimitExtension(t, resources, bandwidthFilterName)).Fields["enabled"].GetBoolValue() {
		t.Fatal("removed policy still enabled")
	}
}
