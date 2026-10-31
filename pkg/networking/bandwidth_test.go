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
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
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
      "connectionPool":{"http":{"defaultRoute":{"retries":{"attempts":3,"retryOn":"5xx"}}}},
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

func TestNetworkLimitsRouteGates(t *testing.T) {
	test.SetForTest(t, &features.EnableUDPProxy, true)
	settings := new(configv1.EgressGateway)
	if err := protojson.Unmarshal([]byte(`{
 "bandwidthLimit":{
 "rateLimits":[{"actions":[{"filterState":{"key":"sandbox.id","descriptorKey":"sandbox"}}]}],
 "descriptors":[{"entries":[{"key":"sandbox"}],"bandwidthLimit":{"downloadBytesPerSecond":100}}]},
 "connectConcurrencyLimit":{
 "rateLimits":[{"actions":[{"filterState":{"key":"sandbox.id","descriptorKey":"sandbox"}}]}],
 "descriptors":[{"entries":[{"key":"sandbox"}],"maxConcurrentStreams":2}]}
 }`), settings); err != nil {
		t.Fatal(err)
	}
	var initial *hcmv3.HttpConnectionManager
	for _, tc := range []struct {
		name        string
		bandwidth   bool
		concurrency bool
	}{{"off", false, false}, {"bandwidth", true, false}, {"concurrency", false, true}, {"both", true, true}, {"off-again", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := proto.Clone(settings).(*configv1.EgressGateway)
			if !tc.bandwidth {
				gateway.BandwidthLimit = nil
			}
			if !tc.concurrency {
				gateway.ConnectConcurrencyLimit = nil
			}
			resources, err := Build(
				Inputs{Gateway: testGateway(gateway), DiscoveryAddress: "agentiod:15012", TrustDomain: "cluster.local"},
			)
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
			if initial == nil {
				initial = hcm
			} else if !proto.Equal(initial, hcm) {
				t.Fatal("enabling limits changed HCM and would drain existing HTTP/2 connections")
			}
			routes := messagesOf(
				t,
				resources,
				model.RouteType,
				func() *routev3.RouteConfiguration { return new(routev3.RouteConfiguration) },
			)
			for name, enabled := range map[string]bool{bandwidthFilterName: tc.bandwidth, concurrencyFilterName: tc.concurrency} {
				found := false
				for _, filter := range hcm.HttpFilters {
					if filter.Name == name {
						found = true
						if !filter.Disabled || filter.GetConfigDiscovery() == nil {
							t.Fatalf("%s needs a default-disabled ECDS slot", name)
						}
					}
				}
				if !found ||
					modulePolicy(networkLimitExtension(t, resources, name)).Fields["enabled"].GetBoolValue() != enabled {
					t.Fatalf("%s slot/policy disagrees with setting", name)
				}
				for _, routeConfig := range routes {
					for _, host := range routeConfig.VirtualHosts {
						for _, route := range host.Routes {
							config := route.TypedPerFilterConfig[name]
							want := enabled && routeConfig.Name == ConnectTerminate &&
								route.GetRoute().GetCluster() == MainInternal
							if (config != nil) != want {
								t.Fatalf(
									"%s gate on %s route: got %v, want %v",
									name,
									routeConfig.Name,
									config != nil,
									want,
								)
							}
							if config != nil {
								wrapper := new(routev3.FilterConfig)
								if err := config.UnmarshalTo(wrapper); err != nil {
									t.Fatal(err)
								}
								if wrapper.Disabled || wrapper.Config == nil || wrapper.Config.TypeUrl != "" {
									t.Fatalf(
										"%s needs a present empty config to enable without a module per-route API",
										name,
									)
								}
							}
						}
					}
				}
			}
		})
	}
}
