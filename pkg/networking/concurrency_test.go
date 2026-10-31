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

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestConcurrencyIndependentTCPAdmission(t *testing.T) {
	test.SetForTest(t, &features.EnableUDPProxy, true)
	settings := new(configv1.EgressGateway)
	if err := protojson.Unmarshal([]byte(`{
 "connectRateLimit":{"tokenBucket":{"maxTokens":10,"fillInterval":"1s"}},
 "connectConcurrencyLimit":{
 "rateLimits":[{"actions":[{"filterState":{"key":"sandbox.id","descriptorKey":"sandbox"}}]}],
 "descriptors":[{"entries":[{"key":"sandbox"}],"maxConcurrentStreams":2}]}
 }`), settings); err != nil {
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
	found := false
	for i, filter := range hcm.HttpFilters {
		if filter.Name != concurrencyFilterName {
			continue
		}
		found = true
		if hcm.HttpFilters[i-1].Name != "envoy.filters.http.local_ratelimit" ||
			hcm.HttpFilters[i+1].Name != bandwidthFilterName {
			t.Fatal(hcm.HttpFilters)
		}
		if filter.GetConfigDiscovery() == nil {
			t.Fatal("expected ECDS")
		}
		typed := networkLimitExtension(t, resources, filter.Name)
		if typed.Value.Fields["filter_name"].GetStringValue() != "envoy_agentio_connect_concurrency" {
			t.Fatal(typed)
		}
		if typed.Value.Fields["dynamic_module_config"].GetStructValue().Fields["name"].GetStringValue() != "envoy_agentio_network_limits" {
			t.Fatal(typed)
		}
	}
	if !found ||
		modulePolicy(networkLimitExtension(t, resources, bandwidthFilterName)).Fields["enabled"].GetBoolValue() {
		t.Fatal("concurrency must work without bandwidth")
	}
	for _, upgrade := range hcm.UpgradeConfigs {
		if upgrade.UpgradeType == connectUDPUpgradeType {
			for _, filter := range upgrade.Filters {
				if filter.Name == concurrencyFilterName {
					t.Fatal("TCP admission leaked into UDP")
				}
			}
		}
	}
	inputs.LegacyGateway = true
	if _, err := Build(inputs); err == nil {
		t.Fatal("legacy gateway accepted concurrency module")
	}
	inputs.LegacyGateway = false
	inputs.Gateway.Config.ConnectConcurrencyLimit = nil
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
	if modulePolicy(networkLimitExtension(t, resources, concurrencyFilterName)).Fields["enabled"].GetBoolValue() {
		t.Fatal("removed policy still enabled")
	}
}

func networkLimitExtension(t *testing.T, resources []model.Resource, name string) *udpatypev1.TypedStruct {
	t.Helper()
	extensions := messagesOf(
		t,
		resources,
		model.ExtensionConfigurationType,
		func() *corev3.TypedExtensionConfig { return new(corev3.TypedExtensionConfig) },
	)
	typed := new(udpatypev1.TypedStruct)
	if extensions[name] == nil {
		t.Fatalf("missing ECDS resource %s", name)
	}
	if err := extensions[name].TypedConfig.UnmarshalTo(typed); err != nil {
		t.Fatal(err)
	}
	return typed
}
func modulePolicy(typed *udpatypev1.TypedStruct) *structpb.Struct {
	return typed.Value.Fields["filter_config"].GetStructValue().Fields["value"].GetStructValue()
}
