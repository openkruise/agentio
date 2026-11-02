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

package kubernetes

import (
	"os"
	"strconv"
	"strings"
	"testing"

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func TestBandwidthConfigWatchAndGeneratedListener(t *testing.T) {
	data, err := os.ReadFile("../../../manifests/examples/gateway-bandwidth-config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-config", Namespace: "agentio-system"},
		Data:       map[string]string{"config": string(data)},
	}
	r := newTestRegistry(t, t.Context(), []runtime.Object{cm}, nil)
	for _, rate := range []uint64{10485760, 20971520} {
		rateText := strconv.FormatUint(rate, 10)
		if rate != 10485760 {
			cm = cm.DeepCopy()
			cm.Data["config"] = strings.ReplaceAll(cm.Data["config"], "10485760", rateText)
			cm.Data["config"] = strings.ReplaceAll(cm.Data["config"], "1048576", strconv.FormatUint(rate/10, 10))
			if _, err := r.client.CoreV1().
				ConfigMaps(cm.Namespace).
				Update(t.Context(), cm, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		var gateway *model.Gateway
		eventually(t, func() bool {
			gateway = r.Gateways.GetKey("agentio-system/agentio-egress")
			return gateway != nil &&
				gateway.Config.GetBandwidthLimit().GetDescriptors()[0].GetBandwidthLimit().
					GetUploadBytesPerSecond() ==
					rate && gateway.Config.GetBandwidthLimit().GetDescriptors()[0].GetBandwidthLimit().GetUploadBurstBytes() == rate/10
		}, "bandwidth ConfigMap update")
		resources, err := networking.Build(networking.Inputs{
			Gateway:          *gateway,
			DiscoveryAddress: "agentiod.agentio-system.svc:15012",
			TrustDomain:      "cluster.local",
		})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, resource := range resources {
			if resource.Key.TypeURL != model.ListenerType || resource.XDSName != networking.ConnectTerminate {
				continue
			}
			listener := new(listenerv3.Listener)
			if err := resource.Value.UnmarshalTo(listener); err != nil {
				t.Fatal(err)
			}
			hcm := new(hcmv3.HttpConnectionManager)
			if err := listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
				t.Fatal(err)
			}
			for i, filter := range hcm.HttpFilters {
				if filter.Name != "agentio.bandwidth" {
					continue
				}
				found = true
				if hcm.HttpFilters[i-1].Name != "agentio.connect_concurrency" ||
					hcm.HttpFilters[i+1].Name != "envoy.filters.http.router" {
					t.Fatalf("bandwidth must follow concurrency limiting and precede router: %v", hcm.HttpFilters)
				}
				typed := new(udpatypev1.TypedStruct)
				if filter.GetConfigDiscovery() == nil {
					t.Fatal("expected ECDS filter")
				}
				if err := networkLimitExtension(
					t,
					resources,
					filter.Name,
				).GetTypedConfig().
					UnmarshalTo(typed); err != nil {
					t.Fatal(err)
				}
				config := typed.Value.Fields["filter_config"].GetStructValue().Fields["value"].GetStructValue()
				if config.Fields["budget_name"].GetStringValue() != "agentio/agentio-system/agentio-egress/bandwidth" {
					t.Fatalf("unstable budget identity: %v", config)
				}
				limit := config.Fields["descriptors"].GetListValue().Values[0].GetStructValue().Fields["bandwidth_limit"].GetStructValue()
				if limit.Fields["upload_bytes_per_second"].GetStringValue() != rateText {
					t.Fatalf("updated ProtoJSON byte rate missing: %v", limit)
				}
				if limit.Fields["upload_burst_bytes"].GetStringValue() != strconv.FormatUint(rate/10, 10) ||
					limit.Fields["download_burst_bytes"].GetStringValue() != "5242880" {
					t.Fatalf("updated ProtoJSON burst capacity missing: %v", limit)
				}
			}
		}
		if !found {
			t.Fatal("bandwidth filter missing from generated CONNECT listener")
		}
	}
}

func TestBandwidthValidationAtBothConfigEntrypoints(t *testing.T) {
	valid := `bandwidthLimit:
  rateLimits:
  - actions:
    - filterState: {key: sandbox.id, descriptorKey: sandbox}
    - genericKey: {descriptorKey: class, descriptorValue: default}
  descriptors:
  - entries: [{key: sandbox}, {key: class, value: default}]
    bandwidthLimit: {uploadBytesPerSecond: 100}
`
	for _, tc := range []struct {
		name    string
		content string
		valid   bool
	}{
		{"valid", valid, true},
		{"burst", strings.Replace(valid, "uploadBytesPerSecond: 100", "uploadBytesPerSecond: 100, uploadBurstBytes: 500", 1), true},
		{"zero burst", strings.Replace(valid, "uploadBytesPerSecond: 100", "uploadBytesPerSecond: 100, uploadBurstBytes: 0", 1), false},
		{"negative burst", strings.Replace(valid, "uploadBytesPerSecond: 100", "uploadBytesPerSecond: 100, uploadBurstBytes: -1", 1), false},
		{"burst without upload", strings.Replace(valid, "uploadBytesPerSecond: 100", "downloadBytesPerSecond: 100, uploadBurstBytes: 500", 1), false},
		{"burst without download", strings.Replace(valid, "uploadBytesPerSecond: 100", "uploadBytesPerSecond: 100, downloadBurstBytes: 500", 1), false},
		{"zero rate", strings.Replace(valid, "uploadBytesPerSecond: 100", "uploadBytesPerSecond: 0", 1), false},
		{"missing rate", strings.Replace(valid, "{uploadBytesPerSecond: 100}", "{}", 1), false},
		{"empty source", strings.Replace(valid, "key: sandbox.id", `key: ""`, 1), false},
		{"wrong order", strings.Replace(valid, "[{key: sandbox}, {key: class, value: default}]", "[{key: class, value: default}, {key: sandbox}]", 1), false},
		{"two sources", strings.Replace(valid, "    - genericKey:", "      genericKey:", 1), false},
		{"zero capacity", valid + "  maxDynamicBuckets: 0\n", false},
		{"zero watermark", valid + "  bufferLimitBytes: 0\n", false},
		{"unknown field", valid + "  budgetName: custom\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeEgressGateway(tc.content)
			if (err == nil) != tc.valid {
				t.Fatalf("Gateway parameters error = %v", err)
			}
			_, err = applyAgentioConfig(
				"egressGateways:\n- name: egress\n  namespace: agentio-system\n  "+strings.ReplaceAll(
					strings.TrimSuffix(tc.content, "\n"),
					"\n",
					"\n  ",
				),
				nil,
			)
			if (err == nil) != tc.valid {
				t.Fatalf("AgentioConfig error = %v", err)
			}
		})
	}
}

func networkLimitExtension(t *testing.T, resources []model.Resource, name string) *corev3.TypedExtensionConfig {
	t.Helper()
	for _, resource := range resources {
		if resource.Key.TypeURL == model.ExtensionConfigurationType && resource.XDSName == name {
			extension := new(corev3.TypedExtensionConfig)
			if err := resource.Value.UnmarshalTo(extension); err != nil {
				t.Fatal(err)
			}
			return extension
		}
	}
	t.Fatalf("missing ECDS resource %s", name)
	return nil
}
