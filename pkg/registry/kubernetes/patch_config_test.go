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
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/model"
)

const validPatchConfig = `targetGateways: [demo/egress]
patches:
- target: cluster
  operation: MERGE
  match: {name: http_dynamic_forward_proxy}
  value: {connect_timeout: 3s}
`

func patchConfigMap(content string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "patches", ResourceVersion: "1",
			CreationTimestamp: metav1.NewTime(time.Unix(123, 0)),
			Labels:            map[string]string{ManifestTypeConfigMapLabel: GatewayPatchManifestType}},
		Data: map[string]string{KubePatchDataKey: content},
	}
}

func TestPatchConfigTargetsAndMetadata(t *testing.T) {
	cm := patchConfigMap(strings.Replace(validPatchConfig, "[demo/egress]", "[other/egress, demo/egress, demo/egress]", 1))
	cm.Data[KubePatchDataKey] += "priority: -10\n"
	patches, err := decodeGatewayPatches(cm)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 1 {
		t.Fatalf("patches = %#v", patches)
	}
	p := patches[0]
	if p.Namespace != cm.Namespace || p.Name != cm.Name || p.Source != "agentio-system/patches" ||
		p.ResourceVersion != "1" || !p.CreationTime.IsZero() || p.Priority != -10 {
		t.Fatalf("metadata = %#v", p)
	}
	if !slices.Equal(p.TargetGateways, []string{"demo/egress", "other/egress"}) {
		t.Fatalf("targets = %v", p.TargetGateways)
	}
	cluster := p.Patches[0].Target.(model.ClusterPatch)
	if cluster.Value.GetConnectTimeout().AsDuration() != 3*time.Second {
		t.Fatalf("cluster = %v", cluster.Value)
	}
	if patches, err := decodeGatewayPatches(nil); err != nil || len(patches) != 0 {
		t.Fatalf("nil input = %v, %v", patches, err)
	}
	cm.Labels = nil
	if patches, err := decodeGatewayPatches(cm); err != nil || len(patches) != 0 {
		t.Fatalf("unselected input = %v, %v", patches, err)
	}
}

func TestPatchConfigProtoJSON(t *testing.T) {
	cm := patchConfigMap(`targetGateways: [demo/egress]
patches:
- target: networkFilter
  operation: MERGE
  match:
    name: main_internal
    filterChain:
      filter: {name: envoy.filters.network.http_connection_manager}
  value:
    name: envoy.filters.network.http_connection_manager
    typed_config:
      '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
      stream_idle_timeout: 300s
`)
	patches, err := decodeGatewayPatches(cm)
	if err != nil {
		t.Fatal(err)
	}
	filter := patches[0].Patches[0].Target.(model.NetworkFilterPatch)
	hcm := &hcmv3.HttpConnectionManager{}
	if err := filter.Value.GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatal(err)
	}
	if hcm.GetStreamIdleTimeout().AsDuration() != 5*time.Minute || filter.Match.Name != "main_internal" {
		t.Fatalf("filter = %#v, hcm = %v", filter, hcm)
	}
	cm.Data[KubePatchDataKey] = strings.ReplaceAll(cm.Data[KubePatchDataKey], "stream_idle_timeout", "streamIdleTimeout")
	if _, err := decodeGatewayPatches(cm); err != nil {
		t.Fatalf("camelCase ProtoJSON: %v", err)
	}
	cm.Data[KubePatchDataKey] = strings.ReplaceAll(cm.Data[KubePatchDataKey], "streamIdleTimeout", "unknown_timeout")
	if _, err := decodeGatewayPatches(cm); err == nil || !strings.Contains(err.Error(), "unknown_timeout") {
		t.Fatalf("unknown nested field: %v", err)
	}
}

func TestPatchConfigRejectsMalformedInput(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(validPatchConfig, old, new, 1) }
	for _, tc := range []struct{ name, input, want string }{
		{"null", "null", "expected one YAML object"},
		{"array", "[]", "expected one YAML object"},
		{"extra document", validPatchConfig + "---\n{}\n", "one YAML document"},
		{"empty trailing document", validPatchConfig + "---\n", "one YAML document"},
		{"unknown field", replace("targetGateways:", "targetGateway:"), "unknown field"},
		{"wrong field case", replace("targetGateways:", "TargetGateways:"), "unknown field"},
		{"case alias cannot overwrite targets", validPatchConfig + "TargetGateways: [other/egress]\n", "unknown field"},
		{"resource envelope", "kind: GatewayPatch\nspec: {}", "unknown field"},
		{"duplicate field", validPatchConfig + "targetGateways: [other/egress]\n", "already defined"},
		{"nested duplicate", replace("connect_timeout: 3s", "connect_timeout: 3s, connect_timeout: 4s"), "already defined"},
		{"duplicate JSON", `{"targetGateways":[],"targetGateways":["demo/egress"],"patches":[]}`, "already defined"},
		{"empty targets", replace("[demo/egress]", "[]"), "at least one target"},
		{"missing namespace", replace("demo/egress", "egress"), "targetGateways[0]"},
		{"extra slash", replace("demo/egress", "demo/egress/extra"), "targetGateways[0]"},
		{"invalid namespace", replace("demo/egress", "Demo/egress"), "targetGateways[0]"},
		{"wildcard target", replace("demo/egress", "demo/*"), "targetGateways[0]"},
		{"empty patches", "targetGateways: [demo/egress]\npatches: []", "at least one patch"},
		{"unknown target", replace("target: cluster", "target: invalid"), "unknown target"},
		{"unknown operation", replace("operation: MERGE", "operation: merge"), "operation"},
		{"numeric operation", replace("operation: MERGE", "operation: 2"), "cannot unmarshal"},
		{"priority overflow", validPatchConfig + "priority: 2147483648\n", "cannot unmarshal"},
		{"null value", replace("{connect_timeout: 3s}", "null"), "requires an object"},
		{"array value", replace("{connect_timeout: 3s}", "[]"), "requires an object"},
		{"missing value", replace("  value: {connect_timeout: 3s}\n", ""), "requires an object"},
		{"remove value", replace("operation: MERGE", "operation: REMOVE"), "REMOVE must omit value"},
		{"null match", replace("{name: http_dynamic_forward_proxy}", "null"), "expected an object"},
		{"unknown match", replace("{name: http_dynamic_forward_proxy}", "{service: example.com}"), "unknown field"},
		{"wrong match family", replace("{name: http_dynamic_forward_proxy}", "{filterChain: {}}"), "unknown field"},
		{"unknown protobuf field", replace("connect_timeout", "connect_timout"), "unknown field"},
		{"bad duration", replace("connect_timeout: 3s", "connect_timeout: three"), "Duration"},
		{"unknown Any", replace("connect_timeout: 3s", "typed_extension_protocol_options: {test: {'@type': type.googleapis.com/unknown.Config}}"), "unable to resolve"},
		{"cluster add match", replace("operation: MERGE", "operation: ADD"), "must omit match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeGatewayPatches(patchConfigMap(tc.input))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "data.patches") {
				t.Fatalf("error = %v, want data.patches and %q", err, tc.want)
			}
		})
	}
	for _, content := range []string{"", " \n\t"} {
		got, err := decodeGatewayPatches(patchConfigMap(content))
		if err != nil || len(got) != 0 {
			t.Fatalf("empty source = %v, %v", got, err)
		}
	}
	if _, err := decodeGatewayPatches(patchConfigMap("# comment\n---\n" + validPatchConfig)); err != nil {
		t.Fatal(err)
	}
}

func TestPatchTargetOperationMatrix(t *testing.T) {
	all := "ADD MERGE REMOVE REPLACE INSERT_BEFORE INSERT_AFTER INSERT_FIRST"
	targets := map[string]string{
		"cluster": "ADD MERGE REMOVE", "listener": "ADD MERGE REMOVE", "filterChain": "ADD MERGE REMOVE",
		"listenerFilter": all, "networkFilter": all, "httpFilter": all,
		"routeConfiguration": "MERGE", "virtualHost": "ADD MERGE REMOVE REPLACE",
		"httpRoute": "ADD MERGE REMOVE INSERT_BEFORE INSERT_AFTER INSERT_FIRST", "extensionConfiguration": "ADD",
	}
	for target, supported := range targets {
		for _, operation := range strings.Fields(all) {
			t.Run(target+"/"+operation, func(t *testing.T) {
				input := patchEntry{Target: target, Operation: operation, Match: matrixMatch(target, operation)}
				if operation != "REMOVE" {
					input.Value = json.RawMessage(`{}`)
				}
				raw, err := json.Marshal(patchConfig{TargetGateways: []string{"demo/egress"}, Patches: []patchEntry{input}})
				if err != nil {
					t.Fatal(err)
				}
				result, err := decodeGatewayPatches(patchConfigMap(string(raw)))
				wantOK := slices.Contains(strings.Fields(supported), operation)
				if (err == nil) != wantOK {
					t.Fatalf("accepted = %v, want %v; err = %v", err == nil, wantOK, err)
				}
				if wantOK && result[0].Patches[0].Operation != patchOperations[operation] {
					t.Fatalf("wrong operation: %#v", result)
				}
			})
		}
	}
}

func matrixMatch(target, operation string) json.RawMessage {
	if operation == "ADD" || operation == "INSERT_FIRST" {
		return nil
	}
	switch target {
	case "listenerFilter":
		return json.RawMessage(`{"listenerFilter":"test"}`)
	case "networkFilter":
		return json.RawMessage(`{"filterChain":{"filter":{"name":"test"}}}`)
	case "httpFilter":
		return json.RawMessage(`{"filterChain":{"filter":{"name":"envoy.filters.network.http_connection_manager","subFilter":{"name":"test"}}}}`)
	case "httpRoute":
		return json.RawMessage(`{"virtualHost":{"route":{"name":"test","action":"ROUTE"}}}`)
	default:
		return nil
	}
}

func TestPatchRejectsUnusedMatchesAndMissingAnchors(t *testing.T) {
	for _, tc := range []struct{ target, operation, match, want string }{
		{"listener", "MERGE", `{"filterChain":{}}`, "filterChain"},
		{"listener", "MERGE", `{"listenerFilter":"test"}`, "listenerFilter"},
		{"listener", "MERGE", `{"portNumber":65536}`, "portNumber"},
		{"listener", "ADD", `{}`, "omit match"},
		{"listenerFilter", "MERGE", `{}`, "named listenerFilter"},
		{"listenerFilter", "ADD", `{"listenerFilter":"test"}`, "unused"},
		{"listenerFilter", "MERGE", `{"filterChain":{}}`, "unused"},
		{"filterChain", "ADD", `{"filterChain":{}}`, "unused"},
		{"filterChain", "MERGE", `{"filterChain":{"filter":{"name":"test"}}}`, "unused"},
		{"filterChain", "MERGE", `{"filterChain":{"destinationPort":65536}}`, "destinationPort"},
		{"networkFilter", "REMOVE", `{}`, "named filter"},
		{"networkFilter", "REPLACE", `{}`, "named filter"},
		{"networkFilter", "MERGE", `{"filterChain":{"filter":{}}}`, "filter.name"},
		{"networkFilter", "MERGE", `{"filterChain":{"filter":{"name":"test","subFilter":{"name":"child"}}}}`, "unused"},
		{"httpFilter", "INSERT_BEFORE", `{}`, "named filter"},
		{"httpFilter", "INSERT_AFTER", `{}`, "named filter"},
		{"httpFilter", "MERGE", `{"filterChain":{"filter":{"name":"tcp"}}}`, "http_connection_manager"},
		{"httpFilter", "MERGE", `{"filterChain":{"filter":{"name":"envoy.filters.network.http_connection_manager","subFilter":{}}}}`, "name is required"},
		{"routeConfiguration", "MERGE", `{"virtualHost":{}}`, "unused"},
		{"routeConfiguration", "MERGE", `{"portName":"http"}`, "unknown field"},
		{"virtualHost", "ADD", `{"virtualHost":{}}`, "unused"},
		{"virtualHost", "MERGE", `{"virtualHost":{"route":{}}}`, "unused"},
		{"httpRoute", "ADD", `{"virtualHost":{"route":{}}}`, "unused"},
		{"httpRoute", "INSERT_FIRST", `{"virtualHost":{"route":{}}}`, "unused"},
		{"httpRoute", "INSERT_BEFORE", `{}`, "route.name"},
		{"httpRoute", "INSERT_AFTER", `{"virtualHost":{"route":{"action":"ROUTE"}}}`, "route.name"},
		{"httpRoute", "MERGE", `{"virtualHost":{"route":{"action":"BOGUS"}}}`, "unknown action"},
		{"extensionConfiguration", "ADD", `{}`, "omit match"},
	} {
		t.Run(fmt.Sprintf("%s/%s/%s", tc.target, tc.operation, tc.match), func(t *testing.T) {
			input := patchEntry{Target: tc.target, Operation: tc.operation, Match: json.RawMessage(tc.match)}
			if tc.operation != "REMOVE" {
				input.Value = json.RawMessage(`{}`)
			}
			_, err := decodePatch(input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPatchRemoveHasNoProtobufValue(t *testing.T) {
	input := strings.Replace(validPatchConfig, "MERGE", "REMOVE", 1)
	input = strings.Replace(input, "  value: {connect_timeout: 3s}\n", "", 1)
	patches, err := decodeGatewayPatches(patchConfigMap(input))
	if err != nil {
		t.Fatal(err)
	}
	if patches[0].Patches[0].Target.(model.ClusterPatch).Value != (*clusterv3.Cluster)(nil) {
		t.Fatal("REMOVE acquired an empty protobuf value")
	}
}
