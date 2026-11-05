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

package trafficpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
)

func TestSetupOrder(t *testing.T) {
	fixture := trafficFixture
	t.Cleanup(func() { trafficFixture = fixture })
	digest := "registry.example/test@sha256:" + strings.Repeat("b", 64)
	setups := suiteSetupGraph(agentiocomponent.Config{
		Namespace:         "agentio-system",
		AgentiodImage:     digest,
		ZtunnelImage:      digest,
		ProxyInitImage:    digest,
		GatewayImage:      digest,
		EPEImage:          digest,
		ExtProcImage:      digest,
		ForwardProxyImage: digest,
	})
	names := make([]string, len(setups))
	for index := range setups {
		names[index] = setups[index].name
	}
	want := []string{
		"agentio", "agentio-baseline", "traffic-policy-namespace", "traffic-policy-client",
		"traffic-policy-server", "traffic-policy-another-server", "traffic-policy-workload-target",
		"fixture-readiness",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("setup order = %v, want %v", names, want)
	}
}

func TestTrafficPolicyBuilderTargetsSourceAndCIDR(t *testing.T) {
	policy := trafficPolicy("policy", "sandbox", map[string]string{"app": "client"}, "reject", "10.0.0.8/32")
	if policy.GetAPIVersion() != "agents.kruise.io/v1alpha1" || policy.GetKind() != "TrafficPolicy" {
		t.Fatalf("type metadata = %s %s", policy.GetAPIVersion(), policy.GetKind())
	}
	if policy.GetNamespace() != "sandbox" || policy.GetName() != "policy" {
		t.Fatalf("metadata = %s/%s", policy.GetNamespace(), policy.GetName())
	}
	priority, _, err := unstructured.NestedInt64(policy.Object, "spec", "priority")
	if err != nil || priority != 100 {
		t.Fatalf("priority = %d, err = %v", priority, err)
	}
	selector, _, err := unstructured.NestedStringMap(policy.Object, "spec", "selector", "matchLabels")
	if err != nil || !reflect.DeepEqual(selector, map[string]string{"app": "client"}) {
		t.Fatalf("selector = %#v, err = %v", selector, err)
	}
	rules, _, err := unstructured.NestedSlice(policy.Object, "spec", "egress", "rules")
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules = %#v, err = %v", rules, err)
	}
	rule := rules[0].(map[string]any)
	if rule["action"] != "reject" {
		t.Fatalf("action = %v", rule["action"])
	}
	peers := rule["to"].([]any)
	if peers[0].(map[string]any)["cidr"] != "10.0.0.8/32" {
		t.Fatalf("peers = %#v", peers)
	}
}

func TestDataplaneEchoConfigIsProfileNeutral(t *testing.T) {
	config := dataplaneEchoConfig("client", "sandbox")
	if config.Name != "client" || config.Namespace != "sandbox" {
		t.Fatalf("echo identity = %s/%s", config.Namespace, config.Name)
	}
	if !reflect.DeepEqual(config.Labels, map[string]string{"app": "client"}) {
		t.Fatalf("echo labels = %#v", config.Labels)
	}
	if len(config.PodAnnotations) != 0 {
		t.Fatalf("echo annotations contain dataplane enrollment: %#v", config.PodAnnotations)
	}
}

func TestTrafficPolicyKeepsNonTargetEgressAvailable(t *testing.T) {
	policy := trafficPolicy("lifecycle", "sandbox", map[string]string{"app": "client"}, "reject", "10.0.0.1/32")
	rules := policy.Object["spec"].(map[string]any)["egress"].(map[string]any)["rules"].([]any)
	wantFallback := map[string]any{
		"action": "allow",
		"to": []any{
			map[string]any{"cidr": "0.0.0.0/0"},
		},
	}
	if len(rules) != 2 || !reflect.DeepEqual(rules[1], wantFallback) {
		t.Fatalf("egress rules = %#v, want target rule followed by %#v", rules, wantFallback)
	}
}

func TestWaitForPolicyStateObservesAppearanceAndRemoval(t *testing.T) {
	tests := []struct {
		name    string
		present bool
		dumps   []string
	}{
		{
			name:    "appears",
			present: true,
			dumps:   []string{nativePolicyDump(t, false, false), nativePolicyDump(t, true, true)},
		},
		{
			name:    "disappears",
			present: false,
			dumps:   []string{nativePolicyDump(t, true, true), nativePolicyDump(t, false, true)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := waitForPolicyState(ctx, "tp-target", tc.present, func(context.Context) (string, error) {
				index := calls
				if index >= len(tc.dumps) {
					index = len(tc.dumps) - 1
				}
				calls++
				return tc.dumps[index], nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatalf("dump calls = %d, want 2", calls)
			}
		})
	}
}

func TestWaitForPolicyStateReturnsRecentDumpError(t *testing.T) {
	want := errors.New("admin unavailable")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := waitForPolicyState(ctx, "tp-target", true, func(context.Context) (string, error) {
		return "", want
	})
	if !errors.Is(err, want) {
		t.Fatalf("waitForPolicyState() error = %v", err)
	}
}

func nativePolicyDump(t *testing.T, bound, cached bool) string {
	t.Helper()
	refs := []string{}
	policies := []map[string]any{}
	if bound {
		refs = append(refs, "namespaces/test/trafficPolicies/tp-target")
	}
	if cached {
		policies = append(
			policies,
			map[string]any{
				"name":   "namespaces/test/trafficPolicies/tp-target",
				"egress": map[string]any{"rules": []any{}},
			},
		)
	}
	body, err := json.Marshal(map[string]any{
		"workload":        map[string]any{"uid": "client-uid", "namespace": "test", "trafficPolicyRefs": refs},
		"sandboxes":       []any{},
		"trafficPolicies": policies,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func legacyPolicyDump(t *testing.T, bound, cached bool) string {
	t.Helper()
	refs := []string{}
	policies := []any{}
	if bound {
		refs = append(refs, "test/tp-target-egress")
	}
	if cached {
		policies = append(
			policies,
			map[string]any{
				"namespace": "test",
				"name":      "tp-target-egress",
				"scope":     "WorkloadSelector",
				"priority":  100,
			},
		)
	}
	body, err := json.Marshal(map[string]any{
		"workload": map[string]any{"uid": "client-uid", "namespace": "test", "authorizationPolicies": refs},
		"policies": policies,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestInspectPolicyDumpRequiresBindingAndBody(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dump    string
		found   bool
		wantErr bool
	}{
		{name: "native binding and body", dump: nativePolicyDump(t, true, true), found: true},
		{name: "cached but unbound", dump: nativePolicyDump(t, false, true)},
		{name: "missing referenced body", dump: nativePolicyDump(t, true, false), wantErr: true},
		{name: "exact policy name", dump: strings.ReplaceAll(nativePolicyDump(t, true, true), "tp-target", "tp-target-extra")},
		{name: "missing native binding", dump: strings.Replace(nativePolicyDump(t, true, true), `"trafficPolicyRefs":["namespaces/test/trafficPolicies/tp-target"],`, "", 1), wantErr: true},
		{name: "legacy reference and body", dump: legacyPolicyDump(t, true, true), found: true},
		{name: "legacy unbound body", dump: legacyPolicyDump(t, false, true)},
		{name: "legacy dangling reference", dump: legacyPolicyDump(t, true, false), wantErr: true},
		{name: "legacy namespace scope", dump: strings.ReplaceAll(legacyPolicyDump(t, false, true), "WorkloadSelector", "Namespace"), found: true},
		{name: "legacy global scope", dump: strings.ReplaceAll(legacyPolicyDump(t, false, true), "WorkloadSelector", "Global"), found: true},
		{name: "invalid JSON", dump: `broken`, wantErr: true},
		{name: "missing workload", dump: `{}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inspectPolicyDump(tc.dump, "tp-target")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, want error=%v", err, tc.wantErr)
			}
			if err == nil && got.found != tc.found {
				t.Fatalf("view=%+v", got)
			}
			if got.found && got.body == "" {
				t.Fatal("policy bodies are missing")
			}
		})
	}
}

func TestWaitForPolicyStateTracksLegacyPolicyNames(t *testing.T) {
	for _, present := range []bool{true, false} {
		calls := 0
		err := waitForPolicyState(context.Background(), "tp-target", present, func(context.Context) (string, error) {
			calls++
			if calls == 1 {
				return legacyPolicyDump(t, !present, true), nil
			}
			return legacyPolicyDump(t, present, true), nil
		})
		if err != nil || calls != 2 {
			t.Fatalf("present=%v calls=%d error=%v", present, calls, err)
		}
	}
}
