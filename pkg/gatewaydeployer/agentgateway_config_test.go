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

package gatewaydeployer

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

func agentgatewaySettings(t *testing.T, text string) *configv1.EgressGateway {
	t.Helper()
	data, err := yaml.YAMLToJSONStrict([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	value := &configv1.EgressGateway{}
	if err := protojson.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
	return value
}

func generatedAgentgatewayRenderer(t *testing.T) *renderer {
	t.Helper()
	r := agentgatewayRenderer(t)
	current := r.state.Load()
	values := mergeMaps(current.values, map[string]any{
		"global": map[string]any{
			"caAddress": "https://agentiod.agentio-system.svc:15012",
			"agentgateway": map[string]any{
				"ca":           map[string]any{"enabled": true},
				"agentioImage": "example.com/agentio-agentgateway:tested",
			},
		},
	})
	content, err := os.ReadFile("templates/agentgateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.updateTemplates(
		map[string]string{agentgatewayTemplateName: string(content)},
		values,
		current.proxyConfig,
	); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAgentgatewayGeneratedEgressConfig(t *testing.T) {
	gw, cm := agentgatewayFixture()
	cm.Data = map[string]string{
		"config": "serviceEntries: [{hosts: [api.example], endpoints: [{address: 192.0.2.10}]}]",
	}
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	d.renderer = generatedAgentgatewayRenderer(t)
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	patch := rig.patcher.find("configmaps")
	if patch == nil {
		t.Fatal("no generated native ConfigMap")
	}
	var output corev1.ConfigMap
	if err := json.Unmarshal(patch.data, &output); err != nil {
		t.Fatal(err)
	}
	if output.Name == cm.Name || output.Name != "agentgateway-native" || len(output.OwnerReferences) != 1 ||
		output.OwnerReferences[0].UID != gw.UID {
		t.Fatalf("output must be separate from input and owned by the Gateway: %+v", output.ObjectMeta)
	}
	if !strings.Contains(output.Data[agentgatewayConfigKey], "192.0.2.10") {
		t.Fatal("generated configuration lost the static endpoint")
	}
	deployment := rig.patcher.find("deployments")
	if deployment == nil {
		t.Fatal("no Deployment")
	}
	var dep appsv1.Deployment
	if err := json.Unmarshal(deployment.data, &dep); err != nil {
		t.Fatal(err)
	}
	if dep.Spec.Template.Spec.Volumes[0].ConfigMap.Name != output.Name ||
		dep.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath != "/etc/agentgateway" ||
		dep.Spec.Template.Spec.Containers[0].VolumeMounts[0].SubPath != "" {
		t.Fatal("Deployment does not mount the generated directory for native file watching")
	}
	if dep.Spec.Template.Annotations["gateway.agentio.kruise.io/config-hash"] == "" {
		t.Fatal("configuration updates must trigger a rollout")
	}
	if _, found := cm.Data[agentgatewayConfigKey]; found {
		t.Fatal("operator-owned input was modified")
	}
}

func TestAgentgatewayGeneratedConfigWithNameOverride(t *testing.T) {
	gw, cm := agentgatewayFixture()
	gw.Annotations = map[string]string{nameOverrideAnnotation: "custom-gateway"}
	cm.Data = map[string]string{"config": "{}"}
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	d.renderer = generatedAgentgatewayRenderer(t)
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	patch := rig.patcher.find("configmaps")
	if patch == nil || patch.name != "custom-gateway-native" || rig.patcher.find("deployments") == nil {
		t.Fatalf("name override did not produce a matching native config and Deployment: %+v", patch)
	}
}

func TestAgentgatewayGeneratedRoutePrecedence(t *testing.T) {
	settings := agentgatewaySettings(t, `
http:
  routing:
    fallback: {timeout: 4s}
    hostOverrides:
    - hosts: ["*"]
      settings: {timeout: 3s}
    - hosts: ["*.example"]
      settings: {timeout: 2s}
    - hosts: [a.example]
      settings: {timeout: 1s}
serviceEntries:
- hosts: [a.example, b.example, c.other]
  endpoints: [{address: 192.0.2.10}]
`)
	routes, err := agentgatewayHTTPRoutes(settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1s", "2s", "3s", "2s", "1s", "3s"}
	if len(routes) != len(want) {
		t.Fatalf("got %d routes, want %d", len(routes), len(want))
	}
	for i, value := range routes {
		route := value.(map[string]any)
		got := route["policies"].(map[string]any)["timeout"].(map[string]any)["requestTimeout"]
		if got != want[i] {
			t.Errorf("route %d timeout = %v, want %s", i, got, want[i])
		}
		if _, hasHosts := route["hostnames"]; !hasHosts && i != len(routes)-1 {
			t.Errorf("route %d shadows the final catch-all", i)
		}
	}
}

func TestAgentgatewayGeneratedConfigRejectsUnsupportedSettings(t *testing.T) {
	for _, settings := range []string{
		"tlsTermination: {includeHosts: [api.example]}",
		"bandwidthLimit: {}",
		"connectRateLimit: {}",
		"connectConcurrencyLimit: {}",
		"tls: {origination: {minProtocolVersion: TLSV1_3}}",
		"tcp: {idleTimeout: 30s}",
		"http: {streamIdleTimeout: 30s}",
		"http: {routing: {fallback: {timeout: -1s}}}",
		"http: {routing: {fallback: {retries: {attempts: 256}}}}",
		"http: {routing: {fallback: {retries: {attempts: -1}}}}",
		"http: {routing: {fallback: {retries: {attempts: 1, retryOn: unsupported}}}}",
		"http: {routing: {hostOverrides: [{hosts: [example.*]}]}}",
		"http: {routing: {hostOverrides: [{hosts: ['*', example.*]}]}}",
		"extProc: {service: processor.example, messageTimeout: 5s}",
		"extProc: {service: processor.example, request: {headerMode: 42}}",
		"extProc: {service: processor.example, request: {attributes: [\"filter_state['unknown']\"]}}",
		"serviceEntries: [{hosts: [api.example], endpoints: [{address: invalid}]}]",
	} {
		t.Run(settings, func(t *testing.T) {
			gw, cm := agentgatewayFixture()
			cm.Data = map[string]string{"config": settings}
			rig := newControllerTestRig(t, gw, cm)
			defer rig.close()
			d := rig.newController()
			d.renderer = generatedAgentgatewayRenderer(t)
			if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
				t.Fatal(err)
			}
			if rig.patcher.find("deployments") != nil || rig.patcher.find("configmaps") != nil {
				t.Fatal("unsupported configuration changed running gateway resources")
			}
			patch := rig.patcher.find("gateways")
			if patch == nil || !strings.Contains(string(patch.data), `"status":"False"`) {
				t.Fatal("unsupported configuration did not report a Gateway error")
			}
		})
	}
}

func TestAgentgatewayGeneratedConfigInputBoundaries(t *testing.T) {
	for _, scenario := range []string{"both-formats", "empty", "unknown-field", "no-ca", "owned-input-name", "unowned-output", "no-hbone"} {
		t.Run(scenario, func(t *testing.T) {
			gw, cm := agentgatewayFixture()
			cm.Data = map[string]string{"config": "{}"}
			existing := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: gw.Namespace}}
			switch scenario {
			case "both-formats":
				cm.Data[agentgatewayConfigKey] = "binds: []"
			case "empty":
				cm.Data["config"] = ""
			case "unknown-field":
				cm.Data["config"] = "unknown: true"
			case "owned-input-name":
				cm.Name = gw.Name + "-native"
				gw.Spec.Infrastructure.ParametersRef.Name = cm.Name
			case "unowned-output":
				existing.Name = gw.Name + "-native"
			case "no-hbone":
				gw.Spec.Listeners[0].Protocol = "HTTP"
			}
			rig := newControllerTestRig(t, gw, cm, existing)
			defer rig.close()
			d := rig.newController()
			d.renderer = generatedAgentgatewayRenderer(t)
			if scenario == "no-ca" {
				d.renderer = agentgatewayRenderer(t)
			}
			if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
				t.Fatal(err)
			}
			if rig.patcher.find("deployments") != nil || rig.patcher.find("configmaps") != nil {
				t.Fatal("invalid input or ownership collision changed gateway resources")
			}
		})
	}
}
