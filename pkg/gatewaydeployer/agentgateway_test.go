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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"github.com/openkruise/agentio/internal/testutil"
)

func agentgatewayFixture() (*gatewayv1.Gateway, *corev1.ConfigMap) {
	gw := egressGatewayFixture("agentgateway", "demo")
	gw.Spec.GatewayClassName = "agentio-agentgateway"
	gw.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: "", Kind: "ConfigMap", Name: "agentgateway-config"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "agentgateway-config", Namespace: "demo"}, Data: map[string]string{agentgatewayConfigKey: "binds: []\n"}}
	return gw, cm
}

func agentgatewayRenderer(t *testing.T) *renderer {
	t.Helper()
	values := testValues(t, map[string]any{"global": map[string]any{"agentgateway": map[string]any{"image": "example.com/agentgateway:tested"}}})
	r := testRenderer(t, values)
	contents := map[string]string{}
	for _, name := range []string{egressGatewayTemplateName, agentgatewayTemplateName} {
		content, err := os.ReadFile("templates/" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		contents[name] = string(content)
	}
	if err := r.updateTemplates(contents, values, defaultProxyConfig()); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAgentgatewayDeploymentUsesFileConfig(t *testing.T) {
	gw, cm := agentgatewayFixture()
	gw.Annotations = map[string]string{"gateway.agentio.kruise.io/agentgateway-certs": "gateway-certs", "gateway.istio.io/agentgatewayImage": "untrusted/image"}
	gw.Spec.Infrastructure.Labels = map[gatewayv1.LabelKey]gatewayv1.LabelValue{"agentio.kruise.io/dataplane-mode": "sidecar"}
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	d.renderer = agentgatewayRenderer(t)
	if err := d.Reconcile(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}); err != nil {
		t.Fatal(err)
	}
	p := rig.patcher.find("deployments")
	if p == nil {
		t.Fatal("no Deployment created")
	}
	var dep appsv1.Deployment
	if err := json.Unmarshal(p.data, &dep); err != nil {
		t.Fatal(err)
	}
	pod := dep.Spec.Template
	c := pod.Spec.Containers[0]
	if c.Name != "agentgateway" || c.Image != "example.com/agentgateway:tested" || strings.Join(c.Args, " ") != "-f /etc/agentgateway/config.yaml" {
		t.Fatalf("wrong container: %+v", c)
	}
	if dep.Spec.Replicas != nil || pod.Annotations["gateway.agentio.kruise.io/config-hash"] == "" {
		t.Fatalf("bad rollout configuration: %+v", pod.ObjectMeta)
	}
	if pod.Labels[dataplaneModeLabel] != "none" {
		t.Fatal("gateway was enrolled in a data plane")
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatal("file mode should not mount a Kubernetes token")
	}
	if len(dep.OwnerReferences) != 1 || dep.OwnerReferences[0].Name != gw.Name {
		t.Fatal("Gateway ownership missing")
	}
	if pod.Spec.Volumes[0].ConfigMap.Name != cm.Name || pod.Spec.Volumes[2].Secret.SecretName != "gateway-certs" || c.VolumeMounts[0].SubPath != agentgatewayConfigKey {
		t.Fatal("config or certificate mounts are wrong")
	}
	for _, e := range c.Env {
		if e.Name == "XDS_ADDRESS" || e.Name == "CA_ADDRESS" {
			t.Fatal("file mode must not connect to unsupported xDS")
		}
	}
	if rig.patcher.find("configmaps") != nil || rig.patcher.find("secrets") != nil {
		t.Fatal("deployer adopted operator-owned input")
	}
	if rig.patcher.find("services") == nil || rig.patcher.find("serviceaccounts") == nil {
		t.Fatal("missing gateway children")
	}
}

// HPA/PDB are opt-in; an empty patch enables the template defaults.
func TestAgentgatewayHPAPDB(t *testing.T) {
	gw, cm := agentgatewayFixture()
	cm.Data["horizontalPodAutoscaler"] = "{}"
	cm.Data["podDisruptionBudget"] = "{}"
	gw.Annotations = map[string]string{"gateway.agentio.kruise.io/name-override": "custom-gateway"}
	gw.Spec.Infrastructure.Labels = map[gatewayv1.LabelKey]gatewayv1.LabelValue{"team": "test"}
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	d.renderer = agentgatewayRenderer(t)
	if err := d.Reconcile(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}); err != nil {
		t.Fatal(err)
	}
	hpaPatch, pdbPatch := rig.patcher.find("horizontalpodautoscalers"), rig.patcher.find("poddisruptionbudgets")
	if hpaPatch == nil || pdbPatch == nil {
		t.Fatal("missing HPA/PDB")
	}
	var hpa autoscalingv2.HorizontalPodAutoscaler
	var pdb policyv1.PodDisruptionBudget
	if err := json.Unmarshal(hpaPatch.data, &hpa); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(pdbPatch.data, &pdb); err != nil {
		t.Fatal(err)
	}
	for _, meta := range []metav1.ObjectMeta{hpa.ObjectMeta, pdb.ObjectMeta} {
		if meta.Name != "custom-gateway" || meta.Namespace != gw.Namespace || meta.Labels["team"] != "test" || len(meta.OwnerReferences) != 1 || meta.OwnerReferences[0].UID != gw.UID {
			t.Fatalf("incorrect child metadata: %+v", meta)
		}
	}
	wantHPA := autoscalingv2.HorizontalPodAutoscalerSpec{
		ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "custom-gateway"},
		MaxReplicas:    1,
	}
	if !reflect.DeepEqual(hpa.Spec, wantHPA) {
		t.Fatalf("HPA spec = %+v, want %+v", hpa.Spec, wantHPA)
	}
	wantPDB := policyv1.PodDisruptionBudgetSpec{
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"gateway.networking.k8s.io/gateway-name": gw.Name}},
	}
	if !reflect.DeepEqual(pdb.Spec, wantPDB) {
		t.Fatalf("PDB spec = %+v, want %+v", pdb.Spec, wantPDB)
	}
}

func TestAgentgatewayInvalidConfigReportsStatusWithoutDeploying(t *testing.T) {
	for _, tc := range []string{"missing-ref", "wrong-kind", "missing-config", "other-namespace", "empty", "invalid-yaml"} {
		t.Run(tc, func(t *testing.T) {
			gw, cm := agentgatewayFixture()
			switch tc {
			case "missing-ref":
				gw.Spec.Infrastructure = nil
			case "wrong-kind":
				gw.Spec.Infrastructure.ParametersRef.Kind = "Secret"
			case "missing-config":
				gw.Spec.Infrastructure.ParametersRef.Name = "absent"
			case "other-namespace":
				cm.Namespace = "other"
			case "empty":
				cm.Data[agentgatewayConfigKey] = " "
			case "invalid-yaml":
				cm.Data[agentgatewayConfigKey] = "binds: ["
			}
			rig := newControllerTestRig(t, gw, cm)
			defer rig.close()
			d := rig.newController()
			d.renderer = agentgatewayRenderer(t)
			if err := d.Reconcile(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}); err != nil {
				t.Fatal(err)
			}
			if rig.patcher.find("deployments") != nil {
				t.Fatal("invalid input deployed")
			}
			p := rig.patcher.find("gateways")
			if p == nil || !strings.Contains(string(p.data), "InvalidParameters") || !strings.Contains(string(p.data), `"status":"False"`) {
				t.Fatalf("missing failure status: %v", p)
			}
			var patched gatewayv1.Gateway
			if err := json.Unmarshal(p.data, &patched); err != nil {
				t.Fatal(err)
			}
			if patched.Name != gw.Name || patched.Namespace != gw.Namespace || patched.Annotations[ControllerVersionAnnotation] != fmt.Sprint(ControllerVersion) {
				t.Fatalf("status apply must identify the Gateway and retain its controller version: %+v", patched.ObjectMeta)
			}
		})
	}
}

func TestAgentgatewayConfigUpdatesChangeRolloutHash(t *testing.T) {
	gw, cm := agentgatewayFixture()
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	input := buildTemplateInput(*gw, builtinClasses["agentio-agentgateway"], "cluster", 132, "")
	if err := d.agentgatewayInput(&input); err != nil {
		t.Fatal(err)
	}
	first := input.AgentgatewayConfigHash
	cm.Data[agentgatewayConfigKey] = "binds: []\nconfig: {adminAddr: '127.0.0.1:15000'}\n"
	if _, err := rig.kubeClient.CoreV1().ConfigMaps(cm.Namespace).Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.WaitFor(t, time.Second, func() bool {
		return d.agentgatewayInput(&input) == nil && input.AgentgatewayConfigHash != first
	}, "updated config hash")
}

func TestGatewayTemplatesReloadAtomically(t *testing.T) {
	provider, err := newTemplateProvider(Options{}, defaultProxyConfig())
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{egressGatewayTemplateName: "kind: Service\nmetadata: {name: envoy}", agentgatewayTemplateName: "kind: Service\nmetadata: {name: agentgateway}"}
	encode := func() string {
		b, err := yaml.Marshal(injectorTemplateConfig{Templates: contents})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if err := provider.updateFromInjectorConfig(encode(), "global: {hub: good}"); err != nil {
		t.Fatal(err)
	}
	contents[egressGatewayTemplateName] = "kind: Service\nmetadata: {name: replaced}"
	contents[agentgatewayTemplateName] = "{{broken"
	if err := provider.updateFromInjectorConfig(encode(), "global: {hub: bad}"); err == nil {
		t.Fatal("malformed template accepted")
	}
	for name, want := range map[string]string{egressGatewayTemplateName: "envoy", agentgatewayTemplateName: "agentgateway"} {
		docs, err := provider.Renderer().Render(name, TemplateInput{})
		if err != nil || !strings.Contains(strings.Join(docs, ""), want) {
			t.Fatalf("lost last known template %s: %v", name, err)
		}
	}
	if nestedString(provider.currentValues(), "global", "hub") != "good" {
		t.Fatal("invalid update replaced values")
	}
	// Older injector ConfigMaps remain valid and remove the optional template.
	delete(contents, agentgatewayTemplateName)
	if err := provider.updateFromInjectorConfig(encode(), "global: {hub: old-chart}"); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Renderer().Render(agentgatewayTemplateName, TemplateInput{}); err == nil {
		t.Fatal("removed template remained active")
	}
}

func TestAgentgatewayChartTemplateMatches(t *testing.T) {
	local, err := os.ReadFile("templates/agentgateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	chart, err := os.ReadFile("../../manifests/charts/agentio/files/agentgateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(local) != string(chart) {
		t.Fatal("chart and tested agentgateway template diverged")
	}
}

func TestAgentgatewayProgrammedWaitsForNewConfig(t *testing.T) {
	replicas := int32(1)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Generation: 2},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"gateway.agentio.kruise.io/config-hash": "new"}}},
		},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1},
	}
	if !agentgatewayRolloutReady(dep, "new") {
		t.Fatal("completed rollout not ready")
	}
	if agentgatewayRolloutReady(dep, "newer") {
		t.Fatal("old config reported ready")
	}
	dep.Status.ObservedGeneration = 1
	if agentgatewayRolloutReady(dep, "new") {
		t.Fatal("unobserved deployment reported ready")
	}
	dep.Status.ObservedGeneration = 2
	dep.Status.Replicas = 2
	if agentgatewayRolloutReady(dep, "new") {
		t.Fatal("surging deployment reported ready")
	}
	dep.Status.Replicas = 1
	dep.Status.AvailableReplicas = 0
	if agentgatewayRolloutReady(dep, "new") {
		t.Fatal("unavailable deployment reported ready")
	}
}

func TestAgentgatewayNativeCABootstrap(t *testing.T) {
	for _, extraSecret := range []bool{false, true} {
		t.Run(fmt.Sprint("extra-secret-", extraSecret), func(t *testing.T) {
			gw, cm := agentgatewayFixture()
			gw.Annotations = map[string]string{"gateway.agentio.kruise.io/service-account": "gateway-identity"}
			if extraSecret {
				gw.Annotations["gateway.agentio.kruise.io/agentgateway-certs"] = "application-tls"
			}
			rig := newControllerTestRig(t, gw, cm)
			defer rig.close()
			d := rig.newController()
			values := mergeMaps(testValues(t, nil), map[string]any{"global": map[string]any{
				"agentgateway": map[string]any{"ca": map[string]any{"enabled": true}},
				"caAddress":    "agentiod.control.svc:15012", "trustBundleName": "custom-root",
				"sds": map[string]any{"token": map[string]any{"aud": "custom-ca"}},
			}})
			r, err := newRenderer(func() map[string]any { return values }, defaultProxyConfig(), "mesh.example")
			if err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile("templates/agentgateway.yaml")
			if err != nil {
				t.Fatal(err)
			}
			if err := r.update(agentgatewayTemplateName, string(content), values, defaultProxyConfig()); err != nil {
				t.Fatal(err)
			}
			d.renderer = r
			if err := d.Reconcile(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}); err != nil {
				t.Fatal(err)
			}
			patch := rig.patcher.find("deployments")
			if patch == nil {
				t.Fatal("missing Deployment")
			}
			var dep appsv1.Deployment
			if err := json.Unmarshal(patch.data, &dep); err != nil {
				t.Fatal(err)
			}
			pod := dep.Spec.Template.Spec
			if pod.ServiceAccountName != "gateway-identity" || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
				t.Fatalf("incorrect service account bootstrap: %+v", pod)
			}
			env := map[string]corev1.EnvVar{}
			for _, e := range pod.Containers[0].Env {
				env[e.Name] = e
			}
			for key, want := range map[string]string{
				"CA_ADDRESS": "https://agentiod.control.svc:15012", "TRUST_DOMAIN": "mesh.example",
				"CA_ROOT_CA": "/var/run/secrets/agentio/root-cert.pem", "CA_AUTH_TOKEN": "/var/run/secrets/tokens/agentio-token",
			} {
				if env[key].Value != want {
					t.Errorf("%s = %q, want %q", key, env[key].Value, want)
				}
			}
			for key, field := range map[string]string{"NAMESPACE": "metadata.namespace", "SERVICE_ACCOUNT": "spec.serviceAccountName"} {
				if env[key].ValueFrom == nil || env[key].ValueFrom.FieldRef == nil || env[key].ValueFrom.FieldRef.FieldPath != field {
					t.Errorf("%s must use downward API %s", key, field)
				}
			}
			if _, found := env["XDS_ADDRESS"]; found {
				t.Fatal("CA bootstrap must not enable xDS")
			}
			volumes := map[string]corev1.Volume{}
			for _, v := range pod.Volumes {
				volumes[v.Name] = v
			}
			root := volumes["agentio-ca-root"].ConfigMap
			if root == nil || root.Name != "custom-root" || len(root.Items) != 1 || root.Items[0].Key != "root-cert.pem" {
				t.Fatalf("bad root mount: %+v", root)
			}
			projection := volumes["agentio-ca-token"].Projected
			if projection == nil || len(projection.Sources) != 1 || projection.DefaultMode == nil || *projection.DefaultMode != 0440 {
				t.Fatalf("bad token projection: %+v", projection)
			}
			token := projection.Sources[0].ServiceAccountToken
			if token == nil || token.Audience != "custom-ca" || token.Path != "agentio-token" || token.ExpirationSeconds == nil || *token.ExpirationSeconds != 43200 {
				t.Fatalf("bad token: %+v", token)
			}
			mounts := map[string]corev1.VolumeMount{}
			for _, m := range pod.Containers[0].VolumeMounts {
				mounts[m.Name] = m
			}
			for key, path := range map[string]string{"agentio-ca-root": "/var/run/secrets/agentio", "agentio-ca-token": "/var/run/secrets/tokens"} {
				m := mounts[key]
				if m.MountPath != path || !m.ReadOnly || m.SubPath != "" {
					t.Errorf("%s must be a read-only directory mount: %+v", key, m)
				}
			}
			if extraSecret && (volumes["certs"].Secret == nil || volumes["certs"].Secret.SecretName != "application-tls") {
				t.Fatal("external TLS Secret must coexist with workload CA")
			}
			if rig.patcher.find("secrets") != nil || rig.patcher.find("configmaps") != nil {
				t.Fatal("CA bootstrap must not create or adopt credentials")
			}
		})
	}
}

func TestAgentgatewayCAAddress(t *testing.T) {
	for _, input := range []string{"agentiod.ns.svc:15012", "https://agentiod.ns.svc:15012/"} {
		got, err := agentgatewayCAAddress(input)
		if err != nil || got != "https://agentiod.ns.svc:15012" {
			t.Fatalf("%q: %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "http://agentiod:15012", "https://", "https://user:password@agentiod", "https://agentiod/path", "https://agentiod?token=bad", "https://agentiod#fragment"} {
		if _, err := agentgatewayCAAddress(input); err == nil {
			t.Errorf("accepted invalid CA address %q", input)
		}
	}
}
