// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

func managerChart(t *testing.T, source string) string {
	t.Helper()
	target := t.TempDir()
	writeTestFile(t, target, "Chart.yaml", "apiVersion: v2\nname: sandbox-manager\nversion: 1.0.0\n")
	writeTestFile(t, target, "values.yaml", "global: {hub: parent.invalid}\n")
	// Helm named templates are global; parent names must not affect Agentio.
	writeTestFile(t, target, "templates/_helpers.tpl", `{{- define "gateway.image" -}}parent.invalid/proxy{{- end -}}
{{- define "epe.fullname" -}}parent-epe{{- end -}}
`)
	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestManagerMasterModesAndConfiguration(t *testing.T) {
	target := managerChart(t, repositoryAgentioChart(t))
	for _, gateway := range []string{"disabled", "static", "gatewayAPI"} {
		for _, epe := range []string{"disabled", "managed", "external"} {
			t.Run(gateway+"/"+epe, func(t *testing.T) {
				values := map[string]any{"agentio": map[string]any{
					"enabled": true,
					"global":  map[string]any{"namespace": "custom-agentio", "clusterDomain": "cluster.example"},
					"agentiod": map[string]any{
						"logging": map[string]any{"format": "json"},
						"config": map[string]any{
							"values": map[string]any{"sandboxIgnoredLabels": []string{"custom-label"}},
						},
					},
					"egressGateway": map[string]any{"mode": gateway, "gatewayAPI": map[string]any{"create": true}},
					"epe": map[string]any{
						"mode":                 epe,
						"enableXDSEgressAuthz": epe == "managed",
						"external":             map[string]any{"address": "epe.external", "port": 9443},
					},
				}}
				rendered := renderChart(t, target, values)
				all := ""
				deployments, gateways := 0, 0
				objects := map[string]bool{}
				for _, content := range rendered {
					all += content
					for _, doc := range strings.Split(content, "\n---") {
						var obj struct {
							APIVersion, Kind string
							Metadata         struct{ Name, Namespace string }
						}
						if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
							t.Fatal(err)
						}
						if obj.Kind == "" {
							continue
						}
						key := fmt.Sprintf("%s/%s/%s/%s", obj.APIVersion, obj.Kind, obj.Metadata.Namespace, obj.Metadata.Name)
						if objects[key] {
							t.Fatalf("duplicate resource %s", key)
						}
						objects[key] = true
						switch obj.Kind {
						case "Deployment":
							deployments++
						case "Gateway":
							gateways++
						case "DaemonSet", "MutatingWebhookConfiguration":
							t.Fatalf("unexpected %s", obj.Kind)
						}
					}
				}
				wantDeployments := 1
				if gateway == "static" {
					wantDeployments++
				}
				if epe == "managed" {
					wantDeployments++
				}
				if deployments != wantDeployments {
					t.Fatalf("deployments = %d, want %d", deployments, wantDeployments)
				}
				if (gateways == 1) != (gateway == "gatewayAPI") {
					t.Fatalf("gateways = %d for mode %s", gateways, gateway)
				}
				for _, want := range []string{"--namespace=custom-agentio", "--domain=cluster.example", "custom-label", "AGENTIO_LOG_FORMAT", "AGENTIO_ENABLE_SIDECAR_INJECTOR"} {
					if !strings.Contains(all, want) {
						t.Errorf("rendered manager missing %s", want)
					}
				}
				for _, bad := range []string{"parent.invalid", "parent-epe", "agentgateway", "mutatingwebhookconfigurations", "15017", "AGENTIO_NATIVE_SIDECARS", "AGENTIO_INJECTOR_CONFIGMAP_NAME", "egress-gateway: |", "sidecar-injector"} {
					if strings.Contains(all, bad) {
						t.Errorf("rendered manager contains %s", bad)
					}
				}

				if epe == "managed" {
					for _, required := range []string{
						"principal: spiffe://cluster.local/ns/custom-agentio/sa/agentio-epe",
						"--xds-address=agentiod.custom-agentio.svc.cluster.example:15012",
						"--enable-xds-egressauthz",
					} {
						if !strings.Contains(all, required) {
							t.Fatalf("missing EPE xDS integration %q", required)
						}
					}
				}
				if epe == "managed" && !strings.Contains(all, "agentio-epe.custom-agentio.svc.cluster.example") {
					t.Error("managed EPE uses the wrong namespace or domain")
				}
				if epe == "external" && !strings.Contains(all, "epe.external") {
					t.Error("external EPE is missing")
				}

			})
		}
	}
}

func TestControllerUsesMasterBootstrapOverrides(t *testing.T) {
	source := filepath.Join(t.TempDir(), "agentio")
	copyTestTree(t, repositoryAgentioChart(t), source)
	content := readTestFile(t, source, "values.yaml")
	var values map[string]any
	if err := yaml.Unmarshal([]byte(content), &values); err != nil {
		t.Fatal(err)
	}
	global := values["global"].(map[string]any)
	global["clusterId"], global["clusterDomain"], global["imagePullPolicy"] = "test-cluster", "example.internal", "Always"
	agentiod := values["agentiod"].(map[string]any)
	agentiod["fullnameOverride"], agentiod["tokenAudience"] = "custom-agentiod", "custom-ca"
	agentiod["ca"].(map[string]any)["trustBundleConfigMapName"] = "custom-root"
	injector := agentiod["injector"].(map[string]any)
	injector["ztunnel"].(map[string]any)["enableFirewallRules"] = false
	injector["ztunnel"].(map[string]any)["firewallBackend"] = "nftables"
	encoded, err := yaml.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, "values.yaml", string(encoded))
	bundle := filepath.Join(t.TempDir(), "openkruise")
	if err := BuildIntegrationBundle(source, bundle); err != nil {
		t.Fatal(err)
	}
	target := newSandboxControllerChart(t)
	if err := ExportSandboxController(filepath.Join(bundle, "sandbox-controller"), target); err != nil {
		t.Fatal(err)
	}
	cm := renderSandboxInjectionConfig(t, target)
	var config struct {
		InitContainers []corev1.Container
		Volumes        []corev1.Volume `json:"volume"`
		Labels         map[string]string
	}
	if err := json.Unmarshal([]byte(cm.Data["traffic-proxy"]), &config); err != nil {
		t.Fatal(err)
	}
	proxy := config.InitContainers[1]
	for name, want := range map[string]string{
		"AGENTIO_SANDBOX_MODE":  "true",
		"CA_ADDRESS":            "custom-agentiod.sandbox-system.svc.example.internal:15012",
		"XDS_ADDRESS":           "custom-agentiod.sandbox-system.svc.example.internal:15012",
		"ISTIO_META_CLUSTER_ID": "test-cluster", "ENABLE_FIREWALL_RULES": "false", "FIREWALL_BACKEND": "nftables",
	} {
		if got := envValue(proxy.Env, name); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	if proxy.ImagePullPolicy != corev1.PullAlways {
		t.Errorf("pull policy = %s", proxy.ImagePullPolicy)
	}
	if !hasConfigMapVolume(config.Volumes, "custom-root") {
		t.Error("custom trust bundle was not mounted")
	}
	foundToken := false
	for _, volume := range config.Volumes {
		if volume.Projected == nil {
			continue
		}
		for _, source := range volume.Projected.Sources {
			if source.ServiceAccountToken != nil {
				foundToken = true
				if source.ServiceAccountToken.Audience != "custom-ca" {
					t.Error("token audience does not match Agentiod")
				}
			}
		}
	}
	if !foundToken {
		t.Fatal("no bound service account token")
	}
	for _, key := range []string{"networking.istio.io/tunnel", "security.istio.io/tlsMode", "networking.agents.kruise.io/proxy-type"} {
		if _, found := config.Labels[key]; found {
			t.Errorf("runtime template retains legacy label %s", key)
		}
	}
	workloadPod := &corev1.Pod{Spec: corev1.PodSpec{InitContainers: config.InitContainers}}
	workloadPod.Labels = config.Labels
	workload := podsource.BaseWorkloadFromPod("test-cluster", workloadPod)
	if workload.TunnelProtocol != model.TunnelProtocolHBONE || !workload.NativeTunnel {
		t.Fatalf("Kruise runtime is not recognized as native HBONE: protocol=%s native=%t", workload.TunnelProtocol, workload.NativeTunnel)
	}
	if config.Labels["agentio.kruise.io/dataplane-mode"] != "none" {
		t.Error("Sandbox must opt out of duplicate admission/CNI injection")
	}
}

func TestReleasePackageContainsPinnedIntegrationBundle(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	source := filepath.Join(t.TempDir(), "agentio")
	copyTestTree(t, repositoryAgentioChart(t), source)
	digest := "sha256:" + strings.Repeat("b", 64)
	images := []string{}
	for _, component := range []string{"agentiod", "agentio-epe", "ztunnel", "install-cni", "proxy-init", "agentio-gateway", "agentio-porter"} {
		images = append(images, "registry.example/"+component+"@"+digest)
	}
	args := append([]string{source, "1.2.3"}, images...)
	if output, err := exec.Command("../prepare-release-chart.sh", args...).CombinedOutput(); err != nil {
		t.Fatalf("prepare chart: %v\n%s", err, output)
	}
	packageDir := t.TempDir()
	if output, err := exec.Command("helm", "package", source, "--destination", packageDir).CombinedOutput(); err != nil {
		t.Fatalf("package chart: %v\n%s", err, output)
	}
	unpacked := t.TempDir()
	if output, err := exec.Command("tar", "-xzf", filepath.Join(packageDir, "agentio-1.2.3.tgz"), "-C", unpacked).CombinedOutput(); err != nil {
		t.Fatalf("unpack chart: %v\n%s", err, output)
	}
	bundle := filepath.Join(unpacked, "agentio", "integrations", "openkruise")
	if err := VerifyIntegrationBundle(bundle); err != nil {
		t.Fatal(err)
	}
	manager := t.TempDir()
	writeTestFile(t, manager, "Chart.yaml", "apiVersion: v2\nname: sandbox-manager\nversion: 1.0.0\n")
	writeTestFile(t, manager, "values.yaml", "{}\n")
	if err := Export(filepath.Join(bundle, "sandbox-manager"), manager); err != nil {
		t.Fatal(err)
	}
	rendered := renderChart(t, manager, map[string]any{"agentio": map[string]any{"enabled": true, "egressGateway": map[string]any{"mode": "static"}, "epe": map[string]any{"mode": "managed"}}})
	all := ""
	for _, content := range rendered {
		all += content
	}
	for _, image := range []string{images[0], images[1], images[5]} {
		if !strings.Contains(all, image) {
			t.Errorf("packaged manager lost immutable image %s", image)
		}
	}
	controller := newSandboxControllerChart(t)
	if err := ExportSandboxController(filepath.Join(bundle, "sandbox-controller"), controller); err != nil {
		t.Fatal(err)
	}
	cm := renderSandboxInjectionConfig(t, controller)
	for _, image := range []string{images[2], images[4]} {
		if !strings.Contains(cm.Data["traffic-proxy"], image) {
			t.Errorf("packaged controller lost immutable image %s", image)
		}
	}
	if strings.Contains(all+cm.Data["traffic-proxy"], ":latest") {
		t.Error("packaged integration retains mutable latest images")
	}
	// Exporting from an actual Helm package must be repeatable.
	before := readTestTree(t, manager)
	if err := Export(filepath.Join(bundle, "sandbox-manager"), manager); err != nil {
		t.Fatal(err)
	}
	if readTestTree(t, manager) != before {
		t.Error("package export is not idempotent")
	}
}

func TestNamespaceRewritePreservesLiteralsAndRootContext(t *testing.T) {
	input := `{{ .Release.Namespace }} {{ $.Release.Namespace }} {{ printf ".Release.Namespace" }} {{/* .Release.Namespace */}}`
	got, err := rewriteTemplate([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want := `{{ (include "agentio.namespace" .) }} {{ (include "agentio.namespace" $) }} {{ printf ".Release.Namespace" }} {{/* .Release.Namespace */}}`
	if string(got) != want {
		t.Fatalf("namespace rewrite = %s, want %s", got, want)
	}
}

func TestManagerBundleOmitsAgentgateway(t *testing.T) {
	target := managerChart(t, repositoryAgentioChart(t))
	if strings.Contains(readTestTree(t, target), "agentgateway") {
		t.Fatal("Kruise manager bundle must omit agentgateway values, configuration, and template files")
	}
}

func TestManagerDefaultsDisableInjectionAndGatewayDeployer(t *testing.T) {
	target := managerChart(t, repositoryAgentioChart(t))
	var values map[string]any
	if err := yaml.Unmarshal([]byte(readTestFile(t, target, "values.yaml")), &values); err != nil {
		t.Fatal(err)
	}
	agentio := values["agentio"].(map[string]any)
	agentiod := agentio["agentiod"].(map[string]any)
	if _, ok := agentiod["injector"]; ok {
		t.Fatal("manager exposes injector configuration")
	}
	rendered := renderChart(t, target, map[string]any{"agentio": map[string]any{"enabled": true}})
	for _, content := range rendered {
		for _, doc := range strings.Split(content, "\n---") {
			var object struct {
				Kind string
				Spec struct{ Template struct{ Spec corev1.PodSpec } }
			}
			if err := yaml.Unmarshal([]byte(doc), &object); err != nil {
				t.Fatal(err)
			}
			if object.Kind != "Deployment" {
				continue
			}
			for _, container := range object.Spec.Template.Spec.Containers {
				if container.Name != "discovery" {
					continue
				}
				for _, name := range []string{"AGENTIO_ENABLE_SIDECAR_INJECTOR", "AGENTIO_ENABLE_CLIENT_TRUST_DISTRIBUTOR", "AGENTIO_ENABLE_GATEWAY_DEPLOYER"} {
					if got := envValue(container.Env, name); got != "false" {
						t.Errorf("%s = %q, want false", name, got)
					}
				}
				return
			}
		}
	}
	t.Fatal("missing Agentiod deployment")
}
