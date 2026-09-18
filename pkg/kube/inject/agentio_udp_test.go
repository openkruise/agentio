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

package inject

import (
	"path/filepath"
	"slices"
	"testing"

	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"istio.io/istio/pkg/config/mesh"
	testenv "istio.io/istio/pkg/test/env"
)

// Render both template layers: Helm's injector ConfigMap and the Pod injection
// template it carries. Checking Helm alone leaves the latter unevaluated.
func TestAgentioUDPInjection(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		enabled, native, firewall, ambient bool
		cni, nft                           bool
		metadata                           map[string]string
		mode                               string
		wantError                          bool
	}{
		{name: "disabled"},
		{name: "enabled", enabled: true, firewall: true},
		{name: "without-firewall", enabled: true},
		{name: "native-sidecar", enabled: true, native: true},
		{name: "coexist-with-ambient", enabled: true, ambient: true},
		{name: "matching-metadata", enabled: true, metadata: map[string]string{"ENABLE_UDP_PROXY": "true", "PACKET_MARK": "1337"}},
		{name: "conflicting-mark", enabled: true, metadata: map[string]string{"PACKET_MARK": "1339"}, wantError: true},
		{name: "conflicting-enable", enabled: true, metadata: map[string]string{"ENABLE_UDP_PROXY": "false"}, wantError: true},
		{name: "no-capture", enabled: true, mode: "NONE", wantError: true},
		{name: "tproxy-annotation", enabled: true, mode: "TPROXY"},
		{name: "cni-capture", enabled: true, cni: true, wantError: true},
		{name: "native-nft-capture", enabled: true, nft: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chart, err := loader.Load(filepath.Join(testenv.IstioSrc, "manifests/charts/agentio"))
			if err != nil {
				t.Fatal(err)
			}
			overrides := map[string]any{
				"global":          map[string]any{"enableFirewallRules": tc.firewall},
				"sidecarInjector": map[string]any{"ztunnel": map[string]any{"udpProxy": map[string]any{"enabled": tc.enabled, "captureMark": 2001, "routeTable": 200}}},
				"ambient":         map[string]any{"enabled": tc.ambient},
			}
			values, err := chartutil.ToRenderValues(chart, overrides, chartutil.ReleaseOptions{Name: "agentio", Namespace: "agentio-system"}, chartutil.DefaultCapabilities)
			if err != nil {
				t.Fatal(err)
			}
			rendered, err := engine.Render(chart, values)
			if err != nil {
				t.Fatal(err)
			}
			var cm corev1.ConfigMap
			if err := yaml.Unmarshal([]byte(rendered["agentio/templates/injection-templates.yaml"]), &cm); err != nil {
				t.Fatal(err)
			}
			cfg, err := UnmarshalConfig([]byte(cm.Data["config"]))
			if err != nil {
				t.Fatal(err)
			}
			var injectionValues map[string]any
			if err := yaml.Unmarshal([]byte(cm.Data["values"]), &injectionValues); err != nil {
				t.Fatal(err)
			}
			injectionValues["global"].(map[string]any)["nativeNftables"] = tc.nft
			injectionValues["pilot"].(map[string]any)["cni"].(map[string]any)["enabled"] = tc.cni
			pc := mesh.DefaultProxyConfig()
			pc.ProxyMetadata = tc.metadata
			data := SidecarTemplateData{
				ObjectMeta:  metav1.ObjectMeta{Name: "app", Annotations: map[string]string{}},
				Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
				ProxyConfig: pc, MeshConfig: mesh.DefaultMeshConfig(), Values: injectionValues,
				ProxyUID: 1337, ProxyGID: 1337, NativeSidecars: tc.native,
			}
			data.DeploymentMeta.Name = "app"
			if tc.mode != "" {
				data.ObjectMeta.Annotations["sidecar.istio.io/interceptionMode"] = tc.mode
			}
			output, err := runTemplate(cfg.Templates["ztunnel"], data)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected incompatible UDP configuration to fail injection")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var pod corev1.Pod
			if err := yaml.Unmarshal(output.Bytes(), &pod); err != nil {
				t.Fatal(err)
			}
			init := FindContainer("istio-init", pod.Spec.InitContainers)
			if init == nil {
				t.Fatal("missing init container")
			}
			if got := slices.Contains(init.Args, "--enable-udp-tproxy"); got != tc.enabled {
				t.Fatalf("UDP init enabled=%v, want %v", got, tc.enabled)
			}
			proxy := FindContainer("istio-proxy", pod.Spec.Containers)
			if tc.native {
				proxy = FindContainer("istio-proxy", pod.Spec.InitContainers)
			}
			if proxy == nil {
				t.Fatal("missing proxy")
			}
			countUDP := 0
			for _, e := range proxy.Env {
				if e.Name == "ENABLE_UDP_PROXY" {
					countUDP++
					if e.Value != "true" {
						t.Fatalf("unexpected UDP value %s", e.Value)
					}
				}
			}
			if tc.enabled {
				if countUDP != 1 {
					t.Fatalf("UDP env count=%d, want 1", countUDP)
				}
				for _, arg := range []string{"REDIRECT", "--udp-proxy-port=15002", "--udp-proxy-mark=1337", "--udp-tproxy-mark=2001", "--udp-tproxy-route-table=200"} {
					if !slices.Contains(init.Args, arg) {
						t.Errorf("missing init arg %s", arg)
					}
				}
				if !slices.Contains(proxy.SecurityContext.Capabilities.Add, corev1.Capability("NET_ADMIN")) {
					t.Error("UDP proxy needs NET_ADMIN")
				}
			} else if countUDP != 0 {
				t.Error("disabled feature enabled UDP")
			}
			if tc.ambient {
				var ds struct {
					Spec struct{ Template struct{ Spec corev1.PodSpec } }
				}
				if err := yaml.Unmarshal([]byte(rendered["agentio/templates/ztunnel-daemonset.yaml"]), &ds); err != nil {
					t.Fatal(err)
				}
				if len(ds.Spec.Template.Spec.Containers) == 0 {
					t.Fatal("ambient DaemonSet was not rendered")
				}
				for _, c := range ds.Spec.Template.Spec.Containers {
					for _, e := range c.Env {
						if e.Name == "ENABLE_UDP_PROXY" {
							t.Error("sidecar UDP leaked into ambient")
						}
					}
				}
			}
		})
	}
}
