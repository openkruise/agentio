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
package inject

import (
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/config/agentio"
	"istio.io/istio/pkg/config/mesh"
)

func TestAgentioTrafficInjection(t *testing.T) {
	raw, err := os.ReadFile("../../../manifests/charts/agentio/files/ztunnel-injection-template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	templates, err := ParseTemplates(RawTemplates{SidecarTemplateName: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
		invalid     bool
	}{
		{"legacy", map[string]string{"traffic.sidecar.istio.io/excludeOutboundPorts": "8080"}, "8080", false},
		{"agentio", map[string]string{"traffic.sidecar.agentio.kruise.io/exclude-outbound-ports": "8443"}, "8443", false},
		{"precedence", map[string]string{"traffic.sidecar.istio.io/excludeOutboundPorts": "8080", "traffic.sidecar.agentio.kruise.io/exclude-outbound-ports": "8443"}, "8443", false},
		{"empty", map[string]string{"traffic.sidecar.istio.io/excludeOutboundPorts": "8080", "traffic.sidecar.agentio.kruise.io/exclude-outbound-ports": ""}, "", false},
		{"invalid", map[string]string{"traffic.sidecar.agentio.kruise.io/exclude-outbound-ports": "bad-port"}, "", true},
	} {
		for _, mode := range []string{"sidecar", "native", "cni"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				_, values, mc := getInjectionSettings(t, nil, "")
				values.asMap["global"].(map[string]any)["proxy_ztunnel"] = map[string]any{"image": "openkruise/ztunnel:latest", "peerCaCrl": map[string]any{"enabled": false}}
				values.asMap["pilot"].(map[string]any)["cni"].(map[string]any)["enabled"] = mode == "cni"
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}, InitContainers: []corev1.Container{{Name: "app-init"}}}}
				params := InjectionParameters{nativeSidecar: mode == "native", pod: pod, templates: templates, defaultTemplate: []string{SidecarTemplateName}, meshConfig: mc, valuesConfig: values, proxyConfig: mesh.DefaultProxyConfig()}
				merged, injected, err := RunTemplate(params)
				if tc.invalid {
					if err == nil {
						t.Fatal("invalid Agentio annotation accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				initName := AgentioInitContainerName
				if mode == "cni" {
					initName = AgentioValidationContainerName
				}
				init := FindContainer(initName, merged.Spec.InitContainers)
				if init == nil {
					t.Fatal("missing agentio-init")
				}
				found := false
				for i, arg := range init.Args {
					if arg == "-o" {
						found = true
						if i+1 >= len(init.Args) || init.Args[i+1] != tc.want {
							t.Fatalf("args = %v", init.Args)
						}
					}
				}
				if !found {
					t.Fatalf("missing outbound port argument: %v", init.Args)
				}
				if err := reorderPod(merged, params); err != nil {
					t.Fatal(err)
				}
				index := len(merged.Spec.InitContainers) - 1
				if mode != "sidecar" {
					index = 0
				}
				if merged.Spec.InitContainers[index].Name != initName {
					t.Fatalf("incorrect %s init ordering: %v", mode, merged.Spec.InitContainers)
				}
				if mode == "cni" && merged.Annotations["traffic.sidecar.agentio.kruise.io/exclude-outbound-ports"] != tc.want {
					t.Fatalf("CNI annotations = %v", merged.Annotations)
				}
				applyMetadata(merged, *injected, params)
				if merged.Annotations[agentio.SidecarStatus] == "" || merged.Annotations["sidecar.istio.io/status"] != "" {
					t.Fatalf("injection status annotations = %v", merged.Annotations)
				}
				params.pod = merged
				stripped := stripPod(params)
				if len(stripped.Spec.InitContainers) != 1 || stripped.Spec.InitContainers[0].Name != "app-init" || injectionStatus(stripped) != nil {
					t.Fatalf("reinjection did not strip Agentio containers/status: %v", stripped)
				}
			})
		}
	}
}

func TestAgentioInitContainerUser(t *testing.T) {
	for _, name := range []string{AgentioInitContainerName, AgentioValidationContainerName} {
		t.Run(name, func(t *testing.T) {
			uid, gid, root := int64(2000), int64(3000), int64(0)
			original := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            ProxyContainerName,
				SecurityContext: &corev1.SecurityContext{RunAsUser: &uid, RunAsGroup: &gid},
			}}}}
			final := original.DeepCopy()
			final.Spec.InitContainers = []corev1.Container{{Name: name, Args: []string{"-u", "1337"}, SecurityContext: &corev1.SecurityContext{RunAsUser: &root}}}
			adjustInitContainerUser(final, original, mesh.DefaultProxyConfig())
			init := final.Spec.InitContainers[0]
			if init.Args[1] != "2000" {
				t.Fatalf("UID argument = %s", init.Args[1])
			}
			if name == AgentioValidationContainerName {
				if *init.SecurityContext.RunAsUser != uid || *init.SecurityContext.RunAsGroup != gid {
					t.Fatal("validation container must use the proxy UID/GID")
				}
			} else if *init.SecurityContext.RunAsUser != 0 {
				t.Fatal("traffic init container must remain root")
			}
		})
	}
}

func TestAgentioVirtualInterfaceInjection(t *testing.T) {
	raw, err := os.ReadFile("../../../manifests/charts/agentio/files/ztunnel-injection-template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	templates, err := ParseTemplates(RawTemplates{SidecarTemplateName: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
	}{
		{"legacy", map[string]string{"istio.io/reroute-virtual-interfaces": "eth1"}, "eth1"},
		{"agentio", map[string]string{"agentio.kruise.io/reroute-virtual-interfaces": "eth2"}, "eth2"},
		{"precedence", map[string]string{"istio.io/reroute-virtual-interfaces": "eth1", "agentio.kruise.io/reroute-virtual-interfaces": "eth2"}, "eth2"},
		{"empty", map[string]string{"istio.io/reroute-virtual-interfaces": "eth1", "agentio.kruise.io/reroute-virtual-interfaces": ""}, ""},
		{"kubevirt fallback", map[string]string{"traffic.sidecar.agentio.kruise.io/kubevirt-interfaces": "eth3"}, "eth3"},
		{"reroute before kubevirt", map[string]string{"traffic.sidecar.agentio.kruise.io/kubevirt-interfaces": "eth3", "agentio.kruise.io/reroute-virtual-interfaces": "eth2"}, "eth2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, values, mc := getInjectionSettings(t, nil, "")
			values.asMap["global"].(map[string]any)["proxy_ztunnel"] = map[string]any{"image": "openkruise/ztunnel:latest", "peerCaCrl": map[string]any{"enabled": false}}
			tc.annotations["status.sidecar.agentio.kruise.io/port"] = "16020"
			tc.annotations["sidecar.agentio.kruise.io/interception-mode"] = "REDIRECT"
			params := InjectionParameters{pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tc.annotations}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}, templates: templates, defaultTemplate: []string{SidecarTemplateName}, meshConfig: mc, valuesConfig: values, proxyConfig: mesh.DefaultProxyConfig()}
			merged, _, err := RunTemplate(params)
			if err != nil {
				t.Fatal(err)
			}
			init := FindContainer(AgentioInitContainerName, merged.Spec.InitContainers)
			if init == nil {
				t.Fatal("missing init container")
			}
			if init.Args[0] != "agentio-iptables" {
				t.Fatalf("command = %s", init.Args[0])
			}
			flags := map[string]string{}
			for i := 0; i+1 < len(init.Args); i++ {
				flags[init.Args[i]] = init.Args[i+1]
			}
			if value, ok := flags["-k"]; !ok || value != tc.want {
				t.Fatalf("virtual interfaces = %q, found=%v", value, ok)
			}
			if flags["-m"] != "REDIRECT" || flags["-d"] != "15090,15021,16020" {
				t.Fatalf("traffic args = %v", init.Args)
			}
		})
	}
}
