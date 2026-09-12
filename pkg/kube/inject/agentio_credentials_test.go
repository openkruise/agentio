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
	"fmt"
	"os"
	"strings"
	"testing"

	"istio.io/istio/pkg/config/mesh"
	corev1 "k8s.io/api/core/v1"
)

func TestAgentioCredentialMounts(t *testing.T) {
	raw, err := os.ReadFile("../../../manifests/charts/agentio/files/ztunnel-injection-template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	templates, err := ParseTemplates(RawTemplates{SidecarTemplateName: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	for _, native := range []bool{false, true} {
		for _, trustBundle := range []bool{false, true} {
			for _, crl := range []bool{false, true} {
				t.Run(fmt.Sprintf("native=%v/trustBundle=%v/crl=%v", native, trustBundle, crl), func(t *testing.T) {
					_, values, mc := getInjectionSettings(t, nil, "")
					values.asMap["global"].(map[string]any)["proxy_ztunnel"] = map[string]any{"image": "openkruise/ztunnel:latest", "peerCaCrl": map[string]any{"enabled": crl}}
					values.asMap["pilot"].(map[string]any)["env"] = map[string]any{"ENABLE_CLUSTER_TRUST_BUNDLE_API": trustBundle}
					pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
					merged, _, err := RunTemplate(InjectionParameters{nativeSidecar: native, pod: pod, templates: templates, defaultTemplate: []string{SidecarTemplateName}, meshConfig: mc, valuesConfig: values, proxyConfig: mesh.DefaultProxyConfig()})
					if err != nil {
						t.Fatal(err)
					}
					proxy := FindSidecar(merged)
					if proxy == nil {
						t.Fatal("missing proxy")
					}
					envs := map[string]string{}
					for _, env := range proxy.Env {
						envs[env.Name] = env.Value
					}
					for _, key := range []string{"AUTH_TOKEN", "CA_ROOT_CA", "XDS_ROOT_CA"} {
						want := "/var/run/secrets/agentio/root-cert.pem"
						if key == "AUTH_TOKEN" {
							want = "/var/run/secrets/tokens/agentio-token"
						}
						if envs[key] != want {
							t.Errorf("%s = %q, want %q", key, envs[key], want)
						}
					}
					volumes := map[string]corev1.Volume{}
					for _, volume := range merged.Spec.Volumes {
						volumes[volume.Name] = volume
					}
					mounts := map[string]string{}
					for _, mount := range proxy.VolumeMounts {
						if _, ok := volumes[mount.Name]; !ok {
							t.Fatalf("missing volume %q", mount.Name)
						}
						if strings.HasPrefix(mount.Name, "istio") || strings.Contains(mount.MountPath, "/istio") {
							t.Errorf("legacy credential mount: %v", mount)
						}
						mounts[mount.Name] = mount.MountPath
					}
					token := volumes["agentio-token"].Projected
					if token == nil || len(token.Sources) != 1 || token.Sources[0].ServiceAccountToken == nil {
						t.Fatal("missing projected token")
					}
					if mounts["agentio-token"]+"/"+token.Sources[0].ServiceAccountToken.Path != envs["AUTH_TOKEN"] {
						t.Fatal("token path does not match the projected file")
					}
					ca := volumes["agentio-ca-certs"]
					if trustBundle {
						if ca.Projected == nil || len(ca.Projected.Sources) != 1 || ca.Projected.Sources[0].ClusterTrustBundle == nil {
							t.Fatal("missing trust bundle")
						}
						if mounts[ca.Name]+"/"+ca.Projected.Sources[0].ClusterTrustBundle.Path != envs["CA_ROOT_CA"] {
							t.Fatal("CA path does not match the trust bundle file")
						}
					} else if ca.ConfigMap == nil || mounts[ca.Name]+"/root-cert.pem" != envs["CA_ROOT_CA"] {
						t.Fatal("CA path does not match the ConfigMap mount")
					}
					if crl {
						if volumes["agentio-ca-crl"].ConfigMap == nil || envs["CRL_PATH"] != mounts["agentio-ca-crl"]+"/ca-crl.pem" {
							t.Fatal("CRL path does not match its volume")
						}
					}
				})
			}
		}
	}
}
