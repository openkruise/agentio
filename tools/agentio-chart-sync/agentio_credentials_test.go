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
	"strings"
	"testing"

	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestChartCredentialMounts(t *testing.T) {
	for _, trustBundle := range []bool{false, true} {
		chart, err := loader.Load(repositoryAgentioChart(t))
		if err != nil {
			t.Fatal(err)
		}
		values, err := chartutil.ToRenderValues(chart, map[string]any{
			"global":        map[string]any{"enableClusterTrustBundle": trustBundle},
			"ambient":       map[string]any{"enabled": true},
			"egressGateway": map[string]any{"gateways": []any{map[string]any{"name": "agentio-egress"}}},
		}, chartutil.ReleaseOptions{Name: "agentio", Namespace: "agentio-system", IsInstall: true}, chartutil.DefaultCapabilities)
		if err != nil {
			t.Fatal(err)
		}
		rendered, err := engine.Render(chart, values)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for name, content := range rendered {
			if !strings.HasSuffix(name, "/templates/ztunnel-daemonset.yaml") && !strings.HasSuffix(name, "/templates/egress-gateway.yaml") && !strings.HasSuffix(name, "/templates/agentiod.yaml") {
				continue
			}
			for _, doc := range strings.Split(content, "\n---") {
				var workload struct {
					Kind string
					Spec struct{ Template corev1.PodTemplateSpec }
				}
				if err := yaml.Unmarshal([]byte(doc), &workload); err != nil {
					t.Fatal(err)
				}
				if workload.Kind != "Deployment" && workload.Kind != "DaemonSet" {
					continue
				}
				if strings.HasSuffix(name, "/templates/agentiod.yaml") {
					path := envValue(workload.Spec.Template.Spec.Containers[0].Env, "JWT_PATH")
					if path != "/var/run/secrets/tokens/agentio-token" {
						t.Fatalf("agentiod JWT_PATH = %q", path)
					}
					var projected *corev1.ProjectedVolumeSource
					for _, volume := range workload.Spec.Template.Spec.Volumes {
						if volume.Name == "agentio-token" {
							projected = volume.Projected
						}
					}
					if projected == nil || len(projected.Sources) != 1 || projected.Sources[0].ServiceAccountToken == nil || projected.Sources[0].ServiceAccountToken.Path != "agentio-token" {
						t.Fatal("agentiod projected token does not match JWT_PATH")
					}
					found++
					continue
				}
				env := "JWT_PATH"
				if workload.Kind == "DaemonSet" {
					env = "AUTH_TOKEN"
				}
				assertCredentialMounts(t, workload.Spec.Template.Spec, env)
				found++
			}
		}
		if found != 3 {
			t.Fatalf("validated %d workloads, want agentiod, gateway and ztunnel", found)
		}
	}
}

func assertCredentialMounts(t *testing.T, spec corev1.PodSpec, tokenEnv string) {
	t.Helper()
	volumes := map[string]corev1.Volume{}
	for _, volume := range spec.Volumes {
		if strings.HasPrefix(volume.Name, "istio") {
			t.Errorf("legacy volume name %q", volume.Name)
		}
		volumes[volume.Name] = volume
	}
	found := false
	containers := append(append([]corev1.Container{}, spec.Containers...), spec.InitContainers...)
	for _, container := range containers {
		if envValue(container.Env, tokenEnv) == "" {
			continue
		}
		found = true
		for _, key := range []string{tokenEnv, "CA_ROOT_CA", "XDS_ROOT_CA"} {
			path := envValue(container.Env, key)
			want := "/var/run/secrets/agentio/root-cert.pem"
			if key == tokenEnv {
				want = "/var/run/secrets/tokens/agentio-token"
			}
			if path != want {
				t.Fatalf("%s %s = %q, want %q", container.Name, key, path, want)
			}
			matched := false
			for _, mount := range container.VolumeMounts {
				if !strings.HasPrefix(path, mount.MountPath+"/") {
					continue
				}
				volume, ok := volumes[mount.Name]
				if !ok {
					t.Fatalf("missing volume %q", mount.Name)
				}
				if key == tokenEnv {
					if volume.Projected == nil {
						t.Fatal("token volume is not projected")
					}
					for _, source := range volume.Projected.Sources {
						if source.ServiceAccountToken != nil && mount.MountPath+"/"+source.ServiceAccountToken.Path == path && source.ServiceAccountToken.Audience == "istio-ca" {
							matched = true
						}
					}
				} else if volume.ConfigMap != nil {
					matched = true
				} else if volume.Projected != nil {
					for _, source := range volume.Projected.Sources {
						if source.ClusterTrustBundle != nil && mount.MountPath+"/"+source.ClusterTrustBundle.Path == path {
							matched = true
						}
					}
				}
			}
			if !matched {
				t.Fatalf("%s %s path %q does not resolve to its credential volume", container.Name, key, path)
			}
		}
	}
	if !found {
		t.Fatalf("no container uses %s", tokenEnv)
	}
}
