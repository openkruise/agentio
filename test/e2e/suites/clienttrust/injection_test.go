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

package clienttrust

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestClientTrustHTTPS(t *testing.T) {
	s := newScenario(t)
	podOnlyNS := namespace.Create(t, s.env, namespace.Config{Prefix: "client-trust-pod"})
	s.applyTLSProfile(t, podOnlyNS.Name())
	for _, tc := range []struct {
		name      string
		enabled   bool
		native    bool
		namespace string
	}{
		{"disabled", false, true, s.namespace},
		{"trusted", true, true, s.namespace},
		{"pod-only", true, false, podOnlyNS.Name()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := s.pod(tc.name)
			pod.Namespace = tc.namespace
			pod.Spec.InitContainers = nil
			pod.Annotations[annotationPrefix+"native-sidecar"] = fmt.Sprint(tc.native)
			pod.Annotations[annotationPrefix+"client-trust-containers"] = "app-*"
			pod.Annotations[annotationPrefix+"client-trust-exclude-containers"] = "*-metrics"
			if !tc.enabled {
				pod.Annotations[annotationPrefix+"client-trust"] = "false"
			}
			if tc.namespace == podOnlyNS.Name() {
				pod.Labels[harness.DataplaneModeLabel] = "sidecar"
			}
			ready := s.createPod(t, pod)
			var selected []string
			if tc.enabled {
				selected = []string{"app-main"}
			}
			if err := checkSelected(ready, selected); err != nil {
				t.Fatal(err)
			}
			native := false
			for _, c := range ready.Spec.InitContainers {
				if c.Name == "agentio-proxy" && c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
					native = true
				}
			}
			if native != tc.native {
				t.Fatalf("native sidecar=%v, want=%v", native, tc.native)
			}
			s.verifiedHTTPS(t, ready, "app-main", tc.enabled)
			if tc.enabled {
				s.verifiedHTTPS(t, ready, "app-metrics", false)
				ctx, cancel := e2e.Context(t, 15*time.Second)
				defer cancel()
				cm, err := s.env.Cluster.Kube.CoreV1().ConfigMaps(tc.namespace).Get(ctx, "agentio-client-ca", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if strings.Count(cm.Data["ca-bundle.pem"], "BEGIN CERTIFICATE") < 50 || cm.Annotations["client-trust.agentio.kruise.io/package"] == "" {
					t.Fatal("missing managed public CA collection")
				}
				s.save(t, "bundle-metadata", cm.ObjectMeta)
			}
		})
		if t.Failed() {
			return
		}
	}
}

func TestClientTrustContainerSelection(t *testing.T) {
	s := newScenario(t)
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        []string
		warning     string
	}{
		{"defaults", nil, []string{"app-main", "app-metrics"}, ""},
		{"wildcard", map[string]string{"client-trust-containers": "*", "client-trust-exclude-containers": "*-metrics"}, []string{"app-main"}, ""},
		{"exact", map[string]string{"client-trust-containers": "app-metrics"}, []string{"app-metrics"}, ""},
		{"disabled", map[string]string{"client-trust": "false"}, nil, ""},
		{"no-match", map[string]string{"client-trust-containers": "missing-*"}, nil, "matched no business containers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := s.pod(tc.name)
			for key, value := range tc.annotations {
				pod.Annotations[annotationPrefix+key] = value
			}
			_, warnings := s.selected(t, pod, tc.want...)
			if tc.warning != "" && !strings.Contains(strings.Join(warnings, "\n"), tc.warning) {
				t.Fatalf("missing warning %q: %v", tc.warning, warnings)
			}
		})
	}
	for _, tc := range []struct{ name, key, value, error string }{
		{"invalid-mode", "client-trust", "maybe", "client trust"},
		{"invalid-pattern", "client-trust-containers", "app-?", "client trust"},
		{"overlapping-mount", "", "", "overlaps"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := s.pod(tc.name)
			if tc.key != "" {
				pod.Annotations[annotationPrefix+tc.key] = tc.value
			} else {
				pod.Spec.Volumes = []corev1.Volume{{Name: "existing", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
				pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "existing", MountPath: "/etc/agentio"}}
			}
			ctx, cancel := e2e.Context(t, 20*time.Second)
			defer cancel()
			_, warnings, err := s.env.Kube.AdmitPod(ctx, pod)
			s.save(t, "rejection", map[string]any{"error": fmt.Sprint(err), "warnings": warnings})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.error) {
				t.Fatalf("expected %q rejection, got %v", tc.error, err)
			}
		})
	}
}

func TestClientTrustEnvironment(t *testing.T) {
	s := newScenario(t)
	t.Run("preserve-and-overwrite", func(t *testing.T) {
		pod := s.pod("conflict")
		pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "SSL_CERT_FILE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}}}
		admitted, warnings := s.admit(t, pod)
		variable := envVariable(admitted.Spec.Containers[0], "SSL_CERT_FILE")
		if variable == nil || variable.ValueFrom == nil || !strings.Contains(strings.Join(warnings, "\n"), "SSL_CERT_FILE") {
			t.Fatalf("Preserve lost existing valueFrom or warning: %v %v", variable, warnings)
		}
		settings := baseSettings()
		settings["envConflictPolicy"] = "Overwrite"
		s.configure(t, settings)
		admitted, _ = s.admit(t, pod)
		variable = envVariable(admitted.Spec.Containers[0], "SSL_CERT_FILE")
		if variable == nil || variable.ValueFrom != nil || variable.Value != defaultBundlePath {
			t.Fatalf("Overwrite did not install bundle path: %v", variable)
		}
	})
	if t.Failed() {
		return
	}
	for _, tc := range []struct {
		name  string
		names []string
	}{
		{"python", []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"}},
		{"node", []string{"NODE_EXTRA_CA_CERTS"}},
		{"curl", []string{"CURL_CA_BUNDLE"}},
		{"custom", []string{"CUSTOM_CA_FILE"}},
		{"builtin", []string{bundleEnv}},
		{"empty", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := baseSettings()
			settings["env"] = tc.names
			s.configure(t, settings)
			admitted, _ := s.admit(t, s.pod("environment"))
			assertEnvironment(t, admitted.Spec.Containers[0], tc.names, defaultBundlePath)
			if len(tc.names) == 0 {
				pod := s.pod("bundle-only")
				pod.Spec.InitContainers = nil
				ready := s.createPod(t, pod)
				for _, host := range []string{"example.com", "example.org"} {
					result := s.probe(t, ready, "app-main", host)
					if result.Custom.Status != 200 {
						t.Fatalf("custom client could not load builtin bundle: %+v", result.Custom)
					}
					for _, key := range caVariables {
						if result.Env[key] != nil {
							t.Fatalf("env: [] unexpectedly injected %s", key)
						}
					}
				}
			}
		})
		if t.Failed() {
			return
		}
	}
}

func TestClientTrustGlobalOverrides(t *testing.T) {
	s := newScenario(t)
	settings := baseSettings()
	settings["enabled"] = false
	settings["containers"] = map[string]any{"include": []string{"app-main"}}
	s.configure(t, settings)
	s.selected(t, s.pod("global-disabled"))
	pod := s.pod("pod-enabled")
	pod.Annotations[annotationPrefix+"client-trust"] = "true"
	s.selected(t, pod)
	settings["enabled"] = true
	s.configure(t, settings)
	s.selected(t, pod, "app-main")
	pod.Name = "empty-override"
	pod.Annotations[annotationPrefix+"client-trust-containers"] = ""
	s.selected(t, pod, "app-main", "app-metrics")
}

func TestClientTrustCustomMount(t *testing.T) {
	s := newScenario(t)
	target := s.values["clientTrustBundle"].(map[string]any)["target"].(map[string]any)
	const path = "/var/run/client-trust-e2e/roots.pem"
	settings := baseSettings()
	settings["containers"] = map[string]any{"includeInitContainers": true}
	settings["mounts"] = []any{map[string]any{"name": "custom-roots", "mountPath": "/var/run/client-trust-e2e", "configMap": map[string]any{
		"name": target["configMapName"], "items": []any{map[string]any{"key": target["key"], "path": "roots.pem"}},
	}}}
	settings["files"] = map[string]any{"caBundle": path}
	settings["env"] = append(slices.Clone(caVariables), "CUSTOM_TRUST_FILE")
	s.configure(t, settings)
	admitted, _ := s.selected(t, s.pod("custom-mount"), "app-main", "app-metrics", "bootstrap")
	for _, c := range admitted.Spec.Containers {
		if !strings.HasPrefix(c.Name, "app-") {
			continue
		}
		assertEnvironment(t, c, append(slices.Clone(caVariables), "CUSTOM_TRUST_FILE"), path)
		if !slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool { return m.MountPath == "/var/run/client-trust-e2e" && m.ReadOnly }) {
			t.Fatal("missing readonly custom mount")
		}
	}
	ready := s.createPod(t, s.pod("custom-mount"))
	completed := false
	for _, status := range ready.Status.InitContainerStatuses {
		if status.Name == "bootstrap" && status.State.Terminated != nil && status.State.Terminated.ExitCode == 0 {
			completed = true
		}
	}
	if !completed {
		t.Fatal("business init did not load its injected CA file")
	}
	s.verifiedHTTPS(t, ready, "app-main", true)
}

func TestClientTrustSupportedTemplates(t *testing.T) {
	s := newScenario(t)
	templates := s.templates["templates"].(map[string]any)
	templates["custom-client"] = templates["ztunnel"]
	templates["extra"] = "spec: {}"
	s.templates["aliases"] = map[string]any{
		"client-alias": []string{"ztunnel", "extra"},
		"custom-alias": []string{"custom-client", "extra"},
	}
	s.publish(t)
	// Pod opt-in cannot enable CA injection for unsupported templates.
	for _, name := range []string{"custom-client", "custom-alias", "extra"} {
		pod := s.pod(name)
		pod.Annotations["inject.agentio.kruise.io/templates"] = name
		pod.Annotations[annotationPrefix+"client-trust"] = "true"
		s.selected(t, pod)
	}
	pod := s.pod("supported-template")
	for _, name := range []string{"ztunnel", "extra,ztunnel", "client-alias"} {
		pod.Annotations["inject.agentio.kruise.io/templates"] = name
		admitted, _ := s.selected(t, pod, "app-main", "app-metrics")
		assertEnvironment(t, admitted.Spec.Containers[0], caVariables, defaultBundlePath)
	}
	pod.Spec.InitContainers = nil
	ready := s.createPod(t, pod)
	s.verifiedHTTPS(t, ready, "app-main", true)
	pod.Name = "opt-out"
	pod.Annotations[annotationPrefix+"client-trust"] = "false"
	s.selected(t, pod)
}
