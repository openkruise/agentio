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
	"encoding/json"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/clienttrust"
)

func TestClientTrustAdmission(t *testing.T) {
	for _, mode := range []NativeSidecarMode{NativeSidecarModeEnabled, NativeSidecarModeDisabled} {
		t.Run(string(mode), func(t *testing.T) {
			wh := newTestWebhook(t, mode)
			setClientTrustEnabled(t, wh, true)
			pod := testPod()
			pod.Spec.Containers = []corev1.Container{{Name: "app", Image: "app"}, {Name: "metrics", Image: "metrics"}}
			pod.Annotations = map[string]string{clienttrust.IncludeAnnotation: "app*"}
			out := injectTestPod(t, wh, pod)
			for _, c := range out.Spec.Containers {
				if c.Name == "app" && len(c.VolumeMounts) == 0 {
					t.Fatal("missing CA mount")
				}
				if c.Name == "metrics" && len(c.Env) > 0 {
					t.Fatal("selected metrics")
				}
			}
			if out.Labels[clienttrust.ManagedLabel] != "true" {
				t.Fatal("no managed marker")
			}
			pod.Annotations[clienttrust.IncludeAnnotation] = "no-match*"
			response, _ := admitTestPod(t, wh, pod)
			if !response.Allowed || len(response.Warnings) != 1 {
				t.Fatalf("missing no-match warning: %+v", response)
			}
			pod.Annotations[clienttrust.IncludeAnnotation] = "[invalid]"
			response, _ = admitTestPod(t, wh, pod)
			if response.Allowed {
				t.Fatal("invalid pattern accepted")
			}
		})
	}
}

func TestClientTrustInvalidConfigRetainsLastGood(t *testing.T) {
	withFiles := func(paths ...string) clienttrust.Config {
		var items []corev1.KeyToPath
		for _, file := range paths {
			items = append(items, corev1.KeyToPath{Key: "ca", Path: file})
		}
		return clienttrust.Config{
			Mounts: []clienttrust.Mount{{
				Name:      "custom",
				MountPath: "/trust",
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "custom"},
					Items:                items,
				},
			}},
			Files: clienttrust.Files{CABundle: "/trust/roots.pem"},
		}
	}
	for name, config := range map[string]any{
		"invalid-boolean": map[string]any{"enabled": "typo"},
		"removed-auto":    map[string]any{"enabled": "auto"},
		"directory-file":  withFiles("roots.pem", "."),
		"child-file":      withFiles("roots.pem", "roots.pem/extra.pem"),
		"parent-file":     withFiles("roots.pem/extra.pem", "roots.pem"),
		"overlapping-mounts": clienttrust.Config{
			Mounts: []clienttrust.Mount{
				{Name: "parent", MountPath: "/trust", ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "parent"},
					Items:                []corev1.KeyToPath{{Key: "ca", Path: "ca.pem"}},
				}},
				{Name: "child", MountPath: "/trust/nested", ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "child"},
					Items:                []corev1.KeyToPath{{Key: "ca", Path: "ca.pem"}},
				}},
			},
			Files: clienttrust.Files{CABundle: "/trust/ca.pem"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			wh := newTestWebhook(t, NativeSidecarModeDisabled)
			setClientTrustEnabled(t, wh, true)
			original := injectTestPod(t, wh, testPod())
			before := wh.ClientTrustConfiguration().Get()
			values := map[string]any{}
			if err := json.Unmarshal([]byte(wh.valuesConfig.raw), &values); err != nil {
				t.Fatal(err)
			}
			values["clientTrust"] = config
			raw, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			if err := wh.UpdateConfig(wh.config, string(raw)); err == nil {
				t.Fatal("accepted bad config")
			}
			after := wh.ClientTrustConfiguration().Get()
			if !reflect.DeepEqual(after, before) {
				t.Fatal("lost last valid config")
			}
			if pod := injectTestPod(t, wh, testPod()); !reflect.DeepEqual(pod, original) {
				t.Fatal("invalid update changed subsequent Pod injection")
			}
		})
	}
}

func TestClientTrustSupportedTemplates(t *testing.T) {
	for _, tc := range []struct {
		name        string
		defaults    []string
		selected    string
		podOverride string
		want        bool
	}{
		{"ztunnel-default", []string{"ztunnel"}, "", "", true},
		{"ztunnel-pod-selection", []string{"custom-proxy"}, "ztunnel", "", true},
		{"alias", []string{"client"}, "", "", true},
		{"selected-alias", []string{"custom-proxy"}, "client", "", true},
		{"multiple-templates", []string{"ztunnel", "extra"}, "", "", true},
		{"selected-multiple-templates", []string{"custom-proxy"}, "extra,ztunnel", "", true},
		{"custom-default", []string{"custom-proxy"}, "", "true", false},
		{"custom-pod-selection", []string{"ztunnel"}, "custom-proxy", "true", false},
		{"custom-alias", []string{"custom-client"}, "", "true", false},
		{"gateway", []string{"egress-gateway"}, "", "true", false},
		{"agentgateway", []string{"agentgateway"}, "", "true", false},
		{"pod-opt-out", []string{"ztunnel"}, "", "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wh := newTestWebhook(t, NativeSidecarModeDisabled)
			raw, err := json.Marshal(map[string]any{
				"policy": "enabled", "defaultTemplates": tc.defaults,
				"templates": map[string]string{
					"ztunnel": wh.config.RawTemplates["ztunnel"], "custom-proxy": wh.config.RawTemplates["ztunnel"],
					"extra": "spec: {}", "egress-gateway": "spec: {}", "agentgateway": "spec: {}",
				},
				"aliases": map[string][]string{
					"client":        {"ztunnel", "extra"},
					"custom-client": {"custom-proxy", "extra"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			config, err := UnmarshalConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err = wh.UpdateConfig(&config, wh.valuesConfig.raw); err != nil {
				t.Fatal(err)
			}
			setClientTrustEnabled(t, wh, true)
			pod := testPod()
			pod.Annotations = map[string]string{}
			if tc.selected != "" {
				pod.Annotations[injectTemplatesAnnotation] = tc.selected
			}
			if tc.podOverride != "" {
				pod.Annotations[clienttrust.EnableAnnotation] = tc.podOverride
			}
			out := injectTestPod(t, wh, pod)
			app := FindContainer("hello", out.Spec.Containers)
			count := 0
			for _, variable := range app.Env {
				if variable.Name == clienttrust.BundleEnvName {
					count++
				}
			}
			wantCount := 0
			if tc.want {
				wantCount = 1
			}
			if count != wantCount || (out.Labels[clienttrust.ManagedLabel] == "true") != tc.want {
				t.Fatalf("bundle count=%d, managed=%q, want=%v", count, out.Labels[clienttrust.ManagedLabel], tc.want)
			}
		})
	}
}

func setClientTrustEnabled(t *testing.T, wh *Webhook, enabled bool) {
	t.Helper()
	values := map[string]any{}
	if err := json.Unmarshal([]byte(wh.valuesConfig.raw), &values); err != nil {
		t.Fatal(err)
	}
	values["clientTrust"] = map[string]any{"enabled": enabled}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := wh.UpdateConfig(wh.config, string(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestClientTrustExplicitEnablement(t *testing.T) {
	wh := newTestWebhook(t, NativeSidecarModeDisabled)
	assertTrust := func(want bool) {
		t.Helper()
		out := injectTestPod(t, wh, testPod())
		if got := out.Labels[clienttrust.ManagedLabel] == "true"; got != want {
			t.Fatalf("client trust=%v, want %v", got, want)
		}
	}
	// Admission needs only explicit configuration, without any Gateway source.
	assertTrust(false)
	for _, enabled := range []bool{true, false, true} {
		setClientTrustEnabled(t, wh, enabled)
		assertTrust(enabled)
	}
}

func TestClientTrustConfigurationRevision(t *testing.T) {
	wh := newTestWebhook(t, NativeSidecarModeDisabled)
	setClientTrustEnabled(t, wh, true)
	before := wh.ClientTrustConfiguration().Get()
	values := map[string]any{}
	if err := json.Unmarshal([]byte(wh.valuesConfig.raw), &values); err != nil {
		t.Fatal(err)
	}
	values["clientTrustBundle"] = map[string]any{"target": map[string]any{"configMapName": "new-client-ca", "key": "roots.pem"}}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := wh.UpdateConfig(wh.config, string(raw)); err != nil {
		t.Fatal(err)
	}
	after := wh.ClientTrustConfiguration().Get()
	if after.Bundle.Target.ConfigMapName != "new-client-ca" {
		t.Fatal("new revision did not publish its target")
	}
	if before.Bundle.Target.ConfigMapName != "agentio-client-ca" {
		t.Fatal("configuration update mutated the previous snapshot")
	}
	// New admissions must mount the same target published to the distributor.
	pod := injectTestPod(t, wh, testPod())
	found := false
	for _, volume := range pod.Spec.Volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == "new-client-ca" {
			found = true
			if !reflect.DeepEqual(volume.ConfigMap.Items, []corev1.KeyToPath{{Key: "roots.pem", Path: "roots.pem"}}) {
				t.Fatalf("injected bundle keys = %v", volume.ConfigMap.Items)
			}
		}
	}
	if !found {
		t.Fatal("new admission did not mount the updated bundle")
	}
	for _, env := range FindContainer("hello", pod.Spec.Containers).Env {
		if env.Name == clienttrust.BundleEnvName {
			if env.Value != "/etc/agentio/client-ca/roots.pem" {
				t.Fatalf("injected bundle path = %q", env.Value)
			}
			return
		}
	}
	t.Fatal("new admission is missing the bundle environment variable")
}
