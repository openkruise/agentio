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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseAndValidate(t *testing.T) {
	defaultMounts := []Mount{{
		Name:      "bundle",
		MountPath: DefaultMountPath,
		ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "agentio-client-ca"},
			Items:                []corev1.KeyToPath{{Key: "ca-bundle.pem", Path: "ca-bundle.pem"}},
		},
	}}
	for _, tc := range []struct {
		name   string
		values map[string]any
		bad    bool
	}{
		{"defaults", nil, false},
		{"boolean-true", map[string]any{"clientTrust": map[string]any{"enabled": true}}, false},
		{"boolean-false", map[string]any{"clientTrust": map[string]any{"enabled": false}}, false},
		{"auto", map[string]any{"clientTrust": map[string]any{"enabled": "auto"}}, true},
		{"string-true", map[string]any{"clientTrust": map[string]any{"enabled": "true"}}, true},
		{"string-false", map[string]any{"clientTrust": map[string]any{"enabled": "false"}}, true},
		{"unknown", map[string]any{"clientTrust": map[string]any{"presets": map[string]any{"python": true}}}, true},
		{"invalid-mode", map[string]any{"clientTrust": map[string]any{"enabled": "yes"}}, true},
		{"invalid-pattern", map[string]any{"clientTrust": map[string]any{"containers": map[string]any{"include": []string{"app?"}}}}, true},
		{"empty-mounts", map[string]any{"clientTrust": map[string]any{"mounts": []any{}}}, true},
		{"explicit-default-mount-without-path", map[string]any{"clientTrust": map[string]any{"mounts": defaultMounts}}, true},
		{"explicit-default-mount-with-path", map[string]any{"clientTrust": map[string]any{
			"mounts": defaultMounts,
			"files":  Files{CABundle: "/etc/agentio/client-ca/ca-bundle.pem"},
		}}, false},
		{"empty-sources", map[string]any{"clientTrustBundle": map[string]any{"sources": []any{}}}, true},
		{"ambiguous-source", map[string]any{"clientTrustBundle": map[string]any{"sources": []any{map[string]any{"defaultCAs": true, "agentioMITM": true}}}}, true},
		{"missing-ref", map[string]any{"clientTrustBundle": map[string]any{"sources": []any{map[string]any{"configMap": map[string]any{"name": "foo"}}}}}, true},
		{"duplicate-env", map[string]any{"clientTrust": map[string]any{"env": []string{"A", "A"}}}, true},
		{"empty-name", map[string]any{"clientTrust": map[string]any{"env": []string{""}}}, true},
		{"invalid-name", map[string]any{"clientTrust": map[string]any{"env": []string{"BAD=NAME"}}}, true},
		{"value-object", map[string]any{"clientTrust": map[string]any{"env": []any{map[string]any{"name": "A", "value": "/ca.pem"}}}}, true},
		{"valueFrom-object", map[string]any{"clientTrust": map[string]any{"env": []any{map[string]any{"name": "A", "valueFrom": map[string]any{"fieldRef": map[string]any{"fieldPath": "metadata.name"}}}}}}, true},
		{"extra-ca-path", map[string]any{"clientTrust": map[string]any{"files": map[string]any{"extraCA": "/ca.pem"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(tc.values)
			if (err != nil) != tc.bad {
				t.Fatalf("err=%v bad=%v", err, tc.bad)
			}
			if err == nil && s.Client.Enabled != (tc.name == "boolean-true") {
				t.Fatalf("enabled=%v, unexpected default or parsed boolean", s.Client.Enabled)
			}
			if err == nil && s.Client.Files.CABundle == "" {
				t.Fatal("missing default bundle path")
			}
		})
	}
}
func TestEnvironmentNameLists(t *testing.T) {
	defaults := []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"}
	for _, tc := range []struct {
		name   string
		config map[string]any
		want   []string
	}{
		{"omitted", map[string]any{}, defaults},
		{"custom", map[string]any{"env": []string{"CUSTOM_CA_FILE", "CURL_CA_BUNDLE"}}, []string{"CUSTOM_CA_FILE", "CURL_CA_BUNDLE"}},
		{"empty", map[string]any{"env": []string{}}, []string{}},
		{"explicit-builtin", map[string]any{"env": []string{BundleEnvName}}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.config["enabled"] = true
			s, err := Parse(map[string]any{"clientTrust": tc.config})
			if err != nil {
				t.Fatal(err)
			}
			original := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: "APP_SETTING", Value: "unchanged"}}}}}}
			out := original.DeepCopy()
			if _, err = Apply(original, out, s, excludeProxy); err != nil {
				t.Fatal(err)
			}
			c := out.Spec.Containers[0]
			if len(c.Env) != len(tc.want)+2 {
				t.Fatalf("unexpected env: %+v", c.Env)
			}
			for _, name := range append([]string{BundleEnvName}, tc.want...) {
				v := env(c, name)
				if v == nil || v.Value != s.Client.Files.CABundle || v.ValueFrom != nil {
					t.Fatalf("%s: %+v", name, v)
				}
			}
			if env(c, "APP_SETTING").Value != "unchanged" || len(c.VolumeMounts) != 1 {
				t.Fatal("application env or CA mount changed")
			}
		})
	}
}

func TestBundleEnvConflictPolicy(t *testing.T) {
	for _, existing := range []corev1.EnvVar{
		{Name: BundleEnvName, Value: "/application/roots.pem"},
		{Name: BundleEnvName, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
	} {
		for _, policy := range []string{"Preserve", "Overwrite"} {
			s := parsed(t)
			s.Client.Env = []string{}
			s.Client.EnvConflictPolicy = policy
			original := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{existing}}}}}
			out := original.DeepCopy()
			warnings, err := Apply(original, out, s, excludeProxy)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Spec.Containers[0].Env) != 1 {
				t.Fatal("duplicate builtin variable")
			}
			got := env(out.Spec.Containers[0], BundleEnvName)
			if policy == "Preserve" {
				if !reflect.DeepEqual(got, &existing) || len(warnings) != 1 || !strings.Contains(warnings[0], BundleEnvName) {
					t.Fatalf("preserve: %+v, %v", got, warnings)
				}
			} else if got.Value != s.Client.Files.CABundle || got.ValueFrom != nil || len(warnings) != 0 {
				t.Fatalf("overwrite: %+v, %v", got, warnings)
			}
		}
	}
}

func TestEnvironmentUsesCustomBundlePath(t *testing.T) {
	s, err := Parse(map[string]any{"clientTrust": map[string]any{
		"enabled": true,
		"env":     []string{"CUSTOM_CA_FILE", "NODE_EXTRA_CA_CERTS"},
		"mounts":  []any{map[string]any{"name": "custom", "mountPath": "/custom-ca", "configMap": map[string]any{"name": "custom", "items": []any{map[string]any{"key": "roots", "path": "roots.pem"}}}}},
		"files":   map[string]any{"caBundle": "/custom-ca/roots.pem"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	original := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	out := original.DeepCopy()
	if _, err = Apply(original, out, s, excludeProxy); err != nil {
		t.Fatal(err)
	}
	for _, v := range out.Spec.Containers[0].Env {
		if v.Value != "/custom-ca/roots.pem" {
			t.Fatalf("incorrect path: %+v", v)
		}
	}
	s.Client.Env = []string{}
	s.Client.Files.CABundle = "/unmounted.pem"
	if s.Validate() == nil {
		t.Fatal("accepted an unmounted bundle path")
	}
}

func TestConfiguredMountOverlap(t *testing.T) {
	for _, tc := range []struct {
		name, first, second string
		wantError           bool
	}{
		{"nested", "/trust", "/trust/nested", true},
		{"parent", "/trust/nested", "/trust", true},
		{"same", "/trust", "/trust", true},
		{"siblings", "/trust/one", "/trust/two", false},
		{"shared-prefix", "/trust", "/trust-extra", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mount := func(name, directory string) Mount {
				return Mount{Name: name, MountPath: directory, ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: name},
					Items:                []corev1.KeyToPath{{Key: "ca", Path: "ca.pem"}},
				}}
			}
			_, err := Parse(map[string]any{"clientTrust": Config{
				Mounts: []Mount{mount("one", tc.first), mount("two", tc.second)},
				Files:  Files{CABundle: tc.first + "/ca.pem"},
			}})
			if (err != nil) != tc.wantError {
				t.Fatalf("Parse error = %v, want error = %v", err, tc.wantError)
			}
		})
	}
}

func TestConfiguredFilePaths(t *testing.T) {
	for _, tc := range []struct {
		name      string
		paths     []string
		wantError bool
	}{
		{name: "directory", paths: []string{"."}, wantError: true},
		{name: "duplicate", paths: []string{"roots.pem", "roots.pem"}, wantError: true},
		{name: "child", paths: []string{"roots.pem", "roots.pem/extra.pem"}, wantError: true},
		{name: "parent", paths: []string{"roots.pem/extra.pem", "roots.pem"}, wantError: true},
		{name: "siblings", paths: []string{"roots/one.pem", "roots/two.pem"}},
		{name: "shared-prefix", paths: []string{"roots.pem", "roots.pem-extra/ca.pem"}},
	} {
		for _, source := range []string{"configMap", "secret"} {
			t.Run(tc.name+"/"+source, func(t *testing.T) {
				var items []corev1.KeyToPath
				for _, file := range tc.paths {
					items = append(items, corev1.KeyToPath{Key: "ca", Path: file})
				}
				mount := Mount{Name: "custom", MountPath: "/trust"}
				if source == "configMap" {
					mount.ConfigMap = &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "custom"},
						Items:                items,
					}
				} else {
					mount.Secret = &corev1.SecretVolumeSource{SecretName: "custom", Items: items}
				}
				_, err := Parse(map[string]any{"clientTrust": Config{
					Mounts: []Mount{mount},
					Files:  Files{CABundle: path.Join(mount.MountPath, tc.paths[0])},
				}})
				if (err != nil) != tc.wantError {
					t.Fatalf("Parse error = %v, want error = %v", err, tc.wantError)
				}
			})
		}
	}
}

func parsed(t *testing.T) Settings {
	t.Helper()
	s, err := Parse(map[string]any{"clientTrust": map[string]any{"enabled": true}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func excludeProxy(name string) bool { return name == "agentio-proxy" || name == "agentio-init" }
func env(c corev1.Container, name string) *corev1.EnvVar {
	for _, e := range c.Env {
		if e.Name == name {
			return &e
		}
	}
	return nil
}

func TestSelectionOverridesAndNativeSidecar(t *testing.T) {
	original := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{IncludeAnnotation: "app-*,worker", ExcludeAnnotation: "*-metrics"}}, Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "app-main"}, {Name: "app-metrics"}, {Name: "worker"}, {Name: "other"}}, InitContainers: []corev1.Container{{Name: "app-setup"}}}}
	before := original.DeepCopy()
	pod := original.DeepCopy()
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{Name: "agentio-proxy"}, corev1.Container{Name: "agentio-init"})
	s := parsed(t)
	s.Client.Containers.Include = []string{"does-not-match"}
	s.Client.Containers.IncludeInitContainers = true
	warnings, err := Apply(original, pod, s, excludeProxy)
	if err != nil || len(warnings) > 0 {
		t.Fatalf("%v %v", err, warnings)
	}
	for _, c := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		want := c.Name == "app-main" || c.Name == "worker" || c.Name == "app-setup"
		if (env(c, "SSL_CERT_FILE") != nil) != want || (env(c, BundleEnvName) != nil) != want {
			t.Errorf("unexpected selection: %s", c.Name)
		}
	}
	if !reflect.DeepEqual(original, before) {
		t.Fatal("mutated original")
	}
	if pod.Labels[ManagedLabel] != "true" {
		t.Fatal("missing distribution marker")
	}
	// Reapplying a plan after API defaulting is idempotent.
	mode := int32(0644)
	pod.Spec.Volumes[0].ConfigMap.DefaultMode = &mode
	after := pod.DeepCopy()
	if _, err = Apply(original, pod, s, excludeProxy); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, pod) {
		t.Fatal("non-idempotent apply")
	}
}
func TestEnablementAndNoMatch(t *testing.T) {
	for _, tc := range []struct {
		enabled    bool
		annotation string
		want       bool
	}{{false, "", false}, {true, "", true}, {false, "true", false}, {true, "false", false}} {
		s := parsed(t)
		s.Client.Enabled = tc.enabled
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
		if tc.annotation != "" {
			p.Annotations[EnableAnnotation] = tc.annotation
		}
		out := p.DeepCopy()
		if _, err := Apply(p, out, s, excludeProxy); err != nil {
			t.Fatal(err)
		}
		if (len(out.Spec.Volumes) > 0) != tc.want || (env(out.Spec.Containers[0], BundleEnvName) != nil) != tc.want {
			t.Fatalf("enablement %+v", tc)
		}
	}
	p := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	s := parsed(t)
	s.Client.Containers.Include = []string{"worker-*"}
	out := p.DeepCopy()
	warnings, err := Apply(p, out, s, excludeProxy)
	if err != nil || len(warnings) != 1 || !reflect.DeepEqual(p, out) {
		t.Fatalf("%v %v", warnings, err)
	}
	s.Client.Containers.Include = []string{"*"}
	s.Client.Containers.Exclude = []string{"*"}
	warnings, err = Apply(p, out, s, excludeProxy)
	if err != nil || len(warnings) > 0 || !reflect.DeepEqual(p, out) {
		t.Fatal("explicit exclusion should be silent")
	}
}
func TestEnvAndMountConflicts(t *testing.T) {
	p := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: "SSL_CERT_FILE", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "existing"}, Key: "path"}}}}}}}}
	s := parsed(t)
	s.Client.Env = []string{"SSL_CERT_FILE"}
	out := p.DeepCopy()
	warnings, err := Apply(p, out, s, excludeProxy)
	if err != nil || len(warnings) != 1 || env(out.Spec.Containers[0], "SSL_CERT_FILE").ValueFrom == nil {
		t.Fatalf("preserve %v %v", err, warnings)
	}
	s.Client.EnvConflictPolicy = "Overwrite"
	out = p.DeepCopy()
	_, err = Apply(p, out, s, excludeProxy)
	e := env(out.Spec.Containers[0], "SSL_CERT_FILE")
	if err != nil || e.ValueFrom != nil || e.Value != s.Client.Files.CABundle {
		t.Fatalf("overwrite %+v %v", e, err)
	}
	out = p.DeepCopy()
	out.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "business", MountPath: "/etc/agentio"}}
	if _, err = Apply(p, out, s, excludeProxy); err == nil {
		t.Fatal("expected overlapping mount error")
	}
	out = p.DeepCopy()
	out.Spec.Volumes = []corev1.Volume{{Name: "agentio-client-ca-bundle", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	if _, err = Apply(p, out, s, excludeProxy); err == nil {
		t.Fatal("expected volume conflict")
	}
}
func TestPatternGrammar(t *testing.T) {
	for _, name := range []string{"app", "app-main", "app-main-worker"} {
		if !Matches([]string{"app*"}, name) {
			t.Fatal(name)
		}
	}
	if Matches([]string{"app-*"}, "prefix-app-main") {
		t.Fatal("match must cover entire name")
	}
	for _, p := range []string{"", "a?", "[abc]", "first:0", "a/b"} {
		if ValidatePatterns([]string{p}) == nil {
			t.Fatal(p)
		}
	}
	if _, err := Patterns(map[string]string{IncludeAnnotation: "app,,worker"}, IncludeAnnotation, nil); err == nil {
		t.Fatal("empty token")
	}
	got, err := Patterns(map[string]string{IncludeAnnotation: ""}, IncludeAnnotation, []string{"app"})
	if err != nil || len(got) != 0 {
		t.Fatal("empty annotation must override")
	}
}
func certificate(t *testing.T, ca bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func TestBundleUnion(t *testing.T) {
	a, b := certificate(t, true), certificate(t, true)
	now := time.Now()
	first, _, err := Merge([][]byte{a, b, a}, now)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := Merge([][]byte{b, append([]byte("# comment\n"), a...)}, now)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("unstable union %v", err)
	}
	if strings.Count(string(first), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("duplicates")
	}
	for _, bad := range [][]byte{nil, []byte("garbage"), certificate(t, false), append(a, []byte("garbage")...), append(a, []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")...)} {
		if _, _, err := Merge([][]byte{a, bad}, now); err == nil {
			t.Fatal("accepted partial/invalid bundle")
		}
	}
}

func TestBundleRejectsSkippedPEM(t *testing.T) {
	valid := certificate(t, true)
	for _, tc := range []struct {
		name, malformed string
	}{
		{"invalid-base64", "-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----\n"},
		{"missing-end", "-----BEGIN CERTIFICATE-----\nYWJj\n"},
		{"wrong-end", "-----BEGIN CERTIFICATE-----\nYWJj\n-----END PRIVATE KEY-----\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, prefix := range []string{"", string(valid) + "# another certificate follows\n"} {
				source := []byte(prefix + tc.malformed + string(valid))
				bundle, warnings, err := Merge([][]byte{source}, time.Now())
				if err == nil || bundle != nil || warnings != nil {
					t.Fatalf("accepted partial source: bundle bytes=%d, warnings=%v, error=%v", len(bundle), warnings, err)
				}
			}
		})
	}
}
