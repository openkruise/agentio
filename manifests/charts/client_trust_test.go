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

package charts_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/inject"
)

func TestClientTrustChartContract(t *testing.T) {
	data, err := os.ReadFile("../../agentio.deps")
	if err != nil {
		t.Fatal(err)
	}
	var pins []struct{ Name, Repository, Digest string }
	if err = json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	var trustImage string
	for _, p := range pins {
		if p.Name == "TRUST_PACKAGE_IMAGE" {
			trustImage = p.Repository + "@" + p.Digest
		}
	}
	if trustImage == "" {
		t.Fatal("missing CA package pin")
	}
	manifest := renderAgentio(t, "--set", "profile=sidecar", "--set", "agentiod.injector.clientTrust.enabled=true")
	foundDeployment, foundConfig := false, false
	for _, document := range bytes.Split([]byte(manifest), []byte("\n---")) {
		var object renderedObject
		if err = yaml.Unmarshal(document, &object); err != nil {
			t.Fatal(err)
		}
		if object.Kind == "Deployment" && object.Metadata.Name == "agentiod" {
			foundDeployment = true
			var deploy appsv1.Deployment
			if err = yaml.Unmarshal(document, &deploy); err != nil {
				t.Fatal(err)
			}
			spec := deploy.Spec.Template.Spec
			if len(spec.InitContainers) != 1 || spec.InitContainers[0].Image != trustImage {
				t.Fatalf("CA package diverges from dependency pin: %+v", spec.InitContainers)
			}
			mounted := false
			for _, m := range spec.Containers[0].VolumeMounts {
				mounted = mounted || m.Name == "client-trust-package" && m.ReadOnly
			}
			if !mounted {
				t.Fatal("discovery does not mount trust package read-only")
			}
			if spec.SecurityContext.FSGroup == nil {
				t.Fatal("non-root trust init requires shared volume group")
			}
		}
		if object.Kind == "ConfigMap" && object.Metadata.Name == "agentio-sidecar-injector" {
			foundConfig = true
			var cm corev1.ConfigMap
			if err = yaml.Unmarshal(document, &cm); err != nil {
				t.Fatal(err)
			}
			config, err := inject.UnmarshalConfig([]byte(cm.Data["config"]))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(config.DefaultTemplates, []string{"ztunnel"}) {
				t.Fatal("client trust requires the ztunnel template")
			}
			values := map[string]any{}
			if err = yaml.Unmarshal([]byte(cm.Data["values"]), &values); err != nil {
				t.Fatal(err)
			}
			settings, err := clienttrust.Parse(values)
			if err != nil {
				t.Fatal(err)
			}
			if !settings.Client.Enabled || !reflect.DeepEqual(settings.Client.Env, []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"}) {
				t.Fatal("incorrect defaults")
			}
		}
	}
	if !foundDeployment || !foundConfig {
		t.Fatal("missing chart resources")
	}
}

func TestClientTrustChartRejectsInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"--set", "agentiod.injector.clientTrust.enabled=invalid"},
		{"--set", "agentiod.injector.clientTrust.enabled=auto"},
		{"--set-string", "agentiod.injector.clientTrust.enabled=true"},
		{"--set-string", "agentiod.injector.clientTrust.enabled=false"},
		{"--set", "agentiod.injector.clientTrust.presets.python=true"},
		{"--set-json", `agentiod.injector.clientTrust.env=[{"name":"SSL_CERT_FILE","value":"/ca.pem"}]`},
		{"--set-json", `agentiod.injector.clientTrust.env=[{"name":"SSL_CERT_FILE","valueFrom":{"fieldRef":{"fieldPath":"metadata.name"}}}]`},
		{"--set-json", `agentiod.injector.clientTrust.env=["SSL_CERT_FILE","SSL_CERT_FILE"]`},
		{"--set-json", `agentiod.injector.clientTrust.env=["BAD=NAME"]`},
		{"--set-json", `agentiod.injector.clientTrust.containers.include=["app?"]`},
		{"--set-json", `agentiod.clientTrustBundle.sources=[{"defaultCAs":true,"agentioMITM":true}]`},
		{"--set-json", `agentiod.injector.clientTrust.mounts=[{"name":"ca","mountPath":"/ca","secret":{"secretName":"ca"}}]`},
		{"--set", "agentiod.trustPackage.image=example.invalid/unpinned:latest"},
		{"--set", "agentiod.trustPackage.enabled=true"},
		{"--set", "agentiod.trustPackage.enabled=false"},
	} {
		if output, err := helmTemplate(t, args...); err == nil {
			t.Fatalf("invalid config rendered: %v\n%s", args, output)
		}
	}
}

func TestClientTrustChartEnvListReplacement(t *testing.T) {
	for _, names := range [][]string{{"CUSTOM_CA_FILE"}, {}} {
		raw, err := json.Marshal(names)
		if err != nil {
			t.Fatal(err)
		}
		manifest := renderAgentio(t, "--set", "profile=sidecar", "--set", "agentiod.injector.clientTrust.enabled=true", "--set-json", "agentiod.injector.clientTrust.env="+string(raw))
		found := false
		for _, document := range bytes.Split([]byte(manifest), []byte("\n---")) {
			var cm corev1.ConfigMap
			if err = yaml.Unmarshal(document, &cm); err != nil || cm.Kind != "ConfigMap" || cm.Name != "agentio-sidecar-injector" {
				continue
			}
			found = true
			var values map[string]any
			if err = yaml.Unmarshal([]byte(cm.Data["values"]), &values); err != nil {
				t.Fatal(err)
			}
			settings, err := clienttrust.Parse(values)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(settings.Client.Env, names) {
				t.Fatalf("Helm did not replace defaults: got %v want %v", settings.Client.Env, names)
			}
			if !settings.Client.Enabled {
				t.Fatal("explicit client trust enablement was lost")
			}
		}
		if !found {
			t.Fatal("missing injector values")
		}
	}
}

func TestClientTrustSecretWatchPermissions(t *testing.T) {
	// References keep their namespace; configuring another source must not grant new privileges.
	manifest := renderAgentio(t, "--set", "profile=sidecar", "--set", "agentiod.injector.clientTrust.enabled=true", "--set-json", `agentiod.clientTrustBundle.sources=[{"secret":{"namespace":"agentio-system","name":"roots","key":"ca.crt"}},{"secret":{"namespace":"company-ca","name":"external-roots","key":"ca.crt"}}]`)
	foundRole, foundBinding, foundClusterRole := false, false, false
	for _, document := range bytes.Split([]byte(manifest), []byte("\n---")) {
		var object renderedObject
		if err := yaml.Unmarshal(document, &object); err != nil {
			t.Fatal(err)
		}
		if (object.Kind == "Role" || object.Kind == "RoleBinding") && strings.Contains(object.Metadata.Name, "client-ca-") {
			t.Fatalf("CA source added RBAC: %s %s", object.Kind, object.Metadata.Name)
		}
		switch {
		case object.Kind == "Role" && object.Metadata.Name == "agentiod":
			var role rbacv1.Role
			if err := yaml.Unmarshal(document, &role); err != nil {
				t.Fatal(err)
			}
			if role.Namespace != "agentio-system" {
				t.Fatalf("agentiod Role is outside the system namespace: %s", role.Namespace)
			}
			for _, rule := range role.Rules {
				if slices.Contains(rule.Resources, "secrets") && slices.Contains(rule.Verbs, "get") && slices.Contains(rule.Verbs, "list") && slices.Contains(rule.Verbs, "watch") {
					foundRole = true
				}
			}
		case object.Kind == "RoleBinding" && object.Metadata.Name == "agentiod":
			var binding rbacv1.RoleBinding
			if err := yaml.Unmarshal(document, &binding); err != nil {
				t.Fatal(err)
			}
			foundBinding = binding.Namespace == "agentio-system" && binding.RoleRef.Kind == "Role" && binding.RoleRef.Name == "agentiod" &&
				len(binding.Subjects) == 1 && binding.Subjects[0].Kind == "ServiceAccount" && binding.Subjects[0].Name == "agentiod" && binding.Subjects[0].Namespace == "agentio-system"
		case object.Kind == "ClusterRole" && object.Metadata.Name == "agentiod-agentio-system":
			var role rbacv1.ClusterRole
			if err := yaml.Unmarshal(document, &role); err != nil {
				t.Fatal(err)
			}
			foundClusterRole = true
			for _, rule := range role.Rules {
				if slices.Contains(rule.Resources, "secrets") || slices.Contains(rule.Resources, "*") {
					t.Fatalf("agentiod received cluster-wide Secret permissions: %+v", rule)
				}
			}
		}
	}
	if !foundRole || !foundBinding || !foundClusterRole {
		t.Fatalf("missing existing agentiod RBAC: role=%v, binding=%v, clusterRole=%v", foundRole, foundBinding, foundClusterRole)
	}
}

func TestClientTrustMasterSwitch(t *testing.T) {
	for _, tc := range []struct {
		name        string
		profile     string
		sources     string
		enabled     bool
		wantEnabled bool
		wantPackage bool
	}{
		{name: "default-disabled", profile: "sidecar"},
		{name: "enabled", profile: "sidecar", enabled: true, wantEnabled: true, wantPackage: true},
		{name: "ambient", profile: "ambient", enabled: true},
		{
			name:        "mitm-only",
			profile:     "sidecar",
			sources:     `[{"agentioMITM":true}]`,
			enabled:     true,
			wantEnabled: true,
		},
		{
			name:    "private-sources",
			profile: "sidecar",
			sources: `[
  {"secret":{"namespace":"company-ca","name":"roots","key":"ca.crt"}},
  {"configMap":{"namespace":"company-ca","name":"extra-roots","key":"ca.crt"}}
]`,
			enabled:     true,
			wantEnabled: true,
		},
		{
			name:    "public-source-last",
			profile: "sidecar",
			sources: `[
  {"secret":{"namespace":"company-ca","name":"roots","key":"ca.crt"}},
  {"defaultCAs":true}
]`,
			enabled:     true,
			wantEnabled: true,
			wantPackage: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"--set", "profile=" + tc.profile}
			if tc.sources != "" {
				args = append(args, "--set-json", "agentiod.clientTrustBundle.sources="+tc.sources)
			}
			if tc.enabled {
				args = append(args, "--set", "agentiod.injector.clientTrust.enabled=true")
			}
			manifest := renderAgentio(t, args...)
			found, role, binding := false, false, false
			for _, document := range bytes.Split([]byte(manifest), []byte("\n---")) {
				var object renderedObject
				if err := yaml.Unmarshal(document, &object); err != nil {
					t.Fatal(err)
				}
				role = role || object.Kind == "Role" && strings.Contains(object.Metadata.Name, "client-ca-")
				binding = binding || object.Kind == "RoleBinding" && strings.Contains(object.Metadata.Name, "client-ca-")
				if object.Kind != "Deployment" || object.Metadata.Name != "agentiod" {
					continue
				}
				found = true
				var deployment appsv1.Deployment
				if err := yaml.Unmarshal(document, &deployment); err != nil {
					t.Fatal(err)
				}
				spec := deployment.Spec.Template.Spec
				flagCount, packageEnvCount := 0, 0
				for _, variable := range spec.Containers[0].Env {
					if variable.Name == "AGENTIO_ENABLE_CLIENT_TRUST_DISTRIBUTOR" {
						flagCount++
						if variable.Value != strconv.FormatBool(tc.wantEnabled) {
							t.Fatalf("process gate=%s, want=%v", variable.Value, tc.wantEnabled)
						}
					}
					if variable.Name == "AGENTIO_CLIENT_TRUST_PACKAGE_PATH" {
						packageEnvCount++
					}
				}
				if flagCount != 1 ||
					(packageEnvCount > 0) != tc.wantPackage ||
					(len(spec.InitContainers) > 0) != tc.wantPackage ||
					(len(spec.Volumes) > 0) != tc.wantPackage ||
					(len(spec.Containers[0].VolumeMounts) > 0) != tc.wantPackage {
					t.Fatalf("inconsistent process gate or package resources: %+v", spec)
				}
			}
			if !found || role || binding {
				t.Fatalf("deployment=%v, source role=%v, binding=%v, enabled=%v", found, role, binding, tc.wantEnabled)
			}
		})
	}
}
