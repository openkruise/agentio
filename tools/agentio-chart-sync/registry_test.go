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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestApplyReleasedBundlePreservesChartImageRegistry(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	source := filepath.Join(t.TempDir(), "agentio")
	copyTestTree(t, repositoryAgentioChart(t), source)
	digest := "sha256:" + strings.Repeat("a", 64)
	images := []string{}
	for _, name := range []string{"agentiod", "agentio-epe", "ztunnel", "install-cni", "proxy-init", "agentio-gateway", "agentio-porter"} {
		images = append(images, "docker.io/openkruise/"+name+"@"+digest)
	}
	if output, err := exec.Command("../prepare-release-chart.sh", append([]string{source, "1.2.3"}, images...)...).
		CombinedOutput(); err != nil {
		t.Fatalf("prepare released bundle: %v\n%s", err, output)
	}
	bundle := filepath.Join(source, "integrations", "openkruise")
	// Simulate the published 0.2.0 bundle's previous namespace default.
	for _, component := range []string{"sandbox-manager", "sandbox-controller"} {
		path := filepath.Join(component, "values.yaml")
		writeTestFile(
			t,
			bundle,
			path,
			strings.NewReplacer("sandbox-system", "agentio-system", "mode: static", "mode: disabled", "mode: managed", "mode: disabled").
				Replace(readTestFile(t, bundle, path)),
		)
	}
	namespaceHelper := "sandbox-manager/templates/agentio/_namespace.tpl"
	writeTestFile(
		t,
		bundle,
		namespaceHelper,
		strings.ReplaceAll(readTestFile(t, bundle, namespaceHelper), "sandbox-system", "agentio-system"),
	)
	beforeBundle := readTestTree(t, bundle)
	manager, controller := t.TempDir(), newSandboxControllerChart(t)
	writeTestFile(t, manager, "Chart.yaml", "apiVersion: v2\nname: sandbox-manager\nversion: 1.0.0\n")
	writeTestFile(t, manager, "values.yaml", "image: {registry: docker.io}\nparent: unchanged\n")
	writeTestFile(t, controller, "values.yaml", "image: {registry: docker.io}\nnamespace: {name: sandbox-system}\n")
	args := []string{"--bundle", bundle, "--manager-chart", manager, "--controller-chart", controller}
	if err := runApply(args); err != nil {
		t.Fatal(err)
	}
	for _, chart := range []string{manager, controller} {
		if strings.Contains(readTestFile(t, chart, "values.yaml"), "agentio-system") {
			t.Fatal("apply retained the previous namespace default")
		}
	}
	config := renderSandboxInjectionConfig(t, controller)
	if !strings.Contains(config.Data["traffic-proxy"], "agentiod.sandbox-system.svc.cluster.local:15012") {
		t.Fatal("controller does not target the default control-plane namespace")
	}
	for resource, namespace := range renderAgentioResourceNamespaces(t, manager, map[string]any{"agentio": map[string]any{"enabled": true, "global": map[string]any{"namespace": ""}}}) {
		if namespace != "sandbox-system" {
			t.Errorf("%s namespace = %s", resource, namespace)
		}
	}
	testIntegrationEgressDefaults(t, manager)
	beforeManager, beforeController := readTestTree(t, manager), readTestTree(t, controller)
	if err := runApply(args); err != nil {
		t.Fatal(err)
	}
	if readTestTree(t, manager) != beforeManager || readTestTree(t, controller) != beforeController {
		t.Fatal("reapplying a released bundle changes the adapted charts")
	}
	if readTestTree(t, bundle) != beforeBundle {
		t.Fatal("apply mutated the released bundle")
	}
	if !strings.HasPrefix(
		readTestFile(t, manager, "values.yaml"),
		"image: {registry: docker.io}\nparent: unchanged\n",
	) {
		t.Fatal("apply changed parent values outside the generated block")
	}
	for _, tc := range []struct {
		name             string
		chartRegistry    string
		globalRegistry   string
		imageRegistry    string
		repository       string
		tag              string
		digest           string
		managerPrefix    string
		controllerPrefix string
	}{
		{name: "released defaults", managerPrefix: "docker.io/openkruise/", controllerPrefix: "docker.io/openkruise/"},
		{name: "chart registry", chartRegistry: "mirror.example:5000", managerPrefix: "mirror.example:5000/openkruise/", controllerPrefix: "mirror.example:5000/openkruise/"},
		{name: "agentio registry", chartRegistry: "chart.example", globalRegistry: "agentio.example", managerPrefix: "agentio.example/openkruise/", controllerPrefix: "chart.example/openkruise/"},
		{name: "per-image registry", chartRegistry: "chart.example", globalRegistry: "agentio.example", imageRegistry: "image.example", managerPrefix: "image.example/openkruise/", controllerPrefix: "image.example/openkruise/"},
		{name: "qualified repository", chartRegistry: "chart.example", globalRegistry: "agentio.example", imageRegistry: "image.example", repository: "explicit.example:5000/team/image"},
		{name: "digest override", digest: digest, tag: "2.3.4", managerPrefix: "docker.io/openkruise/", controllerPrefix: "docker.io/openkruise/"},
		{name: "tag override", chartRegistry: "mirror.example", tag: "2.3.4", managerPrefix: "mirror.example/openkruise/", controllerPrefix: "mirror.example/openkruise/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imageValues := map[string]any{"registry": tc.imageRegistry}
			if tc.repository != "" {
				imageValues["repository"] = tc.repository
			}
			suffix := ":1.2.3"
			if tc.tag != "" {
				imageValues["tag"] = tc.tag
				suffix = ":" + tc.tag
			}
			if tc.digest != "" {
				imageValues["digest"] = tc.digest
				suffix = "@" + tc.digest
			}
			managerValues := map[string]any{
				"image": map[string]any{"registry": tc.chartRegistry},
				"agentio": map[string]any{
					"enabled":       true,
					"global":        map[string]any{"registry": tc.globalRegistry},
					"agentiod":      map[string]any{"image": imageValues},
					"epe":           map[string]any{"mode": "managed", "image": imageValues},
					"egressGateway": map[string]any{"mode": "static", "image": imageValues, "porter": map[string]any{"image": imageValues}},
				},
			}
			controllerValues := map[string]any{
				"image": map[string]any{"registry": tc.chartRegistry},
				"agentio": map[string]any{
					"trafficProxy": map[string]any{"image": imageValues, "initImage": imageValues},
				},
			}
			for _, chart := range []struct {
				path   string
				prefix string
				values map[string]any
				names  []string
			}{
				{
					manager,
					tc.managerPrefix,
					managerValues,
					[]string{"agentiod", "agentio-epe", "agentio-gateway", "agentio-porter"},
				},
				{controller, tc.controllerPrefix, controllerValues, []string{"ztunnel", "proxy-init"}},
			} {
				all := ""
				for _, content := range renderChart(t, chart.path, chart.values) {
					all += content
				}
				for _, name := range chart.names {
					want := chart.prefix + name + suffix
					if tc.repository != "" {
						want = tc.repository + suffix
					}
					if !strings.Contains(all, `"`+want+`"`) {
						t.Errorf("rendered chart does not contain image %s", want)
					}
				}
			}
		})
	}
}

func TestApplyRequiresFixedReleaseTag(t *testing.T) {
	for _, tag := range []string{"", "latest", "main", "0.2", "01.2.3", "1.2.3-01", "1.2.3+build"} {
		t.Run(tag, func(t *testing.T) {
			bundle, target := t.TempDir(), t.TempDir()
			writeTestFile(t, bundle, "sandbox-manager/values.yaml", "agentio:\n  global:\n    tag: \""+tag+"\"\n")
			before := readTestTree(t, target)
			if err := runApply(
				[]string{"--bundle", bundle, "--manager-chart", target},
			); err == nil ||
				!strings.Contains(err.Error(), "fixed release version") {
				t.Fatalf("expected release tag validation error, got %v", err)
			}
			if readTestTree(t, target) != before {
				t.Fatal("invalid release tag changed target")
			}
		})
	}
	for _, tag := range []string{"0.2.0", "1.2.3-rc.1"} {
		bundle := t.TempDir()
		writeTestFile(t, bundle, "sandbox-manager/values.yaml", "agentio:\n  global:\n    tag: \""+tag+"\"\n")
		if actual, err := integrationImageTag(bundle); err != nil || actual != tag {
			t.Fatalf("tag %q: got %q, %v", tag, actual, err)
		}
	}
}

func testIntegrationEgressDefaults(t *testing.T, chart string) {
	t.Helper()
	for _, tc := range []struct {
		name    string
		agentio map[string]any
		policy  string
		service string
	}{
		{name: "default gateway and EPE", policy: "GATEWAY", service: "agentio-egress.sandbox-system.svc.cluster.local"},
		{name: "custom gateway address", agentio: map[string]any{"global": map[string]any{"namespace": "custom", "clusterDomain": "example.internal"}, "egressGateway": map[string]any{"fullnameOverride": "my-egress"}}, policy: "GATEWAY", service: "my-egress.custom.svc.example.internal"},
		{name: "explicit passthrough", agentio: map[string]any{"agentiod": map[string]any{"config": map[string]any{"values": map[string]any{"egressPolicies": []any{map[string]any{"policy": "PASSTHROUGH"}}}}}}, policy: "PASSTHROUGH"},
		{name: "explicit empty routes", agentio: map[string]any{"agentiod": map[string]any{"config": map[string]any{"values": map[string]any{"egressPolicies": []any{}}}}}},
		{name: "gateway and EPE disabled", agentio: map[string]any{"egressGateway": map[string]any{"mode": "disabled"}, "epe": map[string]any{"mode": "disabled"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.agentio == nil {
				tc.agentio = map[string]any{}
			}
			tc.agentio["enabled"] = true
			rendered := renderChart(t, chart, map[string]any{"agentio": tc.agentio})
			found := false
			for _, content := range rendered {
				for doc := range strings.SplitSeq(content, "\n---") {
					var object struct {
						Kind string
						Data map[string]string
					}
					if err := yaml.Unmarshal([]byte(doc), &object); err != nil {
						t.Fatal(err)
					}
					if object.Kind != "ConfigMap" || object.Data["config"] == "" {
						continue
					}
					found = true
					var config struct {
						EgressPolicies []struct {
							Policy  string
							Gateway struct{ Service string }
						}
						SandboxExtProc map[string]any
					}
					if err := yaml.Unmarshal([]byte(object.Data["config"]), &config); err != nil {
						t.Fatal(err)
					}
					if tc.policy == "" {
						if len(config.EgressPolicies) != 0 {
							t.Fatal("unexpected default egress route")
						}
					} else if len(config.EgressPolicies) != 1 ||
						config.EgressPolicies[0].Policy != tc.policy ||
						config.EgressPolicies[0].Gateway.Service != tc.service {
						t.Fatalf("unexpected egress policies: %+v", config.EgressPolicies)
					}
					if tc.name == "default gateway and EPE" && len(config.SandboxExtProc) == 0 {
						t.Fatal("default EPE provider missing")
					}
				}
			}
			if !found {
				t.Fatal("Agentio ConfigMap missing")
			}
		})
	}
}
