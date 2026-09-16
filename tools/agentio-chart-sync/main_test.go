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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestCLIApplySubcommandSyncsPreparedBundle(t *testing.T) {
	bundle := t.TempDir()
	target := t.TempDir()

	writeTestFile(t, bundle, "sandbox-manager/values.yaml", `# BEGIN GENERATED AGENTIO VALUES - DO NOT EDIT
agentio:
  enabled: false
# END GENERATED AGENTIO VALUES
`)
	writeTestFile(t, bundle, "sandbox-manager/templates/agentio/config.yaml", `{{- if .Values.agentio.enabled }}
kind: ConfigMap
{{- end }}
`)
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")

	command := exec.Command("go", "run", ".", "apply",
		"--bundle", bundle,
		"--manager-chart", target,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("agentio-chart-sync apply failed: %v\n%s", err, output)
	}

	if got := readTestFile(t, target, "templates/agentio/config.yaml"); !strings.Contains(got, ".Values.agentio.enabled") {
		t.Fatalf("prepared manager template was not synchronized unchanged:\n%s", got)
	}
	if got := readTestFile(t, target, "values.yaml"); !strings.Contains(got, "manager: unchanged") || !strings.Contains(got, "agentio:") {
		t.Fatalf("manager values were not merged:\n%s", got)
	}
}

func TestCLIPrepareSubcommandVersionsChartImagesAndBundle(t *testing.T) {
	chart := t.TempDir()
	writeTestFile(t, chart, "Chart.yaml", `apiVersion: v2
name: agentio
version: old
appVersion: old
annotations:
  artifacthub.io/changes: |
    - "[Changed]: See Agentio release notes: https://github.com/openkruise/agentio/releases"
`)
	writeTestFile(t, chart, "values.yaml", `global:
  hub: docker.io/openkruise
agentiod:
  image: {hub: "", name: pilot, tag: latest}
proxy:
  image: {hub: "", name: proxyv2, tag: latest}
proxyInit:
  image: {hub: "", name: proxy-init, tag: latest}
epe:
  image: {hub: "", name: agentio-epe, tag: latest}
egressGateway:
  image: {hub: "", name: proxyv2, tag: latest}
ztunnel:
  image: {hub: "", name: ztunnel, tag: latest}
cni:
  image: {hub: "", name: install-cni, tag: latest}
`)
	writeTestFile(t, chart, "templates/config.yaml", "kind: ConfigMap\n")
	writeTestFile(t, chart, "files/kruise-agents-traffic-proxy-injection.tpl", `{"image":"{{ .Values.agentio.trafficProxy.image }}"}
`)

	command := exec.Command("go", "run", ".", "prepare",
		"--chart", chart,
		"--version", "1.2.3",
		"--source-repository", "openkruise/agentio",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("agentio-chart-sync prepare failed: %v\n%s", err, output)
	}

	chartMetadata := map[string]any{}
	if err := yaml.Unmarshal([]byte(readTestFile(t, chart, "Chart.yaml")), &chartMetadata); err != nil {
		t.Fatalf("decode prepared Chart.yaml: %v", err)
	}
	if chartMetadata["version"] != "1.2.3" || chartMetadata["appVersion"] != "1.2.3" {
		t.Fatalf("prepared chart versions = version:%v appVersion:%v, want 1.2.3", chartMetadata["version"], chartMetadata["appVersion"])
	}
	annotations, ok := chartMetadata["annotations"].(map[string]any)
	if !ok || !strings.Contains(fmt.Sprint(annotations["artifacthub.io/changes"]), "/releases/tag/1.2.3") {
		t.Fatalf("prepared chart release annotation = %#v", chartMetadata["annotations"])
	}

	values := map[string]any{}
	if err := yaml.Unmarshal([]byte(readTestFile(t, chart, "values.yaml")), &values); err != nil {
		t.Fatalf("decode prepared values.yaml: %v", err)
	}
	imageTags := collectImageTags(values)
	wantImageCounts := map[string]int{
		"pilot": 1, "proxy-init": 1, "proxyv2": 2,
		"install-cni": 1, "ztunnel": 1, "agentio-epe": 1,
	}
	for name, wantCount := range wantImageCounts {
		tags := imageTags[name]
		if len(tags) != wantCount {
			t.Errorf("prepared image %s count = %d, want %d: %#v", name, len(tags), wantCount, tags)
		}
		for _, tag := range tags {
			if tag != "1.2.3" {
				t.Errorf("prepared image %s tag = %q, want 1.2.3", name, tag)
			}
		}
	}

	controllerValues := readTestFile(t, chart, "integrations/openkruise/sandbox-controller/values.yaml")
	for _, want := range []string{"docker.io/openkruise/ztunnel:1.2.3", "docker.io/openkruise/proxy-init:1.2.3"} {
		if !strings.Contains(controllerValues, want) {
			t.Errorf("prepared controller bundle does not contain %q:\n%s", want, controllerValues)
		}
	}
}

func TestCLIVerifySubcommandAcceptsRepositoryBundle(t *testing.T) {
	bundle := filepath.Join(repositoryAgentioChart(t), "integrations", "openkruise")
	command := exec.Command("go", "run", ".", "verify", "--bundle", bundle)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("agentio-chart-sync verify failed: %v\n%s", err, output)
	}
}

func TestVerifyIntegrationBundleRejectsVersionMetadataInTemplates(t *testing.T) {
	source := filepath.Join(repositoryAgentioChart(t), "integrations", "openkruise")
	bundle := filepath.Join(t.TempDir(), "openkruise")
	copyTestTree(t, source, bundle)

	template := "sandbox-manager/templates/agentio/agentiod.yaml"
	content := readTestFile(t, bundle, template)
	writeTestFile(t, bundle, template, content+"\n_metadata:\n  chartVersion: 1.2.3\n")

	err := VerifyIntegrationBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "chartVersion") {
		t.Fatalf("VerifyIntegrationBundle() error = %v, want chartVersion rejection", err)
	}
}

func TestVerifyIntegrationBundleRejectsVersionMetadataInFiles(t *testing.T) {
	source := filepath.Join(repositoryAgentioChart(t), "integrations", "openkruise")
	bundle := filepath.Join(t.TempDir(), "openkruise")
	copyTestTree(t, source, bundle)

	file := "sandbox-manager/files/agentio/trafficpolicy-crd.yaml"
	content := readTestFile(t, bundle, file)
	writeTestFile(t, bundle, file, content+"\nsourceCommit: abc123\n")

	err := VerifyIntegrationBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "sourceCommit") {
		t.Fatalf("VerifyIntegrationBundle() error = %v, want sourceCommit rejection", err)
	}
}

func TestExportGeneratesFlatAgentioChart(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()

	writeTestFile(t, source, "values.yaml", `global:
  hub: docker.io/openkruise
agentiod:
  replicas: 1
`)
	writeTestFile(t, source, "Chart.yaml", "name: agentio\nversion: 0.1.0\nappVersion: 0.1.0\n")
	writeTestFile(t, source, "templates/_helpers.tpl", `{{/* .Values.inAComment */}}
{{- define "agentio.example" -}}
{{ .Values.global.hub }} {{ printf ".Values.inAString" }} {{ .Chart.Name }}
{{- end -}}
`)
	writeTestFile(t, source, "templates/deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentiod
  annotations:
    example: ".Values.outsideAnAction"
spec:
  replicas: {{ .Values.agentiod.replicas }}
  {{- range .Values.agentiod.extraContainers }}
  image: {{ $.Values.global.hub }}/{{ .image }}
  {{- end }}
  config: |
{{ .Files.Get "files/config.yaml" | indent 4 }}
`)
	writeTestFile(t, source, "files/config.yaml", "feature: enabled\n")
	writeTestFile(t, source, "addons/dashboard.json", "{}\n")

	writeTestFile(t, target, "values.yaml", "replicaCount: 2\n")
	writeTestFile(t, target, "templates/manager.yaml", "kind: Deployment\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	wantValues := `replicaCount: 2

# BEGIN GENERATED AGENTIO VALUES - DO NOT EDIT
agentio:
  enabled: false
  global:
    hub: docker.io/openkruise
  agentiod:
    replicas: 1
# END GENERATED AGENTIO VALUES
`
	assertTestFile(t, target, "values.yaml", wantValues)
	assertTestFile(t, target, "templates/manager.yaml", "kind: Deployment\n")
	assertTestFile(t, target, "files/agentio/config.yaml", "feature: enabled\n")

	helper := readTestFile(t, target, "templates/agentio/_helpers.tpl")
	for _, want := range []string{
		"Code generated by agentio-chart-sync. DO NOT EDIT.",
		"{{ .Values.agentio.global.hub }}",
		`{{ printf ".Values.inAString" }}`,
		"{{ .Chart.Name }}",
		"{{/* .Values.inAComment */}}",
	} {
		if !strings.Contains(helper, want) {
			t.Errorf("generated helper does not contain %q:\n%s", want, helper)
		}
	}
	if strings.Contains(helper, ".Values.agentio.inAString") || strings.Contains(helper, ".Values.agentio.inAComment") {
		t.Fatalf("generated helper rewrote a string or template comment:\n%s", helper)
	}

	resource := readTestFile(t, target, "templates/agentio/deployment.yaml")
	for _, want := range []string{
		"{{- if .Values.agentio.enabled }}",
		"replicas: {{ .Values.agentio.agentiod.replicas }}",
		"{{- range .Values.agentio.agentiod.extraContainers }}",
		"{{ $.Values.agentio.global.hub }}",
		`.Files.Get "files/agentio/config.yaml"`,
		`example: ".Values.outsideAnAction"`,
	} {
		if !strings.Contains(resource, want) {
			t.Errorf("generated resource does not contain %q:\n%s", want, resource)
		}
	}
	if !strings.HasSuffix(resource, "{{- end }}\n") {
		t.Fatalf("generated resource is not guarded through EOF:\n%s", resource)
	}

	for _, unwanted := range []string{"chartVersion", "appVersion", "sourceCommit", "addons/dashboard.json"} {
		if strings.Contains(readAllGenerated(t, target), unwanted) {
			t.Errorf("generated chart unexpectedly contains %q", unwanted)
		}
	}
}

func TestExportCopiesPreparedOpenKruiseBundleWithoutRewriting(t *testing.T) {
	bundle := t.TempDir()
	target := t.TempDir()

	writeTestFile(t, bundle, "values.yaml", `# BEGIN GENERATED AGENTIO VALUES - DO NOT EDIT
agentio:
  enabled: false
  global:
    hub: docker.io/openkruise
# END GENERATED AGENTIO VALUES
`)
	preparedTemplate := `{{/* Code generated by agentio-chart-sync. DO NOT EDIT. */}}
{{- if .Values.agentio.enabled }}
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - image: {{ .Values.agentio.global.hub }}/pilot:latest
{{- end }}
`
	writeTestFile(t, bundle, "templates/agentio/agentiod.yaml", preparedTemplate)
	writeTestFile(t, bundle, "files/agentio/securityprofile-crd.yaml", "kind: CustomResourceDefinition\n")
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")
	writeTestFile(t, target, "templates/manager.yaml", "kind: Deployment\n")

	if err := Export(bundle, target); err != nil {
		t.Fatalf("Export(prepared bundle) error = %v", err)
	}

	assertTestFile(t, target, "templates/agentio/agentiod.yaml", preparedTemplate)
	assertTestFile(t, target, "files/agentio/securityprofile-crd.yaml", "kind: CustomResourceDefinition\n")
	values := readTestFile(t, target, "values.yaml")
	if strings.Contains(values, "agentio:\n  enabled: false\n  agentio:") {
		t.Fatalf("prepared values were nested a second time:\n%s", values)
	}
	for _, want := range []string{"manager: unchanged", "agentio:", "hub: docker.io/openkruise"} {
		if !strings.Contains(values, want) {
			t.Errorf("values.yaml does not contain %q:\n%s", want, values)
		}
	}
}

func TestExportReplacesOnlyGeneratedValuesAndIsIdempotent(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()

	writeTestFile(t, source, "values.yaml", "global:\n  hub: first.example\n")
	writeTestFile(t, source, "templates/config.yaml", "kind: ConfigMap\n")
	writeTestFile(t, target, "values.yaml", "managerHead: true\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("first Export() error = %v", err)
	}
	values := readTestFile(t, target, "values.yaml") + "managerTail: true\n"
	writeTestFile(t, target, "values.yaml", values)
	writeTestFile(t, source, "values.yaml", "global:\n  hub: second.example\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("second Export() error = %v", err)
	}
	firstSnapshot := readAllGenerated(t, target)
	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("idempotent Export() error = %v", err)
	}
	secondSnapshot := readAllGenerated(t, target)

	if firstSnapshot != secondSnapshot {
		t.Fatalf("repeated Export() changed generated output\nfirst:\n%s\nsecond:\n%s", firstSnapshot, secondSnapshot)
	}
	gotValues := readTestFile(t, target, "values.yaml")
	if strings.Count(gotValues, "BEGIN GENERATED AGENTIO VALUES") != 1 || strings.Count(gotValues, "END GENERATED AGENTIO VALUES") != 1 {
		t.Fatalf("generated values markers are not unique:\n%s", gotValues)
	}
	for _, want := range []string{"managerHead: true", "managerTail: true", "hub: second.example"} {
		if !strings.Contains(gotValues, want) {
			t.Errorf("values.yaml does not preserve %q:\n%s", want, gotValues)
		}
	}
	if strings.Contains(gotValues, "first.example") {
		t.Fatalf("values.yaml retained stale generated defaults:\n%s", gotValues)
	}
}

func TestExportRejectsRootEnabledWithoutChangingTarget(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()

	writeTestFile(t, source, "values.yaml", "enabled: true\nglobal: {}\n")
	writeTestFile(t, source, "templates/config.yaml", "kind: ConfigMap\n")
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")
	writeTestFile(t, target, "templates/agentio/keep.yaml", "keep\n")

	err := buildSandboxManagerBundle(source, target)
	if err == nil || !strings.Contains(err.Error(), "root-level enabled") {
		t.Fatalf("Export() error = %v, want root-level enabled rejection", err)
	}
	assertTestFile(t, target, "values.yaml", "manager: unchanged\n")
	assertTestFile(t, target, "templates/agentio/keep.yaml", "keep\n")
}

func TestExportKeepsLeadingNamedTemplateOutsideResourceGuard(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()

	writeTestFile(t, source, "values.yaml", "global: {}\n")
	writeTestFile(t, source, "templates/config.yaml", `{{- define "enhancedTrafficManagement.meshConfig" }}
{{- if .Values.global.enabled }}enabled{{- end }}
{{- end }}

kind: ConfigMap
data:
  config: {{ include "enhancedTrafficManagement.meshConfig" . | quote }}
`)
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	generated := readTestFile(t, target, "templates/agentio/config.yaml")
	define := strings.Index(generated, `define "agentio.meshConfig.defaults"`)
	guard := strings.Index(generated, "{{- if .Values.agentio.enabled }}")
	resource := strings.Index(generated, "kind: ConfigMap")
	if define < 0 || guard < 0 || resource < 0 || !(define < guard && guard < resource) {
		t.Fatalf("helper definition and resource guard are ordered incorrectly:\n%s", generated)
	}
	for _, want := range []string{
		"{{- if .Values.agentio.global.enabled }}",
		`include "agentio.meshConfig.defaults"`,
	} {
		if !strings.Contains(generated, want) {
			t.Errorf("generated template does not contain %q:\n%s", want, generated)
		}
	}
}

func TestExportRejectsNonLeadingNamedTemplateInResourceFile(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()

	writeTestFile(t, source, "values.yaml", "global: {}\n")
	writeTestFile(t, source, "templates/config.yaml", "kind: ConfigMap\n{{- define \"agentio.config\" }}x{{- end }}\n")
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")

	err := buildSandboxManagerBundle(source, target)
	if err == nil || !strings.Contains(err.Error(), "non-leading named template") {
		t.Fatalf("Export() error = %v, want non-leading named template rejection", err)
	}
	assertTestFile(t, target, "values.yaml", "manager: unchanged\n")
}

func TestRepositoryAgentioChartCanBeExported(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not return the test file path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(testFile), "..", ".."))
	source := filepath.Join(repositoryRoot, "manifests", "charts", "agentio")
	target := t.TempDir()
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("Export(repository Agentio chart) error = %v", err)
	}
	if !strings.Contains(readTestFile(t, target, "templates/agentio/agentiod.yaml"), ".Values.agentio.agentiod") {
		t.Fatal("generated repository chart does not scope agentiod values below agentio")
	}
}

func TestRepositoryOpenKruiseIntegrationBundleIsCurrent(t *testing.T) {
	source := repositoryAgentioChart(t)
	generated := filepath.Join(t.TempDir(), "openkruise")

	if err := BuildIntegrationBundle(source, generated); err != nil {
		t.Fatalf("BuildIntegrationBundle() error = %v", err)
	}

	checkedIn := filepath.Join(source, "integrations", "openkruise")
	want := readTestTree(t, checkedIn)
	got := readTestTree(t, generated)
	if got != want {
		t.Fatalf("checked-in OpenKruise integration bundle is stale\ngenerated:\n%s\nchecked in:\n%s", got, want)
	}
}

func TestExportOmitsAmbientAndSidecarInjectionFromSandboxManager(t *testing.T) {
	source := repositoryAgentioChart(t)
	target := t.TempDir()
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("Export(repository Agentio chart) error = %v", err)
	}

	for _, name := range []string{
		"cni-configmap.yaml",
		"cni-daemonset.yaml",
		"cni-rbac.yaml",
		"cni-serviceaccount.yaml",
		"injection-templates.yaml",
		"webhook.yaml",
		"ztunnel-daemonset.yaml",
		"ztunnel-serviceaccount.yaml",
	} {
		if _, err := os.Stat(filepath.Join(target, "templates", "agentio", name)); !os.IsNotExist(err) {
			t.Errorf("sandbox-manager export retained unsupported template %s: %v", name, err)
		}
	}
	for _, name := range []string{
		"kruise-agents-traffic-proxy-injection.tpl",
		"waypoint-injection-template.yaml",
		"ztunnel-injection-template.yaml",
	} {
		if _, err := os.Stat(filepath.Join(target, "files", "agentio", name)); !os.IsNotExist(err) {
			t.Errorf("sandbox-manager export retained unsupported chart file %s: %v", name, err)
		}
	}

	values := map[string]any{}
	if err := yaml.Unmarshal([]byte(readTestFile(t, target, "values.yaml")), &values); err != nil {
		t.Fatalf("decode generated sandbox-manager values: %v", err)
	}
	agentio, ok := values["agentio"].(map[string]any)
	if !ok {
		t.Fatalf("generated values do not contain an agentio map: %#v", values["agentio"])
	}
	for _, key := range []string{"ambient", "sidecarInjector", "ztunnel", "proxy", "proxyInit"} {
		if _, found := agentio[key]; found {
			t.Errorf("sandbox-manager values still expose unsupported agentio.%s", key)
		}
	}
	global, ok := agentio["global"].(map[string]any)
	if !ok {
		t.Fatalf("generated values do not contain agentio.global: %#v", agentio["global"])
	}
	for _, key := range []string{"enableFirewallRules", "enableClusterTrustBundle"} {
		if _, found := global[key]; found {
			t.Errorf("sandbox-manager values still expose unsupported agentio.global.%s", key)
		}
	}

	agentiod := readTestFile(t, target, "templates/agentio/agentiod.yaml")
	if strings.Contains(agentiod, ".Values.agentio.ambient") || strings.Contains(agentiod, ".Values.agentio.sidecarInjector") {
		t.Fatalf("generated agentiod template still depends on removed values:\n%s", agentiod)
	}
	for _, unwanted := range []string{"INJECTOR_CONFIG_MAP_NAME", "INJECTION_WEBHOOK_CONFIG_NAME", "https-webhook", "15017"} {
		if strings.Contains(agentiod, unwanted) {
			t.Errorf("generated agentiod template retained sidecar injector setting %q", unwanted)
		}
	}
	if !strings.Contains(agentiod, "name: INJECT_ENABLED\n          value: \"false\"") {
		t.Fatalf("generated agentiod template does not disable its injector:\n%s", agentiod)
	}
	clusterRole := readTestFile(t, target, "templates/agentio/clusterrole.yaml")
	if strings.Contains(clusterRole, "mutatingwebhookconfigurations") {
		t.Fatal("generated Agentio ClusterRole retains sidecar injector webhook permissions")
	}
	generatedValues := readTestFile(t, target, "values.yaml")
	for _, stale := range []string{"sidecar injector", "ztunnel DaemonSet", "MutatingWebhookConfiguration"} {
		if strings.Contains(generatedValues, stale) {
			t.Errorf("generated sandbox-manager values retain stale capability comment %q", stale)
		}
	}
	for name, paths := range map[string][2]string{
		"agentio-config.yaml": {".Values.agentioConfig", ".Values.agentio.agentioConfig"},
		"meshconfig.yaml":     {".Values.meshConfig", ".Values.agentio.meshConfig"},
	} {
		content := readTestFile(t, target, filepath.Join("templates", "agentio", name))
		if strings.Contains(content, paths[0]) || !strings.Contains(content, paths[1]) {
			t.Errorf("generated %s contains a stale values-path comment: %s", name, content)
		}
	}
}

func TestRepositoryAgentioCRDsAreAlwaysRenderedAndRetained(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not return the test file path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(testFile), "..", ".."))
	source := filepath.Join(repositoryRoot, "manifests", "charts", "agentio")
	target := t.TempDir()
	writeTestFile(t, target, "Chart.yaml", "apiVersion: v2\nname: sandbox-manager\nversion: 0.1.0\n")
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("Export(repository Agentio chart) error = %v", err)
	}

	chart, err := loader.Load(target)
	if err != nil {
		t.Fatalf("load exported chart: %v", err)
	}
	values, err := chartutil.ToRenderValues(chart, map[string]any{}, chartutil.ReleaseOptions{
		Name:      "sandbox-manager",
		Namespace: "default",
		IsInstall: true,
	}, chartutil.DefaultCapabilities)
	if err != nil {
		t.Fatalf("build exported chart render values: %v", err)
	}
	rendered, err := engine.Render(chart, values)
	if err != nil {
		t.Fatalf("render exported chart with agentio.enabled=false: %v", err)
	}

	var crds string
	for name, content := range rendered {
		if strings.HasSuffix(name, "/templates/agentio/crds.yaml") {
			crds = content
			break
		}
	}
	if got := strings.Count(crds, "kind: CustomResourceDefinition"); got != 4 {
		t.Fatalf("rendered CRD count with agentio.enabled=false = %d, want 4\nrendered:\n%s\ntemplate:\n%s", got, crds, readTestFile(t, target, "templates/agentio/crds.yaml"))
	}
	if got := strings.Count(crds, "helm.sh/resource-policy: keep"); got != 4 {
		t.Fatalf("rendered retained CRD annotation count = %d, want 4\n%s", got, crds)
	}
}

func TestSandboxManagerAgentioNamespaceIsIndependentFromReleaseNamespace(t *testing.T) {
	source := repositoryAgentioChart(t)
	target := t.TempDir()
	writeTestFile(t, target, "Chart.yaml", "apiVersion: v2\nname: sandbox-manager\nversion: 0.1.0\n")
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("buildSandboxManagerBundle() error = %v", err)
	}

	for _, test := range []struct {
		name      string
		namespace string
		values    map[string]any
	}{
		{
			name:      "default",
			namespace: "agentio-system",
			values: map[string]any{
				"agentio": map[string]any{"enabled": true},
			},
		},
		{
			name:      "override",
			namespace: "custom-agentio",
			values: map[string]any{
				"agentio": map[string]any{
					"enabled": true,
					"global":  map[string]any{"namespace": "custom-agentio"},
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for resource, namespace := range renderAgentioResourceNamespaces(t, target, test.values) {
				if namespace != test.namespace {
					t.Errorf("%s namespace = %q, want %q", resource, namespace, test.namespace)
				}
			}
		})
	}
}

func TestSandboxManagerCreatesAndRetainsAgentioNamespace(t *testing.T) {
	source := repositoryAgentioChart(t)
	target := t.TempDir()
	writeTestFile(t, target, "Chart.yaml", "apiVersion: v2\nname: sandbox-manager\nversion: 0.1.0\n")
	writeTestFile(t, target, "values.yaml", "manager: unchanged\n")

	if err := buildSandboxManagerBundle(source, target); err != nil {
		t.Fatalf("buildSandboxManagerBundle() error = %v", err)
	}

	for _, test := range []struct {
		name      string
		values    map[string]any
		wantName  string
		wantFound bool
	}{
		{
			name:      "default namespace",
			values:    map[string]any{"agentio": map[string]any{"enabled": true}},
			wantName:  "agentio-system",
			wantFound: true,
		},
		{
			name: "custom namespace",
			values: map[string]any{"agentio": map[string]any{
				"enabled": true,
				"global":  map[string]any{"namespace": "custom-agentio"},
			}},
			wantName:  "custom-agentio",
			wantFound: true,
		},
		{
			name: "namespace creation disabled",
			values: map[string]any{"agentio": map[string]any{
				"enabled": true,
				"global":  map[string]any{"createNamespace": false},
			}},
		},
		{
			name: "release namespace is managed by Helm",
			values: map[string]any{"agentio": map[string]any{
				"enabled": true,
				"global":  map[string]any{"namespace": "sandbox-system"},
			}},
		},
		{
			name:   "agentio disabled",
			values: map[string]any{"agentio": map[string]any{"enabled": false}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			namespace := renderAgentioNamespace(t, target, test.values)
			if !test.wantFound {
				if namespace != nil {
					t.Fatalf("rendered Namespace %q, want none", namespace.Name)
				}
				return
			}
			if namespace == nil {
				t.Fatal("rendered chart contains no Agentio Namespace")
			}
			if namespace.Name != test.wantName {
				t.Errorf("Namespace name = %q, want %q", namespace.Name, test.wantName)
			}
			if got := namespace.Annotations["helm.sh/resource-policy"]; got != "keep" {
				t.Errorf("Namespace resource policy = %q, want keep", got)
			}
		})
	}
}

func TestPreparedSandboxControllerBundleCreatesConsumableTrafficProxyConfig(t *testing.T) {
	source := filepath.Join(repositoryAgentioChart(t), "integrations", "openkruise", "sandbox-controller")
	target := newSandboxControllerChart(t)

	if err := ExportSandboxController(source, target); err != nil {
		t.Fatalf("ExportSandboxController() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "templates", "sandbox-injection-config.yaml")); err != nil {
		t.Fatalf("exported sandbox injection template: %v", err)
	}
	template := readTestFile(t, target, "templates/sandbox-injection-config.yaml")
	if strings.HasPrefix(template, "{{/* Code generated by agentio-chart-sync. DO NOT EDIT. */}}") {
		t.Fatal("shared sandbox injection ConfigMap is marked as wholly generated")
	}
	if strings.Contains(template, "GENERATED AGENTIO TRAFFIC PROXY") {
		t.Fatal("shared sandbox injection ConfigMap contains an Agentio generation marker")
	}
	if _, err := os.Stat(filepath.Join(target, "templates", "agentio-traffic-proxy-injection-config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("export retained the legacy sandbox injection template name: %v", err)
	}

	configMap := renderSandboxInjectionConfig(t, target)
	if configMap.Name != "sandbox-injection-config" || configMap.Namespace != "sandbox-system" {
		t.Fatalf("rendered ConfigMap = %s/%s, want sandbox-system/sandbox-injection-config", configMap.Namespace, configMap.Name)
	}

	var config struct {
		Annotations    map[string]string  `json:"annotations"`
		Labels         map[string]string  `json:"labels"`
		InitContainers []corev1.Container `json:"initContainers"`
		Volumes        []corev1.Volume    `json:"volume"`
	}
	if err := json.Unmarshal([]byte(configMap.Data["traffic-proxy"]), &config); err != nil {
		t.Fatalf("traffic-proxy data is not valid Kruise Agents JSON: %v\n%s", err, configMap.Data["traffic-proxy"])
	}
	if config.Annotations["networking.agents.kruise.io/sidecar-proxy"] != "traffic-proxy" {
		t.Fatalf("sidecar-proxy annotation = %q, want traffic-proxy", config.Annotations["networking.agents.kruise.io/sidecar-proxy"])
	}
	if config.Labels["networking.agents.kruise.io/proxy-type"] != "ztunnel" {
		t.Fatalf("proxy-type label = %q, want ztunnel", config.Labels["networking.agents.kruise.io/proxy-type"])
	}
	if len(config.InitContainers) != 2 {
		t.Fatalf("injected init container count = %d, want agentio-init and traffic-proxy", len(config.InitContainers))
	}
	if got := config.InitContainers[0]; got.Name != "agentio-init" || got.Image != "docker.io/openkruise/proxy-init:latest" {
		t.Fatalf("first init container = %s (%s), want agentio-init (docker.io/openkruise/proxy-init:latest)", got.Name, got.Image)
	}
	proxy := config.InitContainers[1]
	if proxy.Name != "traffic-proxy" || proxy.Image != "docker.io/openkruise/ztunnel:latest" {
		t.Fatalf("native sidecar = %s (%s), want traffic-proxy (docker.io/openkruise/ztunnel:latest)", proxy.Name, proxy.Image)
	}
	if proxy.RestartPolicy == nil || *proxy.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("traffic-proxy restartPolicy = %v, want Always", proxy.RestartPolicy)
	}
	if got := envValue(proxy.Env, "XDS_ADDRESS"); got != "agentiod.agentio-system.svc.cluster.local:15012" {
		t.Fatalf("XDS_ADDRESS = %q, want cross-namespace Agentio address", got)
	}
	if got := envValue(proxy.Env, "CA_ADDRESS"); got != "agentiod.agentio-system.svc.cluster.local:15012" {
		t.Fatalf("CA_ADDRESS = %q, want cross-namespace Agentio address", got)
	}
	assertCredentialMounts(t, corev1.PodSpec{InitContainers: config.InitContainers, Volumes: config.Volumes}, "AUTH_TOKEN")
	if !hasConfigMapVolume(config.Volumes, "agentio-ca-certs") {
		t.Fatalf("traffic-proxy volumes do not mount the namespace-local agentio-ca-certs ConfigMap: %#v", config.Volumes)
	}
}

func TestExportSandboxControllerAddsTrafficProxyToExistingConfigMap(t *testing.T) {
	source := repositoryAgentioChart(t)
	target := newSandboxControllerChart(t)
	writeTestFile(t, target, "templates/inject-config.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: sandbox-injection-config
  namespace: {{ include "sandbox-controller.namespace" . }}
data:
  agent-runtime: |
    {"mainContainer":{},"csiSidecar":[],"volume":[]}
`)

	if err := buildSandboxControllerBundle(source, target); err != nil {
		t.Fatalf("first ExportSandboxController() error = %v", err)
	}
	firstTemplate := readTestFile(t, target, "templates/inject-config.yaml")
	firstValues := readTestFile(t, target, "values.yaml")
	if err := buildSandboxControllerBundle(source, target); err != nil {
		t.Fatalf("second ExportSandboxController() error = %v", err)
	}
	assertTestFile(t, target, "templates/inject-config.yaml", firstTemplate)
	assertTestFile(t, target, "values.yaml", firstValues)

	configMap := renderSandboxInjectionConfig(t, target)
	if got := configMap.Data["agent-runtime"]; got != "{\"mainContainer\":{},\"csiSidecar\":[],\"volume\":[]}\n" {
		t.Fatalf("existing agent-runtime data changed to %q", got)
	}
	if configMap.Data["traffic-proxy"] == "" {
		t.Fatal("existing sandbox-injection-config did not receive traffic-proxy data")
	}
	if _, err := os.Stat(filepath.Join(target, "templates", "sandbox-injection-config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("export created a duplicate injection ConfigMap template: %v", err)
	}
}

func TestExportSandboxControllerRemovesLegacyWholeFileGenerationWarning(t *testing.T) {
	for _, legacyWarning := range []string{
		"{{/* Code generated by agentio-chart-sync. DO NOT EDIT. */}}\n",
		"{{/* Code generated by agentio-chart-exporter. DO NOT EDIT. */}}\n",
	} {
		t.Run(legacyWarning, func(t *testing.T) {
			source := repositoryAgentioChart(t)
			target := newSandboxControllerChart(t)
			writeTestFile(t, target, "templates/sandbox-injection-config.yaml", legacyWarning+`apiVersion: v1
kind: ConfigMap
metadata:
  name: sandbox-injection-config
  namespace: {{ include "sandbox-controller.namespace" . }}
data:
  agent-runtime: |
    {"mainContainer":{},"csiSidecar":[],"volume":[]}
`)

			if err := buildSandboxControllerBundle(source, target); err != nil {
				t.Fatalf("buildSandboxControllerBundle() error = %v", err)
			}

			template := readTestFile(t, target, "templates/sandbox-injection-config.yaml")
			if strings.HasPrefix(template, legacyWarning) {
				t.Fatal("legacy whole-file generation warning was retained")
			}
			configMap := renderSandboxInjectionConfig(t, target)
			if got := configMap.Data["agent-runtime"]; got != "{\"mainContainer\":{},\"csiSidecar\":[],\"volume\":[]}\n" {
				t.Fatalf("existing agent-runtime data changed to %q", got)
			}
			if configMap.Data["traffic-proxy"] == "" {
				t.Fatal("shared ConfigMap did not receive the generated Agentio entry")
			}
		})
	}
}

func TestExportSandboxControllerRemovesLegacyTrafficProxyMarkers(t *testing.T) {
	source := repositoryAgentioChart(t)
	target := newSandboxControllerChart(t)
	writeTestFile(t, target, "templates/sandbox-injection-config.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: sandbox-injection-config
  namespace: {{ include "sandbox-controller.namespace" . }}
data:
  # BEGIN GENERATED AGENTIO TRAFFIC PROXY - DO NOT EDIT
  traffic-proxy: |
    {"old":true}
  # END GENERATED AGENTIO TRAFFIC PROXY
  agent-runtime: |
    {"mainContainer":{},"csiSidecar":[],"volume":[]}
`)

	if err := buildSandboxControllerBundle(source, target); err != nil {
		t.Fatalf("buildSandboxControllerBundle() error = %v", err)
	}

	template := readTestFile(t, target, "templates/sandbox-injection-config.yaml")
	if strings.Contains(template, "GENERATED AGENTIO TRAFFIC PROXY") {
		t.Fatal("legacy Agentio traffic-proxy markers were retained")
	}
	configMap := renderSandboxInjectionConfig(t, target)
	if got := configMap.Data["agent-runtime"]; got != "{\"mainContainer\":{},\"csiSidecar\":[],\"volume\":[]}\n" {
		t.Fatalf("existing agent-runtime data changed to %q", got)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(configMap.Data["traffic-proxy"]), &config); err != nil {
		t.Fatalf("replacement traffic-proxy data is invalid JSON: %v", err)
	}
	if config["old"] != nil {
		t.Fatalf("replacement traffic-proxy retained old data: %#v", config)
	}
}

func TestExportSandboxControllerReplacesExistingTrafficProxyEntry(t *testing.T) {
	source := repositoryAgentioChart(t)
	target := newSandboxControllerChart(t)
	writeTestFile(t, target, "templates/inject-config.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: sandbox-injection-config
  namespace: {{ include "sandbox-controller.namespace" . }}
data:
  agent-runtime: |
    {"mainContainer":{},"csiSidecar":[],"volume":[]}
  traffic-proxy: |
    {"old":true}
`)

	if err := buildSandboxControllerBundle(source, target); err != nil {
		t.Fatalf("ExportSandboxController() error = %v", err)
	}

	template := readTestFile(t, target, "templates/inject-config.yaml")
	if strings.Contains(template, `{"old":true}`) {
		t.Fatal("existing traffic-proxy entry was not replaced")
	}
	if got := strings.Count(template, "  traffic-proxy: |"); got != 1 {
		t.Fatalf("traffic-proxy entry count = %d, want 1", got)
	}
	configMap := renderSandboxInjectionConfig(t, target)
	if got := configMap.Data["agent-runtime"]; got != "{\"mainContainer\":{},\"csiSidecar\":[],\"volume\":[]}\n" {
		t.Fatalf("existing agent-runtime data changed to %q", got)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(configMap.Data["traffic-proxy"]), &config); err != nil {
		t.Fatalf("replacement traffic-proxy data is invalid JSON: %v", err)
	}
	if config["old"] != nil {
		t.Fatalf("replacement traffic-proxy retained old data: %#v", config)
	}
}

func repositoryAgentioChart(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() did not return the test file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(testFile), "..", "..", "manifests", "charts", "agentio"))
}

func newSandboxControllerChart(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	writeTestFile(t, target, "Chart.yaml", "apiVersion: v2\nname: agents-sandbox-controller\nversion: 0.3.0\n")
	writeTestFile(t, target, "values.yaml", "namespace:\n  name: sandbox-system\n")
	writeTestFile(t, target, "templates/_helpers.tpl", `{{- define "sandbox-controller.namespace" -}}
{{- default .Values.namespace.name .Release.Namespace -}}
{{- end -}}
`)
	return target
}

func renderAgentioResourceNamespaces(t *testing.T, target string, userValues map[string]any) map[string]string {
	t.Helper()
	chart, err := loader.Load(target)
	if err != nil {
		t.Fatalf("load sandbox-manager chart: %v", err)
	}
	values, err := chartutil.ToRenderValues(chart, userValues, chartutil.ReleaseOptions{
		Name:      "sandbox-manager",
		Namespace: "sandbox-system",
		IsInstall: true,
	}, chartutil.DefaultCapabilities)
	if err != nil {
		t.Fatalf("build sandbox-manager render values: %v", err)
	}
	rendered, err := engine.Render(chart, values)
	if err != nil {
		t.Fatalf("render sandbox-manager chart: %v", err)
	}

	namespaces := map[string]string{}
	for name, content := range rendered {
		if !strings.Contains(name, "/templates/agentio/") {
			continue
		}
		for index, document := range strings.Split(content, "\n---") {
			object := struct {
				Kind     string `yaml:"kind"`
				Metadata struct {
					Name      string `yaml:"name"`
					Namespace string `yaml:"namespace"`
				} `yaml:"metadata"`
			}{}
			if err := yaml.Unmarshal([]byte(document), &object); err != nil {
				t.Fatalf("decode %s document %d: %v", name, index, err)
			}
			if object.Kind == "" || object.Metadata.Namespace == "" {
				continue
			}
			namespaces[fmt.Sprintf("%s/%s", object.Kind, object.Metadata.Name)] = object.Metadata.Namespace
		}
	}
	if len(namespaces) == 0 {
		t.Fatal("rendered chart contains no namespaced Agentio resources")
	}
	return namespaces
}

func renderAgentioNamespace(t *testing.T, target string, userValues map[string]any) *corev1.Namespace {
	t.Helper()
	chart, err := loader.Load(target)
	if err != nil {
		t.Fatalf("load sandbox-manager chart: %v", err)
	}
	values, err := chartutil.ToRenderValues(chart, userValues, chartutil.ReleaseOptions{
		Name:      "sandbox-manager",
		Namespace: "sandbox-system",
		IsInstall: true,
	}, chartutil.DefaultCapabilities)
	if err != nil {
		t.Fatalf("build sandbox-manager render values: %v", err)
	}
	rendered, err := engine.Render(chart, values)
	if err != nil {
		t.Fatalf("render sandbox-manager chart: %v", err)
	}

	var namespace *corev1.Namespace
	for name, content := range rendered {
		if !strings.Contains(name, "/templates/agentio/") {
			continue
		}
		for index, document := range strings.Split(content, "\n---") {
			object := struct {
				Kind string `yaml:"kind"`
			}{}
			if err := yaml.Unmarshal([]byte(document), &object); err != nil {
				t.Fatalf("decode %s document %d: %v", name, index, err)
			}
			if object.Kind != "Namespace" {
				continue
			}
			if namespace != nil {
				t.Fatalf("rendered chart contains multiple Agentio Namespaces")
			}
			namespace = &corev1.Namespace{}
			if err := yaml.Unmarshal([]byte(document), namespace); err != nil {
				t.Fatalf("decode Agentio Namespace from %s document %d: %v", name, index, err)
			}
		}
	}
	return namespace
}

func renderSandboxInjectionConfig(t *testing.T, target string) corev1.ConfigMap {
	t.Helper()
	chart, err := loader.Load(target)
	if err != nil {
		t.Fatalf("load sandbox-controller chart: %v", err)
	}
	values, err := chartutil.ToRenderValues(chart, map[string]any{}, chartutil.ReleaseOptions{
		Name:      "sandbox-controller",
		Namespace: "sandbox-system",
		IsInstall: true,
	}, chartutil.DefaultCapabilities)
	if err != nil {
		t.Fatalf("build sandbox-controller render values: %v", err)
	}
	rendered, err := engine.Render(chart, values)
	if err != nil {
		t.Fatalf("render sandbox-controller chart: %v", err)
	}
	for name, content := range rendered {
		if !strings.Contains(content, "name: sandbox-injection-config") {
			continue
		}
		configMap := corev1.ConfigMap{}
		if err := yaml.Unmarshal([]byte(content), &configMap); err != nil {
			t.Fatalf("decode sandbox injection ConfigMap from %s: %v\n%s", name, err, content)
		}
		return configMap
	}
	t.Fatal("rendered chart does not contain sandbox-injection-config")
	return corev1.ConfigMap{}
}

func envValue(env []corev1.EnvVar, name string) string {
	for _, item := range env {
		if item.Name == name {
			return item.Value
		}
	}
	return ""
}

func hasConfigMapVolume(volumes []corev1.Volume, name string) bool {
	for _, volume := range volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == name {
			return true
		}
	}
	return false
}

func writeTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func assertTestFile(t *testing.T, root, name, want string) {
	t.Helper()
	if got := readTestFile(t, root, name); got != want {
		t.Fatalf("%s mismatch\ngot:\n%s\nwant:\n%s", name, got, want)
	}
}

func readTestFile(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return string(content)
}

func readAllGenerated(t *testing.T, target string) string {
	t.Helper()
	var out strings.Builder
	for _, root := range []string{"values.yaml", "templates/agentio", "files/agentio"} {
		path := filepath.Join(target, filepath.FromSlash(root))
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("Stat(%q): %v", path, err)
		}
		if !info.IsDir() {
			fmt.Fprintf(&out, "-- %s --\n%s", root, readTestFile(t, target, root))
			continue
		}
		err = filepath.WalkDir(path, func(file string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(target, file)
			if err != nil {
				return err
			}
			content, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			fmt.Fprintf(&out, "-- %s --\n%s", filepath.ToSlash(rel), content)
			return nil
		})
		if err != nil {
			t.Fatalf("WalkDir(%q): %v", path, err)
		}
	}
	return out.String()
}

func readTestTree(t *testing.T, root string) string {
	t.Helper()
	var out strings.Builder
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&out, "-- %s --\n%s", filepath.ToSlash(rel), content)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%q): %v", root, err)
	}
	return out.String()
}

func collectImageTags(value any) map[string][]string {
	tags := map[string][]string{}
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			name, hasName := typed["name"].(string)
			tag, hasTag := typed["tag"].(string)
			if hasName && hasTag {
				tags[name] = append(tags[name], tag)
			}
			for _, child := range typed {
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	return tags
}

func copyTestTree(t *testing.T, source, target string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		writeTestFile(t, target, filepath.ToSlash(rel), string(content))
		return nil
	})
	if err != nil {
		t.Fatalf("copy test tree %q: %v", source, err)
	}
}
