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

package ci

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestReleasePromotesExactProductE2ECandidates(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-release.yml")
	jobs := workflowJobs(t, workflow)

	build := workflowJob(t, jobs, "build-candidates")
	if got := stringValue(t, build, "uses"); got != "./.github/workflows/agentio-image.yml" {
		t.Errorf("build-candidates uses %q, want reusable owned-image workflow", got)
	}

	productE2E := workflowJob(t, jobs, "product-e2e")
	if got := stringValue(t, productE2E, "uses"); got != "./.github/workflows/agentio-e2e.yml" {
		t.Errorf("product-e2e uses %q, want reusable product E2E workflow", got)
	}
	inputs := mapValue(t, productE2E, "with")
	for _, input := range []string{
		"agentiod_image", "epe_image", "porter_image", "cni_image", "ztunnel_image",
		"proxy_init_image", "gateway_image", "ext_proc_image", "chart_artifact",
	} {
		if _, found := inputs[input]; !found {
			t.Errorf("product-e2e does not pass required BOM input %q", input)
		}
	}

	for _, gate := range []string{"release-unit", "product-e2e", "epe-e2e"} {
		if needs := jobNeeds(t, jobs, "tag-agentio"); !slices.Contains(needs, gate) {
			t.Errorf("tag-agentio needs %v, want %s gate", needs, gate)
		}
	}
	for _, job := range []string{"product-e2e", "epe-e2e"} {
		if slices.Contains(jobNeeds(t, jobs, job), "release-unit") {
			t.Errorf("%s must run in parallel with release-unit", job)
		}
	}
	if needs := jobNeeds(
		t,
		jobs,
		"promote-version-images",
	); !slices.Contains(needs, "tag-agentio") ||
		!slices.Contains(needs, "build-candidates") {
		t.Errorf("promote-version-images needs %v, want tag-agentio and build-candidates", needs)
	}
}

func TestGatewayLatestUsesTestedReleaseImage(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-release.yml")
	selected := "${{ needs.validate-release.outputs.gateway_image || needs.build-candidates.outputs.gateway_agent_image }}"
	jobs := workflowJobs(t, workflow)
	for _, job := range []string{"product-e2e", "epe-e2e"} {
		if got := mapValue(t, workflowJob(t, jobs, job), "with")["gateway_image"]; got != selected {
			t.Fatalf("%s gateway = %v, want selected release image", job, got)
		}
	}
	step := workflowStep(t, workflow, "promote-latest", "Promote stable release to latest")
	if got := mapValue(t, step, "env")["GATEWAY_IMAGE"]; got != selected {
		t.Fatalf("latest gateway = %v, want the image used by E2E", got)
	}
	for _, tc := range []struct {
		name    string
		version string
		gateway string
	}{
		{"built candidate", "0.2.0", "registry.example/gateway@sha256:" + strings.Repeat("b", 64)},
		{"gateway override", "0.2.0", "registry.example/custom-gateway@sha256:" + strings.Repeat("c", 64)},
		{"prerelease", "0.2.0-rc.1", "registry.example/custom-gateway@sha256:" + strings.Repeat("c", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "promoted")
			writeTestFile(t, log, "", 0o600)
			writeTestFile(t, filepath.Join(dir, "crane"), `#!/bin/bash
set -euo pipefail
case "$1" in
  auth) cat >/dev/null ;;
  tag) printf '%s\n' "$2" >> "$TEST_PROMOTIONS" ;;
  digest)
    if [[ "$2" == *gateway:latest ]]; then
      printf '%s\n' "$TEST_GATEWAY_DIGEST"
    else
      printf '%s\n' "$TEST_DIGEST"
    fi ;;
  *) exit 1 ;;
esac
`, 0o700)
			digest := "sha256:" + strings.Repeat("a", 64)
			images := []string{
				"registry.example/agentiod@" + digest, "registry.example/epe@" + digest,
				"registry.example/porter@" + digest, "registry.example/ztunnel@" + digest,
			}
			_, gatewayDigest, _ := strings.Cut(tc.gateway, "@")
			cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", stringValue(t, step, "run"))
			cmd.Env = append(
				os.Environ(),
				"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"VERSION="+tc.version,
				"HUB_USERNAME=test",
				"HUB_TOKEN=test",
				"TEST_PROMOTIONS="+log,
				"AGENTIOD_IMAGE="+images[0],
				"EPE_IMAGE="+images[1],
				"PORTER_IMAGE="+images[2],
				"ZTUNNEL_IMAGE="+images[3],
				"GATEWAY_IMAGE="+tc.gateway,
				"TEST_DIGEST="+digest,
				"TEST_GATEWAY_DIGEST="+gatewayDigest,
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("promote latest: %v: %s", err, output)
			}
			promoted, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			if tc.version == "0.2.0" {
				want = append(images, tc.gateway)
			}
			if strings.TrimSpace(string(promoted)) != strings.Join(want, "\n") {
				t.Fatalf("promoted images = %s, want %v", promoted, want)
			}
		})
	}
}

func TestDownstreamSyncAcceptsReleasedBOM(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is not installed")
	}
	dir := t.TempDir()
	release := workflowStep(t, loadWorkflow(t, "agentio-release.yml"), "create-release", "Write released BOM")
	cmd := exec.Command("bash", "-eu", "-c", stringValue(t, release, "run"))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "VERSION=0.2.0", "GITHUB_SHA=test")
	for key := range mapValue(t, release, "env") {
		if strings.HasSuffix(key, "_IMAGE") {
			cmd.Env = append(cmd.Env, key+"=docker.io/openkruise/test@sha256:test")
		}
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write release BOM: %v\n%s", err, output)
	}
	sync := workflowStep(
		t,
		loadWorkflow(t, "sync-sandbox-manager-agentio-chart.yml"),
		"sync",
		"Verify release image tags against the published BOM",
	)
	for line := range strings.SplitSeq(stringValue(t, sync, "run"), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "jq -e --arg version") {
			continue
		}
		cmd := exec.Command("bash", "-eu", "-c", line)
		cmd.Env = append(os.Environ(), "VERSION=0.2.0", "bom="+filepath.Join(dir, "agentio-0.2.0-bom.json"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sync rejected release BOM: %v\n%s", err, output)
		}
		return
	}
	t.Fatal("missing downstream BOM validation")
}

func TestProductE2EUsesGeneratedCoveragePlan(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-e2e.yml")
	jobs := workflowJobs(t, workflow)
	job := workflowJob(t, jobs, "product-e2e")
	if condition, found := job["if"]; found {
		t.Fatalf("reusable product E2E has job restriction %q; callers own branch policy", condition)
	}
	if got := stringValue(t, job, "name"); got != "${{ inputs.epe_only && 'epe' || matrix.id }}" {
		t.Errorf("product E2E job name = %q, want EPE identity or generated product group identity", got)
	}
	if !slices.Contains(jobNeeds(t, jobs, "product-e2e"), "plan") {
		t.Fatal("product E2E must wait for coverage planning")
	}
	strategy := mapValue(t, job, "strategy")
	if strategy["matrix"] != "${{ fromJSON(needs.plan.outputs.matrix) }}" {
		t.Fatal("product E2E must consume the generated matrix")
	}
	plan := workflowJob(t, jobs, "plan")
	outputs := mapValue(t, plan, "outputs")
	if outputs["matrix"] != "${{ steps.coverage.outputs.matrix }}" {
		t.Fatal("plan must export the generated coverage matrix")
	}
	planSteps := listValue(t, plan, "steps")
	index := namedStepIndex(t, planSteps, "Generate product coverage plan")
	if index < 0 ||
		!strings.Contains(
			stringValue(t, planSteps[index].(map[string]any), "run"),
			"go -C test/e2e run ./cmd/product-e2e plan --format=json",
		) {
		t.Fatal("CI must use the same planner as local product runs")
	}

	environment := mapValue(t, job, "env")
	if environment["AGENTIO_E2E_GROUP"] != "${{ matrix.id }}" {
		t.Fatal("runner must execute the selected generated group")
	}
	if environment["AGENTIO_E2E_SUITES"] != "${{ join(matrix.invocations.*.suite, ',') }}" {
		t.Fatal("runner must select only the suites in its generated group")
	}
	for _, variable := range []string{
		"AGENTIO_E2E_AGENTIOD_IMAGE", "AGENTIO_E2E_EPE_IMAGE", "AGENTIO_E2E_PORTER_IMAGE", "AGENTIO_E2E_CNI_IMAGE",
		"AGENTIO_E2E_ZTUNNEL_IMAGE", "AGENTIO_E2E_PROXY_INIT_IMAGE", "AGENTIO_E2E_GATEWAY_IMAGE",
	} {
		if _, found := environment[variable]; !found {
			t.Errorf("product-e2e does not expose %q", variable)
		}
	}
	if got := stringValue(t, environment, "AGENTIO_E2E_FIREWALL_BACKEND"); got != "${{ matrix.backend }}" {
		t.Errorf("firewall backend = %q, want matrix backend", got)
	}
	if got := stringValue(t, environment, "E2E_DIAGNOSTICS_FULL_ON_FAILURE"); got != "true" {
		t.Errorf("full failure diagnostics = %q, want true", got)
	}
	if got := stringValue(t, environment, "E2E_DIAGNOSTICS_MAX_FULL_DUMPS"); got != "1" {
		t.Errorf("maximum full dumps = %q, want 1", got)
	}

	steps := listValue(t, job, "steps")
	exportIndex := namedStepIndex(t, steps, "Export KinD logs")
	uploadIndex := namedStepIndex(t, steps, "Upload Agentio E2E artifacts")
	deleteIndex := namedStepIndex(t, steps, "Delete isolated KinD cluster")
	if exportIndex < 0 || uploadIndex < 0 || deleteIndex < 0 {
		t.Fatalf(
			"missing diagnostic/cleanup step: export %d, upload %d, delete %d",
			exportIndex,
			uploadIndex,
			deleteIndex,
		)
	}
	if !(exportIndex < uploadIndex && uploadIndex < deleteIndex) {
		t.Errorf(
			"diagnostic/cleanup step order = export %d, upload %d, delete %d",
			exportIndex,
			uploadIndex,
			deleteIndex,
		)
	}
}

func TestClientTrustFixtureIsAvailableForReleaseAndPresubmit(t *testing.T) {
	jobs := workflowJobs(t, loadWorkflow(t, "agentio-e2e.yml"))
	if !slices.Contains(jobNeeds(t, jobs, "product-e2e"), "build-client-trust-fixture") {
		t.Fatal("product E2E can run before its client fixture is built")
	}
	build := workflowJob(t, jobs, "build-client-trust-fixture")
	if _, conditional := build["if"]; conditional {
		t.Fatal("client fixture must be available to all workflow callers")
	}
	steps := listValue(t, workflowJob(t, jobs, "product-e2e"), "steps")
	for _, name := range []string{"Download client trust fixture", "Publish client trust fixture to local registry"} {
		index := namedStepIndex(t, steps, name)
		if index < 0 {
			t.Fatalf("missing %s", name)
		}
		if steps[index].(map[string]any)["if"] != "contains(matrix.fixtures, 'clienttrust')" {
			t.Fatalf("%s must follow the selected fixture requirements", name)
		}
	}
	for _, name := range []string{"Start local image registry", "Delete local image registry"} {
		index := namedStepIndex(t, steps, name)
		if index < 0 ||
			!strings.Contains(
				stringValue(t, steps[index].(map[string]any), "if"),
				"contains(matrix.fixtures, 'clienttrust')",
			) {
			t.Fatalf("%s must support release sidecar jobs without candidate archives", name)
		}
	}
}

func TestReleaseBuildsExtProcFixtureWhenNoOverrideIsSupplied(t *testing.T) {
	release := loadWorkflow(t, "agentio-release.yml")
	input := mapValue(
		t,
		mapValue(t, mapValue(t, workflowTriggers(t, release), "workflow_dispatch"), "inputs"),
		"ext_proc_image",
	)
	if input["required"] != false || input["default"] != "" {
		t.Fatal("release must work without a previously published ext-proc fixture")
	}
	e2e := loadWorkflow(t, "agentio-e2e.yml")
	jobs := workflowJobs(t, e2e)
	if !slices.Contains(jobNeeds(t, jobs, "product-e2e"), "build-ext-proc-fixture") {
		t.Fatal("E2E must wait for the source-built ext-proc fixture")
	}
	if _, conditional := workflowJob(t, jobs, "build-ext-proc-fixture")["if"]; conditional {
		t.Fatal("skipping the fixture job would also skip E2E for image-override callers")
	}
	build := workflowStep(t, e2e, "build-ext-proc-fixture", "Build ext-proc fixture")
	if build["if"] != "inputs.candidate_image_artifact == '' && inputs.ext_proc_image == ''" {
		t.Fatal("source fixture must only be built when neither an image override nor candidates are supplied")
	}
	for _, name := range []string{"Download ext-proc fixture", "Publish ext-proc fixture to local registry", "Start local image registry", "Delete local image registry"} {
		step := workflowStep(t, e2e, "product-e2e", name)
		if !strings.Contains(stringValue(t, step, "if"), "needs.build-ext-proc-fixture.outputs.artifact != ''") {
			t.Errorf("%s must support the source-built fixture", name)
		}
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("release validation script test requires %s", tool)
		}
	}
	script := stringValue(
		t,
		workflowStep(t, release, "validate-release", "Validate release version and resolve dependency BOM"),
		"run",
	)
	deps, err := os.ReadFile(filepath.Join("..", "..", "agentio.deps"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, image string
		wantErr     bool
	}{
		{name: "build fixture locally"},
		{name: "immutable override", image: "registry.example/ext-proc@sha256:" + strings.Repeat("a", 64)},
		{name: "reject mutable override", image: "registry.example/ext-proc:latest", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "agentio.deps"), string(deps), 0o600)
			writeTestFile(t, filepath.Join(dir, "gh"), "#!/bin/sh\nexit 1\n", 0o700)
			cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"VERSION=0.2.0", "GITHUB_REPOSITORY=openkruise/agentio", "GITHUB_OUTPUT="+filepath.Join(dir, "output"),
				"CNI_IMAGE=", "PROXY_INIT_IMAGE=", "GATEWAY_IMAGE=", "FORWARD_PROXY_IMAGE=", "EXT_PROC_IMAGE="+tc.image)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validation error = %v, wantErr %v; output: %s", err, tc.wantErr, out)
			}
		})
	}
}

func TestProductE2EPresubmitBuildsLocalCandidatesAndUsesDependencyBOM(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-e2e-presubmit.yml")
	triggers := workflowTriggers(t, workflow)
	for _, trigger := range []string{"pull_request", "push"} {
		if _, found := triggers[trigger]; !found {
			t.Errorf("product E2E presubmit is missing %q trigger", trigger)
		}
	}

	jobs := workflowJobs(t, workflow)
	build := workflowJob(t, jobs, "build-candidates")
	steps := listValue(t, build, "steps")
	if index := namedStepIndex(t, steps, "Upload local candidate images"); index < 0 {
		t.Fatal("candidate images are not uploaded for isolated matrix jobs")
	}

	e2eJob := workflowJob(t, jobs, "product-e2e")
	if got := stringValue(t, e2eJob, "uses"); got != "./.github/workflows/agentio-e2e.yml" {
		t.Fatalf("presubmit product E2E uses %q", got)
	}
	if needs := jobNeeds(t, jobs, "product-e2e"); !slices.Contains(needs, "build-candidates") {
		t.Errorf("presubmit product E2E needs %v, want build-candidates", needs)
	}
	inputs := mapValue(t, e2eJob, "with")
	for _, input := range []string{
		"candidate_image_artifact", "cni_image", "proxy_init_image", "gateway_image",
	} {
		if _, found := inputs[input]; !found {
			t.Errorf("presubmit product E2E does not pass %q", input)
		}
	}
}

func TestOwnedImageWorkflowExportsImmutableReferences(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-image.yml")
	jobs := workflowJobs(t, workflow)
	job := workflowJob(t, jobs, "build-images")
	outputs := mapValue(t, job, "outputs")
	for _, output := range []string{"agentiod_image", "epe_image", "ztunnel_image"} {
		if _, found := outputs[output]; !found {
			t.Errorf("build-images is missing immutable output %q", output)
		}
	}
}

func TestExternalDependencyUpdatesUsePublishedImages(t *testing.T) {
	workflow := loadWorkflow(t, "sync-agentio-deps.yml")
	triggers := workflowTriggers(t, workflow)
	if _, found := triggers["repository_dispatch"]; !found {
		t.Error("dependency sync must accept component release dispatches")
	}
	options := listValue(
		t,
		mapValue(t, mapValue(t, triggers, "workflow_dispatch"), "inputs")["component"].(map[string]any),
		"options",
	)
	for _, option := range options {
		if option == "ztunnel" {
			t.Error("ztunnel source updates must not accept a published-image override")
		}
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "agentio.deps"))
	if err != nil {
		t.Fatal(err)
	}
	var pins []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
		RepoName   string `json:"repoName"`
		SourceSHA  string `json:"lastStableSHA"`
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatalf("parse agentio.deps: %v", err)
	}
	want := map[string]bool{
		"ZTUNNEL_REPO_SHA": false, "CNI_IMAGE": false,
		"PROXY_INIT_IMAGE": false, "GATEWAY_IMAGE": false,
		"TRUST_PACKAGE_IMAGE": false,
	}
	if len(pins) != len(want) {
		t.Fatalf("agentio.deps has %d entries, want one source pin and four external image pins", len(pins))
	}
	for _, pin := range pins {
		if _, found := want[pin.Name]; !found {
			t.Errorf("agentio.deps contains unexpected pin %q", pin.Name)
			continue
		}
		if want[pin.Name] {
			t.Errorf("agentio.deps contains duplicate pin %q", pin.Name)
		}
		want[pin.Name] = true
		if pin.Name == "ZTUNNEL_REPO_SHA" {
			if pin.RepoName != "openkruise/ztunnel" || len(pin.SourceSHA) != 40 || pin.Digest != "" {
				t.Errorf("invalid ztunnel source pin: %+v", pin)
			}
			continue
		}
		if pin.Repository == "" || pin.Digest == "" {
			t.Errorf("agentio.deps pin %q is incomplete", pin.Name)
		}
	}
}

func loadWorkflow(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatalf("read workflow %s: %v", name, err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse workflow %s: %v", name, err)
	}
	return workflow
}

func workflowJobs(t *testing.T, workflow map[string]any) map[string]any {
	t.Helper()
	return mapValue(t, workflow, "jobs")
}

func workflowTriggers(t *testing.T, workflow map[string]any) map[string]any {
	t.Helper()
	// GitHub's `on` key is a YAML 1.1 boolean spelling. sigs.k8s.io/yaml
	// normalizes it to "true" when decoding into an untyped map.
	if _, found := workflow["on"]; found {
		return mapValue(t, workflow, "on")
	}
	return mapValue(t, workflow, "true")
}

func workflowJob(t *testing.T, jobs map[string]any, name string) map[string]any {
	t.Helper()
	return mapValue(t, jobs, name)
}

func mapValue(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, found := parent[key]
	if !found {
		t.Fatalf("missing key %q", key)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("key %q has type %T, want map", key, value)
	}
	return result
}

func stringValue(t *testing.T, parent map[string]any, key string) string {
	t.Helper()
	value, found := parent[key]
	if !found {
		t.Fatalf("missing key %q", key)
	}
	result, ok := value.(string)
	if !ok {
		t.Fatalf("key %q has type %T, want string", key, value)
	}
	return result
}

func listValue(t *testing.T, parent map[string]any, key string) []any {
	t.Helper()
	value, found := parent[key]
	if !found {
		t.Fatalf("missing key %q", key)
	}
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("key %q has type %T, want list", key, value)
	}
	return result
}

func namedStepIndex(t *testing.T, steps []any, name string) int {
	t.Helper()
	for index, raw := range steps {
		step, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("step %d has type %T, want map", index, raw)
		}
		if step["name"] == name {
			return index
		}
	}
	return -1
}

func jobNeeds(t *testing.T, jobs map[string]any, name string) []string {
	t.Helper()
	job := workflowJob(t, jobs, name)
	value, found := job["needs"]
	if !found {
		return nil
	}
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			entry, ok := item.(string)
			if !ok {
				t.Fatalf("job %q needs entry has type %T, want string", name, item)
			}
			result = append(result, entry)
		}
		return result
	default:
		t.Fatalf("job %q needs has type %T, want string or list", name, value)
		return nil
	}
}
