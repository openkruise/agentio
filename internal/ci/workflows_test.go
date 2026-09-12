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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestReleasePromotesExactProductE2ECandidates(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-release.yml")
	jobs := workflowJobs(t, workflow)

	for _, forbidden := range []string{"build-ztunnel", "publish-ztunnel"} {
		if _, found := jobs[forbidden]; found {
			t.Errorf("release workflow must not own external component job %q", forbidden)
		}
	}

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
		"agentiod_image", "epe_image", "cni_image", "ztunnel_image",
		"proxy_init_image", "gateway_image", "ext_proc_image", "chart_artifact",
	} {
		if _, found := inputs[input]; !found {
			t.Errorf("product-e2e does not pass required BOM input %q", input)
		}
	}

	if needs := jobNeeds(t, jobs, "tag-agentio"); !slices.Contains(needs, "product-e2e") {
		t.Errorf("tag-agentio needs %v, want product-e2e gate", needs)
	}
	if needs := jobNeeds(t, jobs, "promote-version-images"); !slices.Contains(needs, "tag-agentio") || !slices.Contains(needs, "build-candidates") {
		t.Errorf("promote-version-images needs %v, want tag-agentio and build-candidates", needs)
	}
}

func TestProductE2EUsesGeneratedCoveragePlan(t *testing.T) {
	workflow := loadWorkflow(t, "agentio-e2e.yml")
	jobs := workflowJobs(t, workflow)
	job := workflowJob(t, jobs, "product-e2e")
	if condition, found := job["if"]; found {
		t.Fatalf("reusable product E2E has job restriction %q; callers own branch policy", condition)
	}
	if got := stringValue(t, job, "name"); got != "${{ matrix.id }}" {
		t.Errorf("product E2E job name = %q, want generated group identity", got)
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
	if index < 0 || !strings.Contains(stringValue(t, planSteps[index].(map[string]any), "run"), "go -C test/e2e run ./cmd/product-e2e plan --format=json") {
		t.Fatal("CI must use the same planner as local product runs")
	}

	environment := mapValue(t, job, "env")
	if environment["AGENTIO_E2E_GROUP"] != "${{ matrix.id }}" {
		t.Fatal("runner must execute the selected generated group")
	}
	if _, duplicated := environment["AGENTIO_E2E_SUITES"]; duplicated {
		t.Fatal("workflow must not maintain a second suite list")
	}
	for _, variable := range []string{
		"AGENTIO_E2E_AGENTIOD_IMAGE", "AGENTIO_E2E_EPE_IMAGE", "AGENTIO_E2E_CNI_IMAGE",
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
		t.Fatalf("missing diagnostic/cleanup step: export %d, upload %d, delete %d", exportIndex, uploadIndex, deleteIndex)
	}
	if !(exportIndex < uploadIndex && uploadIndex < deleteIndex) {
		t.Errorf("diagnostic/cleanup step order = export %d, upload %d, delete %d", exportIndex, uploadIndex, deleteIndex)
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
		if index < 0 || !strings.Contains(stringValue(t, steps[index].(map[string]any), "if"), "contains(matrix.fixtures, 'clienttrust')") {
			t.Fatalf("%s must support release sidecar jobs without candidate archives", name)
		}
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
		"candidate_image_artifact", "cni_image", "ztunnel_image", "proxy_init_image", "gateway_image",
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
	for _, output := range []string{"agentiod_image", "epe_image"} {
		if _, found := outputs[output]; !found {
			t.Errorf("build-images is missing immutable output %q", output)
		}
	}
}

func TestExternalDependencyUpdatesAreReleaseDriven(t *testing.T) {
	workflow := loadWorkflow(t, "sync-agentio-deps.yml")
	triggers := workflowTriggers(t, workflow)
	if _, found := triggers["repository_dispatch"]; !found {
		t.Error("dependency sync must accept component release dispatches")
	}
	if _, found := triggers["schedule"]; found {
		t.Error("dependency sync must not follow source repositories on a schedule")
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "agentio.deps"))
	if err != nil {
		t.Fatal(err)
	}
	var pins []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatalf("parse agentio.deps: %v", err)
	}
	want := map[string]bool{
		"ZTUNNEL_IMAGE": false, "CNI_IMAGE": false,
		"PROXY_INIT_IMAGE": false, "GATEWAY_IMAGE": false,
		"TRUST_PACKAGE_IMAGE": false,
	}
	if len(pins) != len(want) {
		t.Fatalf("agentio.deps has %d entries, want exactly the five externally owned image pins", len(pins))
	}
	for _, pin := range pins {
		if _, found := want[pin.Name]; !found {
			t.Errorf("agentio.deps contains non-image or repository-owned pin %q", pin.Name)
			continue
		}
		if want[pin.Name] {
			t.Errorf("agentio.deps contains duplicate pin %q", pin.Name)
		}
		want[pin.Name] = true
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
