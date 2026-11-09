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
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestZtunnelReleaseUsesBuiltAndTestedImage(t *testing.T) {
	imageJobs := workflowJobs(t, loadWorkflow(t, "agentio-image.yml"))
	if !slices.Contains(jobNeeds(t, imageJobs, "build-images"), "build-ztunnel") {
		t.Fatal("image packaging must wait for the pinned source build")
	}
	if got := workflowJob(t, imageJobs, "build-ztunnel")["uses"]; got != "./.github/workflows/agentio-ztunnel.yml" {
		t.Fatalf("image publisher does not use the shared source build: %v", got)
	}
	release := loadWorkflow(t, "agentio-release.yml")
	inputs := mapValue(t, mapValue(t, workflowTriggers(t, release), "workflow_dispatch"), "inputs")
	if _, found := inputs["ztunnel_image"]; found {
		t.Error("release must use the pinned source build, not an unrelated image override")
	}
	jobs := workflowJobs(t, release)
	want := "${{ needs.build-candidates.outputs.ztunnel_image }}"
	if got := mapValue(t, workflowJob(t, jobs, "product-e2e"), "with")["ztunnel_image"]; got != want {
		t.Errorf("E2E ztunnel = %v, want the built candidate", got)
	}
	for _, check := range []struct{ job, step string }{
		{"prepare-chart", "Prepare exact candidate chart"},
		{"prepare-chart", "Verify candidate chart"},
		{"promote-version-images", "Promote tested images to version tags"},
		{"promote-latest", "Promote stable release to latest"},
		{"create-release", "Write released BOM"},
	} {
		step := workflowStep(t, release, check.job, check.step)
		if got := mapValue(t, step, "env")["ZTUNNEL_IMAGE"]; got != want {
			t.Errorf("%s/%s uses %v instead of the tested ztunnel candidate", check.job, check.step, got)
		}
	}
}

func TestZtunnelPresubmitTestsPinnedSourceWithoutRegistryCredentials(t *testing.T) {
	presubmit := loadWorkflow(t, "agentio-e2e-presubmit.yml")
	jobs := workflowJobs(t, presubmit)
	build := workflowJob(t, jobs, "build-ztunnel")
	if build["uses"] != "./.github/workflows/agentio-ztunnel.yml" || mapValue(t, build, "with")["multi_arch"] != false {
		t.Fatal("presubmit must use the same source build on amd64")
	}
	if _, found := build["secrets"]; found {
		t.Error("fork presubmits must build without registry credentials")
	}
	if !slices.Contains(jobNeeds(t, jobs, "build-candidates"), "build-ztunnel") {
		t.Fatal("presubmit must wait for the pinned source binary before packaging")
	}
	script := stringValue(
		t,
		workflowStep(t, presubmit, "build-candidates", "Build repository-owned and test fixture candidates"),
		"run",
	)
	if !strings.Contains(script, `"agentio-e2e.local/ztunnel:${tag}"`) ||
		!strings.Contains(script, "docker/Dockerfile.ztunnel") {
		t.Fatal("presubmit must package the built ztunnel in the candidate archive")
	}
	e2e := loadWorkflow(t, "agentio-e2e.yml")
	publish := stringValue(t, workflowStep(t, e2e, "product-e2e", "Publish candidates to a local registry"), "run")
	if !strings.Contains(
		publish,
		"for image in agentiod agentio-epe agentio-porter agentio-gateway proxy-init ztunnel ext-proc;",
	) ||
		!strings.Contains(publish, "AGENTIO_E2E_ZTUNNEL_IMAGE=$digest_ref") {
		t.Fatal("E2E must run the archived ztunnel by its local registry digest")
	}
}

func TestZtunnelSyncTargetsEachMaintainedBranch(t *testing.T) {
	w := loadWorkflow(t, "sync-ztunnel-deps.yml")
	sync := workflowJob(t, workflowJobs(t, w), "sync")
	matrix := mapValue(t, mapValue(t, sync, "strategy"), "matrix")
	if !strings.Contains(stringValue(t, matrix, "branch"), `'["master","release-0.1"]'`) {
		t.Fatal("scheduled source sync must cover both maintained branches")
	}
	checkout := workflowStep(t, w, "sync", "Checkout target Agentio branch")
	pr := workflowStep(t, w, "sync", "Create or update source dependency pull request")
	if mapValue(t, checkout, "with")["ref"] != "${{ matrix.branch }}" ||
		mapValue(t, pr, "with")["base"] != "${{ matrix.branch }}" {
		t.Fatal("source sync checkout and PR base must use the selected branch, not the default branch")
	}
	if !strings.Contains(stringValue(t, mapValue(t, pr, "with"), "branch"), "${{ matrix.branch }}") ||
		!strings.Contains(stringValue(t, mapValue(t, sync, "concurrency"), "group"), "${{ matrix.branch }}") {
		t.Fatal("source sync PR branches and concurrency must be isolated per target")
	}
}

func TestZtunnelPresubmitCachesOnlyTheExactSourceBinary(t *testing.T) {
	w := loadWorkflow(t, "agentio-ztunnel.yml")
	inputs := mapValue(t, mapValue(t, workflowTriggers(t, w), "workflow_call"), "inputs")
	if mapValue(t, inputs, "cache_binary")["default"] != false {
		t.Fatal("publication builds must not reuse presubmit binaries by default")
	}
	cache := workflowStep(t, w, "build", "Restore pinned ztunnel binary")
	if cache["if"] != "inputs.cache_binary" {
		t.Fatal("binary cache must be enabled explicitly by the caller")
	}
	settings := mapValue(t, cache, "with")
	for _, input := range []string{"runner.os", "matrix.arch", "steps.source.outputs.repository", "steps.source.outputs.sha", "hashFiles('.github/workflows/agentio-ztunnel.yml')"} {
		if !strings.Contains(stringValue(t, settings, "key"), input) {
			t.Errorf("binary cache key is missing build input %s", input)
		}
	}
	if _, found := settings["restore-keys"]; found {
		t.Fatal("a finished binary must not fall back to another source or build configuration")
	}
	for _, name := range []string{"Checkout pinned ztunnel", "Build ztunnel", "Stage native binary"} {
		if workflowStep(t, w, "build", name)["if"] != "steps.binary-cache.outputs.cache-hit != 'true'" {
			t.Errorf("%s must run on a cache miss and skip on an exact hit", name)
		}
	}
	if _, conditional := workflowStep(t, w, "build", "Verify native binary and runtime")["if"]; conditional {
		t.Fatal("architecture verification and runtime smoke test must also run on cache hits")
	}
	presubmit := workflowJob(t, workflowJobs(t, loadWorkflow(t, "agentio-e2e-presubmit.yml")), "build-ztunnel")
	if mapValue(t, presubmit, "with")["cache_binary"] != true {
		t.Fatal("presubmit must opt into the pinned binary cache")
	}
	publish := workflowJob(t, workflowJobs(t, loadWorkflow(t, "agentio-image.yml")), "build-ztunnel")
	if with, ok := publish["with"].(map[string]any); ok && with["cache_binary"] == true {
		t.Fatal("published candidates must build from source")
	}
}

func TestZtunnelSourceScriptsValidateAndUpdatePins(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("workflow script test requires %s", tool)
		}
	}
	oldSHA, newSHA := strings.Repeat("a", 40), strings.Repeat("b", 40)
	other := map[string]any{
		"name":       "CNI_IMAGE",
		"repository": "example/cni",
		"digest":     "sha256:" + strings.Repeat("c", 64),
	}
	source := func(sha string) map[string]any {
		return map[string]any{"name": "ZTUNNEL_REPO_SHA", "repoName": "openkruise/ztunnel", "lastStableSHA": sha}
	}
	resolve := stringValue(
		t,
		workflowStep(t, loadWorkflow(t, "agentio-ztunnel.yml"), "build", "Resolve pinned ztunnel source"),
		"run",
	)
	update := stringValue(
		t,
		workflowStep(t, loadWorkflow(t, "sync-ztunnel-deps.yml"), "sync", "Update pinned ztunnel source"),
		"run",
	)
	for _, tc := range []struct {
		name       string
		pins       []map[string]any
		remoteSHA  string
		remoteRef  string
		resolveErr bool
		updateErr  bool
	}{
		{name: "update master despite different default branch", pins: []map[string]any{source(oldSHA), other}, remoteSHA: newSHA},
		{name: "unchanged", pins: []map[string]any{source(newSHA), other}, remoteSHA: newSHA},
		{name: "missing source", pins: []map[string]any{other}, resolveErr: true, updateErr: true},
		{name: "duplicate source", pins: []map[string]any{source(oldSHA), source(oldSHA)}, resolveErr: true, updateErr: true},
		{name: "mutable pin", pins: []map[string]any{source("release-0.1")}, resolveErr: true, updateErr: true},
		{name: "invalid repository", pins: []map[string]any{{"name": "ZTUNNEL_REPO_SHA", "repoName": "bad/repo/extra", "lastStableSHA": oldSHA}}, resolveErr: true, updateErr: true},
		{name: "missing remote", pins: []map[string]any{source(oldSHA)}, updateErr: true},
		{name: "invalid remote sha", pins: []map[string]any{source(oldSHA)}, remoteSHA: "latest", updateErr: true},
		{name: "invalid remote branch", pins: []map[string]any{source(oldSHA)}, remoteSHA: newSHA, remoteRef: "refs/heads/bad branch", updateErr: true},
		{name: "master missing with another branch present", pins: []map[string]any{source(oldSHA)}, remoteSHA: newSHA, remoteRef: "refs/heads/release-0.1", updateErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			deps := filepath.Join(dir, "agentio.deps")
			before, err := json.Marshal(tc.pins)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, deps, string(before), 0o600)
			if tc.remoteRef == "" {
				tc.remoteRef = "refs/heads/master"
			}
			remote := "ref: refs/heads/release-0.1\tHEAD\n" + oldSHA + "\tHEAD\n" + tc.remoteSHA + "\t" + tc.remoteRef + "\n"
			writeTestFile(t, filepath.Join(dir, "remote"), remote, 0o600)
			realGit, err := exec.LookPath("git")
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(dir, "git"), `#!/bin/bash
if [[ $1 == ls-remote ]]; then
  [[ "${@: -1}" == refs/heads/master ]] || exit 1
  cat "$TEST_REMOTE_HEAD"
else
  exec "$TEST_REAL_GIT" "$@"
fi
`, 0o700)
			for _, script := range []struct {
				name, body string
				wantErr    bool
			}{{"resolve", resolve, tc.resolveErr}, {"update", update, tc.updateErr}} {
				cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", script.body)
				cmd.Dir = dir
				cmd.Env = append(
					os.Environ(),
					"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
					"GITHUB_OUTPUT="+filepath.Join(
						dir,
						script.name+"-output",
					),
					"TEST_REAL_GIT="+realGit,
					"TEST_REMOTE_HEAD="+filepath.Join(dir, "remote"),
				)
				out, err := cmd.CombinedOutput()
				if (err != nil) != script.wantErr {
					t.Fatalf("%s error = %v, wantErr %v; output: %s", script.name, err, script.wantErr, out)
				}
				if script.name == "update" && !script.wantErr {
					output, err := os.ReadFile(filepath.Join(dir, "update-output"))
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(output), "source_branch=master\n") {
						t.Fatalf("update did not report master as its source: %s", output)
					}
				}
			}
			after, err := os.ReadFile(deps)
			if err != nil {
				t.Fatal(err)
			}
			if tc.updateErr || tc.name == "unchanged" {
				if string(before) != string(after) {
					t.Fatal("failed or unchanged update modified the dependency file")
				}
				return
			}
			var got []map[string]any
			if err := json.Unmarshal(after, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, []map[string]any{source(newSHA), other}) {
				t.Fatalf("update must change only the ztunnel SHA; got %s", after)
			}
		})
	}
}

func workflowStep(t *testing.T, workflow map[string]any, job, name string) map[string]any {
	t.Helper()
	steps := listValue(t, workflowJob(t, workflowJobs(t, workflow), job), "steps")
	i := namedStepIndex(t, steps, name)
	if i < 0 {
		t.Fatalf("missing %s/%s", job, name)
	}
	return steps[i].(map[string]any)
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
