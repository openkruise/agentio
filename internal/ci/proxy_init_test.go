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
	"strings"
	"testing"
)

func TestProxyInitUsesBuiltCandidate(t *testing.T) {
	presubmit := loadWorkflow(t, "agentio-e2e-presubmit.yml")
	build := workflowStep(t, presubmit, "build-candidates", "Build proxy-init candidate")
	if mapValue(t, build, "with")["file"] != "docker/Dockerfile.proxy-init" {
		t.Fatal("presubmit must build proxy-init from this repository")
	}
	archive := stringValue(
		t,
		workflowStep(t, presubmit, "build-candidates", "Build repository-owned and test fixture candidates"),
		"run",
	)
	if !strings.Contains(archive, `"agentio-e2e.local/proxy-init:${tag}"`) {
		t.Fatal("candidate archive must include the built proxy-init")
	}
	publish := stringValue(
		t,
		workflowStep(t, loadWorkflow(t, "agentio-e2e.yml"), "product-e2e", "Publish candidates to a local registry"),
		"run",
	)
	if !strings.Contains(publish, "AGENTIO_E2E_PROXY_INIT_IMAGE=$digest_ref") {
		t.Fatal("E2E must use proxy-init from its candidate archive")
	}
	release := loadWorkflow(t, "agentio-release.yml")
	want := "${{ needs.validate-release.outputs.proxy_init_image || needs.build-candidates.outputs.proxy_init_image }}"
	for _, job := range []string{"product-e2e", "epe-e2e"} {
		if got := mapValue(t, workflowJob(t, workflowJobs(t, release), job), "with")["proxy_init_image"]; got != want {
			t.Fatalf("%s proxy-init = %v, want the selected candidate", job, got)
		}
	}
}
