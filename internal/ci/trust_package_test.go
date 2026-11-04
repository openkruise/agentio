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
	"strings"
	"testing"
)

func TestTrustPackageImagePin(t *testing.T) {
	data, err := os.ReadFile("../../agentio.deps")
	if err != nil {
		t.Fatal(err)
	}
	var pins []struct {
		Name       string
		Repository string
		Tag        string
		Digest     string
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, pin := range pins {
		if pin.Name != "TRUST_PACKAGE_IMAGE" {
			continue
		}
		count++
		want := "ARG TRUST_PACKAGE_IMAGE=" + pin.Repository + ":" + pin.Tag + "@" + pin.Digest + "\n"
		if pin.Tag == "" || !strings.Contains(string(dockerfile), want) {
			t.Fatalf("CA build image diverges from agentio.deps: want %s", want)
		}
	}
	if count != 1 {
		t.Fatalf("expected one CA package pin, got %d", count)
	}
	if !strings.Contains(
		string(dockerfile),
		"COPY --from=trust-package /debian-package/ /usr/local/share/agentio/trust-package/",
	) ||
		!strings.Contains(
			string(dockerfile),
			"ENV AGENTIO_CLIENT_TRUST_PACKAGE_PATH=/usr/local/share/agentio/trust-package/cert-manager-package-debian.json",
		) {
		t.Fatal("Agentiod image must contain the public CA package at its configured path")
	}
}

func TestTrustPackageUpdateSelectsRevisionsAndKeepsPinsTogether(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "sed", "sort"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("workflow script test requires %s", tool)
		}
	}
	w := loadWorkflow(t, "sync-trust-package.yml")
	script := stringValue(t, workflowStep(t, w, "sync", "Update public CA package"), "run")
	const repository = "quay.io/jetstack/trust-pkg-debian-bookworm"
	oldDigest, newDigest := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	for _, tc := range []struct {
		name    string
		tags    string
		digest  string
		wantErr bool
	}{
		{name: "new revision", tags: "20250419-deb12u2.9\n20250419-deb12u2.10\n20250419-deb12u1.1\nsha256-abc.sig", digest: newDigest},
		{name: "no package tags", tags: "sha256-abc.sig", digest: newDigest, wantErr: true},
		{name: "invalid digest", tags: "20250419-deb12u2.10", digest: "latest", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			before := `[{"name":"TRUST_PACKAGE_IMAGE","repository":"` + repository + `","tag":"20250419-deb12u1.1","digest":"` + oldDigest + `"},{"name":"CNI_IMAGE","digest":"untouched"}]`
			writeTestFile(t, filepath.Join(dir, "agentio.deps"), before, 0600)
			writeTestFile(
				t,
				filepath.Join(dir, "Dockerfile"),
				"ARG TRUST_PACKAGE_IMAGE="+repository+":20250419-deb12u1.1@"+oldDigest+"\nFROM ${TRUST_PACKAGE_IMAGE} AS trust-package\n",
				0600,
			)
			writeTestFile(t, filepath.Join(dir, "crane"), `#!/bin/bash
case "$1" in
  ls) printf '%s\n' "$TEST_TAGS" ;;
  digest) printf '%s\n' "$TEST_DIGEST" ;;
  *) exit 1 ;;
esac
`, 0700)
			cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"TEST_TAGS="+tc.tags, "TEST_DIGEST="+tc.digest, "GITHUB_OUTPUT="+filepath.Join(dir, "output"))
			output, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantErr {
				t.Fatalf("update error=%v, wantErr=%t: %s", err, tc.wantErr, output)
			}
			data, err := os.ReadFile(filepath.Join(dir, "agentio.deps"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantErr {
				if string(data) != before {
					t.Fatal("invalid upstream metadata modified the BOM")
				}
				return
			}
			var pins []map[string]string
			if err := json.Unmarshal(data, &pins); err != nil {
				t.Fatal(err)
			}
			if pins[0]["tag"] != "20250419-deb12u2.10" || pins[0]["digest"] != newDigest ||
				pins[1]["digest"] != "untouched" {
				t.Fatalf("incorrect dependency update: %s", data)
			}
			dockerfile, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(
				string(dockerfile),
				"ARG TRUST_PACKAGE_IMAGE="+repository+":20250419-deb12u2.10@"+newDigest+"\n",
			) {
				t.Fatal("CA build image was not synchronized with the BOM")
			}
			cmd = exec.Command("bash", "-e", "-o", "pipefail", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"TEST_TAGS="+tc.tags, "TEST_DIGEST="+tc.digest, "GITHUB_OUTPUT="+filepath.Join(dir, "output"))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("repeat update: %v: %s", err, output)
			}
			repeated, err := os.ReadFile(filepath.Join(dir, "agentio.deps"))
			if err != nil || string(repeated) != string(data) {
				t.Fatal("CA update is not idempotent")
			}
		})
	}
}
