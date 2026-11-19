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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTrustPackagePin(t *testing.T) {
	data, err := os.ReadFile("../../agentio.deps")
	if err != nil {
		t.Fatal(err)
	}
	var pins []struct {
		Name   string
		URL    string
		Digest string
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	datedURL := regexp.MustCompile(`^https://curl\.se/ca/cacert-\d{4}-\d{2}-\d{2}\.pem$`)
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	count := 0
	for _, pin := range pins {
		if pin.Name != "PUBLIC_CA_BUNDLE" {
			continue
		}
		count++
		if !datedURL.MatchString(pin.URL) || !digest.MatchString(pin.Digest) {
			t.Fatalf("invalid public CA snapshot pin: %+v", pin)
		}
		want := fmt.Sprintf("ADD --checksum=%s %s /tmp/\n", pin.Digest, pin.URL)
		if !strings.Contains(string(dockerfile), want) {
			t.Fatalf("Dockerfile public CA pin diverges from agentio.deps, want %s", want)
		}
	}
	if count != 1 {
		t.Fatalf("expected one public CA bundle pin, got %d", count)
	}
	if !strings.Contains(
		string(dockerfile),
		"COPY --from=builder /out/cert-manager-package-debian.json /usr/local/share/agentio/trust-package/",
	) {
		t.Fatal("Agentiod image must contain the public CA package at its configured path")
	}
	if strings.Contains(string(dockerfile), "ENV AGENTIO_CLIENT_TRUST_PACKAGE_PATH=") {
		t.Fatal("the public CA package default belongs in Go configuration, not the image environment")
	}
}

func TestTrustPackageUpdateSelectsSnapshotsAndKeepsPinsTogether(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "sed", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("workflow script test requires %s", tool)
		}
	}
	w := loadWorkflow(t, "sync-trust-package.yml")
	script := stringValue(t, workflowStep(t, w, "sync", "Update public CA package"), "run")
	const oldURL = "https://curl.se/ca/cacert-2026-09-25.pem"
	const newURL = "https://curl.se/ca/cacert-2026-11-05.pem"
	const index = `<a href="/ca/cacert-2026-11-05.pem">new</a><a href="/ca/cacert-2026-10-20.pem">old</a>`
	const bundle = "curl's published PEM snapshot"
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(bundle)))
	oldDigest := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name     string
		index    string
		checksum string
		wantErr  bool
	}{
		{name: "new snapshot", index: index, checksum: hash},
		{name: "no snapshots", index: `<a href="/ca/cacert.pem">latest</a>`, checksum: hash, wantErr: true},
		{name: "invalid checksum", index: index, checksum: "invalid", wantErr: true},
		{name: "checksum mismatch", index: index, checksum: strings.Repeat("f", 64), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			deps := filepath.Join(dir, "agentio.deps")
			dockerfile := filepath.Join(dir, "Dockerfile")
			before := fmt.Sprintf(
				`[{"name":"PUBLIC_CA_BUNDLE","url":%q,"digest":%q},{"name":"CNI_IMAGE","digest":"untouched"}]`,
				oldURL,
				oldDigest,
			)
			oldDockerfile := fmt.Sprintf("FROM golang AS builder\nADD --checksum=%s %s /tmp/\n", oldDigest, oldURL)
			writeTestFile(t, deps, before, 0o600)
			writeTestFile(t, dockerfile, oldDockerfile, 0o600)
			writeTestFile(t, filepath.Join(dir, "curl"), `#!/bin/bash
case "$2" in
  https://curl.se/docs/caextract.html) printf '%s\n' "$TEST_INDEX" ;;
  https://curl.se/ca/cacert-2026-11-05.pem.sha256) printf '%s  cacert-2026-11-05.pem\n' "$TEST_CHECKSUM" ;;
  https://curl.se/ca/cacert-2026-11-05.pem) printf '%s' "$TEST_BUNDLE" > "$4" ;;
  *) exit 1 ;;
esac
`, 0o700)
			run := func() ([]byte, error) {
				cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", script)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
					"TEST_INDEX="+tc.index, "TEST_CHECKSUM="+tc.checksum, "TEST_BUNDLE="+bundle,
					"RUNNER_TEMP="+dir, "GITHUB_OUTPUT="+filepath.Join(dir, "output"))
				return cmd.CombinedOutput()
			}
			output, err := run()
			if (err != nil) != tc.wantErr {
				t.Fatalf("update error=%v, wantErr=%t: %s", err, tc.wantErr, output)
			}
			data, err := os.ReadFile(deps)
			if err != nil {
				t.Fatal(err)
			}
			built, err := os.ReadFile(dockerfile)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantErr {
				if string(data) != before || string(built) != oldDockerfile {
					t.Fatal("invalid upstream metadata modified the pins")
				}
				return
			}
			var pins []map[string]string
			if err := json.Unmarshal(data, &pins); err != nil {
				t.Fatal(err)
			}
			newDigest := "sha256:" + hash
			if pins[0]["url"] != newURL || pins[0]["digest"] != newDigest || pins[1]["digest"] != "untouched" {
				t.Fatalf("incorrect dependency update: %s", data)
			}
			if want := fmt.Sprintf(
				"ADD --checksum=%s %s /tmp/\n",
				newDigest,
				newURL,
			); !strings.Contains(
				string(built),
				want,
			) {
				t.Fatal("Dockerfile was not synchronized with the BOM")
			}
			if output, err := run(); err != nil {
				t.Fatalf("repeat update: %v: %s", err, output)
			}
			repeated, err := os.ReadFile(deps)
			if err != nil || string(repeated) != string(data) {
				t.Fatal("CA update is not idempotent")
			}
		})
	}
}
