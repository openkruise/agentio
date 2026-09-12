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

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkruise/agentio/test/e2e/product"
)

func cleanSelection(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AGENTIO_E2E_SUITES", "AGENTIO_E2E_PROFILE", "AGENTIO_E2E_FIREWALL_BACKEND", "AGENTIO_E2E_GROUP", "E2E_CONFIG", "E2E_CLUSTER_MODE", "E2E_CLUSTER_REUSE", "E2E_CLUSTER_CONTEXT", "AGENTIO_E2E_REUSE"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPlanCLIProducesMatrixAndArtifact(t *testing.T) {
	cleanSelection(t)
	var output bytes.Buffer
	path := filepath.Join(t.TempDir(), "plan.json")
	err := execute(t.Context(), []string{"plan", "--root", "../..", "--group", "sidecar-auto", "--format=json", "--out", path}, &output, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var plan product.Plan
	if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Include) != 1 || len(plan.Include[0].Invocations) != 5 {
		t.Fatalf("plan=%+v", plan)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestCLIRejectsEmptyRunsBeforeSetup(t *testing.T) {
	cleanSelection(t)
	artifacts := t.TempDir()
	t.Setenv("E2E_ARTIFACTS_DIR", artifacts)
	err := execute(t.Context(), []string{"run", "--root", "../..", "--tests", "^TestMissing$"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no tests") {
		t.Fatalf("error=%v", err)
	}
	entries, err := os.ReadDir(artifacts)
	if err != nil || len(entries) != 0 {
		t.Fatal("empty plan started setup", err)
	}
}

func TestCLIRespectsBorrowedClusterFromConfigurationFile(t *testing.T) {
	cleanSelection(t)
	path := filepath.Join(t.TempDir(), "framework.yaml")
	if err := os.WriteFile(path, []byte("cluster:\n  mode: kind\n  name: borrowed\n  reuse: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("E2E_CONFIG", path)
	err := execute(t.Context(), []string{"run", "--root", "../.."}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "select one group") {
		t.Fatalf("error=%v", err)
	}
}
