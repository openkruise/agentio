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

package scenario

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunFailureTimeoutAndEvidence(t *testing.T) {
	output := filepath.Join(t.TempDir(), "run")
	suite := Suite{
		Name: "runner-regression",
		Cases: []Case{
			{
				Name: "pass",
				Command: []string{
					"/bin/sh",
					"-c",
					`printf '%s' "$INPUT"; printf evidence > "$1"; printf evidence > "$SCENARIO_ARTIFACTS/evidence.txt"`,
					"scenario",
					"{artifacts}/argument.txt",
				},
				Env:     map[string]string{"INPUT": "literal $(never execute)"},
				Timeout: "2s",
			},
			{Name: "fail", Command: []string{"/bin/sh", "-c", "exit 7"}, Timeout: "2s"},
			{Name: "timeout", Command: []string{"/bin/sh", "-c", "sleep 30 & wait"}, Timeout: "100ms"},
			{Name: "after-failure", Command: []string{"/bin/sh", "-c", "exit 0"}, Timeout: "2s"},
		},
	}
	results, err := Run(context.Background(), suite, output, io.Discard)
	if err == nil || len(results) != 4 {
		t.Fatalf("results=%+v error=%v", results, err)
	}
	for i, want := range []bool{true, false, false, true} {
		if results[i].Passed != want {
			t.Fatalf("result %d: %+v", i, results[i])
		}
	}
	if results[2].Seconds > 5 || !strings.Contains(results[2].Error, "deadline exceeded") {
		t.Fatalf("timeout did not terminate descendants: %+v", results[2])
	}
	for _, name := range []string{"suite.json", "results.json", "pass/test.log", "pass/evidence.txt", "pass/argument.txt"} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatal(err)
		}
	}
	log, err := os.ReadFile(filepath.Join(output, "pass/test.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(log) != "literal $(never execute)" {
		t.Fatalf("environment changed: %q", log)
	}
	if _, err = Run(context.Background(), suite, output, io.Discard); err == nil {
		t.Fatal("overwrote previous evidence")
	}
}

func TestRejectInvalidPlanBeforeExecution(t *testing.T) {
	for _, cases := range [][]Case{
		nil,
		{{Name: "../outside", Command: []string{"true"}, Timeout: "1s"}},
		{{Name: "bad-timeout", Command: []string{"true"}, Timeout: "0s"}},
		{{Name: "missing-command", Timeout: "1s"}},
		{{Name: "duplicate", Command: []string{"true"}, Timeout: "1s"}, {Name: "duplicate", Command: []string{"true"}, Timeout: "1s"}},
	} {
		output := filepath.Join(t.TempDir(), "run")
		if _, err := Run(context.Background(), Suite{Cases: cases}, output, io.Discard); err == nil {
			t.Fatalf("accepted invalid cases: %+v", cases)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("invalid suite created output: %v", err)
		}
	}
}

func TestDockerExitTimeoutAndCleanup(t *testing.T) {
	image := os.Getenv("SCENARIO_TEST_IMAGE")
	if image == "" {
		t.Skip("set SCENARIO_TEST_IMAGE to test Docker execution")
	}
	output := filepath.Join(t.TempDir(), "run")
	suite := Suite{
		Name: "docker",
		Cases: []Case{
			{Name: "pass", Image: image, Command: []string{"/bin/sh", "-c", "echo ok"}, Timeout: "30s"},
			{Name: "fail", Image: image, Command: []string{"/bin/sh", "-c", "exit 7"}, Timeout: "30s"},
			{Name: "timeout", Image: image, Command: []string{"/bin/sh", "-c", "sleep 60"}, Timeout: "2s"},
		},
	}
	started := time.Now()
	results, err := Run(context.Background(), suite, output, io.Discard)
	if err == nil || len(results) != 3 {
		t.Fatalf("results=%+v error=%v", results, err)
	}
	for i, want := range []bool{true, false, false} {
		if results[i].Passed != want {
			t.Fatalf("result %d: %+v", i, results[i])
		}
	}
	if time.Since(started) > 45*time.Second {
		t.Fatal("Docker timeout not enforced")
	}
	for _, c := range suite.Cases {
		data, err := os.ReadFile(filepath.Join(output, c.Name, "container.json"))
		if err != nil {
			t.Fatal(err)
		}
		var state []struct{ ID string }
		if err = json.Unmarshal(data, &state); err != nil {
			t.Fatal(err)
		}
		if len(state) != 1 {
			t.Fatal("missing container state")
		}
		if err = exec.Command("docker", "inspect", state[0].ID).Run(); err == nil {
			t.Fatalf("leaked container %s", state[0].ID)
		}
	}
}

func TestSuccessMarkerRejectsEmptySelection(t *testing.T) {
	suite := Suite{
		Name: "markers",
		Cases: []Case{
			{
				Name:          "empty",
				Command:       []string{"/bin/sh", "-c", "echo 'no tests to run'"},
				Timeout:       "2s",
				SuccessMarker: "SCENARIO_COMPLETED",
			},
			{
				Name:          "executed",
				Command:       []string{"/bin/sh", "-c", "echo SCENARIO_COMPLETED"},
				Timeout:       "2s",
				SuccessMarker: "SCENARIO_COMPLETED",
			},
		},
	}
	results, err := Run(context.Background(), suite, filepath.Join(t.TempDir(), "run"), io.Discard)
	if err == nil || len(results) != 2 || results[0].Passed || !results[1].Passed {
		t.Fatalf("results=%+v error=%v", results, err)
	}
}

func TestHostExitCleansBackgroundHelpers(t *testing.T) {
	output := filepath.Join(t.TempDir(), "run")
	suite := Suite{Cases: []Case{{
		Name:    "background",
		Command: []string{"/bin/sh", "-c", `(sleep 0.2; echo leaked > "$SCENARIO_ARTIFACTS/orphan") &`},
		Timeout: "2s",
	}}}
	if _, err := Run(context.Background(), suite, output, io.Discard); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(output, "background", "orphan")); !os.IsNotExist(err) {
		t.Fatalf("background helper survived: %v", err)
	}
}
