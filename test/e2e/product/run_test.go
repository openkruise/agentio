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

package product

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/command"
)

type recordingCommands struct {
	requests []command.Request
	action   string
	err      error
}

func (r *recordingCommands) Run(_ context.Context, req command.Request) (command.Result, error) {
	r.requests = append(r.requests, req)
	if r.err != nil {
		return command.Result{}, r.err
	}
	if r.action != "" {
		data, err := json.Marshal(map[string]string{"Action": r.action, "Test": "TestSelected"})
		if err != nil {
			return command.Result{}, err
		}
		for _, b := range append(data, '\n') {
			if _, err := req.Stdout.Write([]byte{b}); err != nil {
				return command.Result{}, err
			}
		}
	}
	return command.Result{}, nil
}

func runnerPlan() Plan {
	return Plan{Include: []Group{{ID: "ambient-iptables", Profile: "ambient", Backend: "iptables", GatewayDataplane: "envoy", Invocations: []Invocation{
		{Suite: "trafficpolicy", Package: "./suites/trafficpolicy", Tests: []string{"TestSelected"}},
	}}}}
}

func TestRunnerUsesExactTestsAndEnvironment(t *testing.T) {
	commands := &recordingCommands{action: "pass"}
	env := []string{"AGENTIO_E2E=0", "AGENTIO_E2E_PROFILE=sidecar", "AGENTIO_E2E_FIREWALL_BACKEND=auto", "AGENTIO_E2E_PROFILE=sidecar", "IMAGE=pinned"}
	r := Runner{Commands: commands, Root: "module", Env: env, Output: io.Discard, Timeout: time.Minute}
	if err := r.Run(t.Context(), runnerPlan()); err != nil {
		t.Fatal(err)
	}
	if len(commands.requests) != 1 {
		t.Fatal(commands.requests)
	}
	req := commands.requests[0]
	if req.Dir != "module" || !reflect.DeepEqual(req.Args, []string{"test", "-json", "-p", "1", "./suites/trafficpolicy", "-run", "^(TestSelected)$", "-count=1", "-timeout=1m0s"}) {
		t.Fatal(req)
	}
	for key, want := range map[string]string{"AGENTIO_E2E": "1", "AGENTIO_E2E_PROFILE": "ambient", "AGENTIO_E2E_FIREWALL_BACKEND": "iptables", "AGENTIO_E2E_ENABLE_FIREWALL_RULES": "true", "IMAGE": "pinned"} {
		if got := envValue(req.Env, key); got != want {
			t.Fatalf("%s=%s", key, got)
		}
		count := 0
		for _, entry := range req.Env {
			if strings.HasPrefix(entry, key+"=") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("duplicate %s", key)
		}
	}
	pattern := regexp.MustCompile(testPattern([]string{"TestSelected", "TestLiteral[case]"}))
	if !pattern.MatchString("TestSelected") || !pattern.MatchString("TestLiteral[case]") || pattern.MatchString("TestSelectedExtra") {
		t.Fatal("test filter is not exact")
	}
}

func TestRunnerRejectsFalseSuccessAndStopsTheGroup(t *testing.T) {
	for _, action := range []string{"", "skip", "fail"} {
		t.Run("completion="+action, func(t *testing.T) {
			commands := &recordingCommands{action: action}
			plan := runnerPlan()
			plan.Include[0].Invocations = append(plan.Include[0].Invocations, plan.Include[0].Invocations[0])
			err := (Runner{Commands: commands, Output: io.Discard, Timeout: time.Minute}).Run(t.Context(), plan)
			if err == nil || len(commands.requests) != 1 {
				t.Fatalf("error=%v requests=%d", err, len(commands.requests))
			}
		})
	}
	commands := &recordingCommands{err: errors.New("compile failed")}
	if err := (Runner{Commands: commands, Output: io.Discard, Timeout: time.Minute}).Run(t.Context(), runnerPlan()); err == nil {
		t.Fatal("command failure ignored")
	}
}

func TestEventValidation(t *testing.T) {
	for _, tc := range []struct{ name, stream string }{
		{"duplicate", "{\"Action\":\"pass\",\"Test\":\"TestSelected\"}\n{\"Action\":\"pass\",\"Test\":\"TestSelected\"}\n"},
		{"unplanned", "{\"Action\":\"pass\",\"Test\":\"TestExtra\"}\n"},
		{"truncated", "{\"Action\":\"pass\""},
		{"invalid-json", "not JSON\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := &testEvents{output: io.Discard, completed: map[string]string{}}
			_, err := events.Write([]byte(tc.stream))
			if err == nil {
				err = events.verify([]string{"TestSelected"})
			}
			if err == nil {
				t.Fatal("invalid event stream accepted")
			}
		})
	}
}

func TestRunnerAgainstGoTest(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{
		"go.mod": "module runnerfixture\n\ngo 1.26.8\n",
		"fixture_test.go": `package runnerfixture
import("os";"testing")
func TestSelected(t *testing.T) {
 if os.Getenv("AGENTIO_E2E")!="1" || os.Getenv("AGENTIO_E2E_PROFILE")!="ambient" || os.Getenv("AGENTIO_E2E_FIREWALL_BACKEND")!="iptables" { t.Fatal("missing execution environment") }
}
func TestSelectedExtra(t *testing.T) {t.Fatal("unselected test ran")}
`,
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	plan := runnerPlan()
	plan.Include[0].Invocations[0].Package = "."
	var output bytes.Buffer
	r := Runner{Commands: command.Runner{}, Root: root, Env: os.Environ(), Output: &output, Timeout: time.Minute}
	if err := r.Run(t.Context(), plan); err != nil {
		t.Fatalf("%v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "PASS: TestSelected") {
		t.Fatal(output.String())
	}
	plan.Include[0].Invocations[0].Tests = []string{"TestMissing"}
	if err := r.Run(t.Context(), plan); err == nil {
		t.Fatal("go test's no-tests success was accepted")
	}
}

func envValue(env []string, key string) string {
	value := ""
	for _, entry := range env {
		if candidate, found := strings.CutPrefix(entry, key+"="); found {
			value = candidate
		}
	}
	return value
}
