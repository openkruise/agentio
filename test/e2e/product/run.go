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
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openkruise/agentio/test/e2e/command"
)

// Runner executes a validated plan serially using the existing Go suite lifecycle.
type Runner struct {
	Commands command.Interface
	Root     string
	Env      []string
	Output   io.Writer
	Timeout  time.Duration // Per suite, including its existing setup and cleanup.
}

// Run streams Go test output and rejects missing, skipped or unexpected tests.
func (r Runner) Run(ctx context.Context, plan Plan) error {
	if len(plan.Include) == 0 || r.Commands == nil || r.Output == nil {
		return errors.New("execution requires a nonempty plan, commands and output")
	}
	if r.Timeout <= 0 {
		return errors.New("suite timeout must be positive")
	}
	output := &synchronizedWriter{writer: r.Output}
	for _, group := range plan.Include {
		for _, invocation := range group.Invocations {
			if len(invocation.Tests) == 0 {
				return fmt.Errorf("%s/%s has no tests", group.ID, invocation.Suite)
			}
			if _, err := fmt.Fprintf(output, "\n[%s] %s: %d top-level tests\n", group.ID, invocation.Suite, len(invocation.Tests)); err != nil {
				return err
			}
			events := &testEvents{output: output, completed: map[string]string{}}
			env := withEnvironment(r.Env, map[string]string{
				"AGENTIO_E2E": "1", "AGENTIO_E2E_PROFILE": group.Profile,
				"AGENTIO_E2E_FIREWALL_BACKEND":      group.Backend,
				"AGENTIO_E2E_GATEWAY_DATAPLANE":     group.GatewayDataplane,
				"AGENTIO_E2E_ENABLE_FIREWALL_RULES": "true",
			})
			// The Go deadline includes normal cleanup. Allow the outer process
			// timeout a small margin to report timeout failures and exit normally.
			wait, cancel := context.WithTimeout(ctx, r.Timeout+time.Minute)
			_, err := r.Commands.Run(wait, command.Request{
				Name: "go", Dir: r.Root, Env: env,
				Args:   []string{"test", "-json", "-p", "1", invocation.Package, "-run", testPattern(invocation.Tests), "-count=1", "-timeout=" + r.Timeout.String()},
				Stdout: events, Stderr: output,
			})
			cancel()
			if err == nil {
				err = events.verify(invocation.Tests)
			}
			if err != nil {
				return fmt.Errorf("%s/%s: %w", group.ID, invocation.Suite, err)
			}
		}
	}
	return nil
}

func testPattern(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return "^(" + strings.Join(quoted, "|") + ")$"
}

func withEnvironment(base []string, values map[string]string) []string {
	result := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if _, overridden := values[key]; !overridden {
			result = append(result, entry)
		}
	}
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}

type testEvents struct {
	pending   bytes.Buffer
	output    io.Writer
	completed map[string]string
}

func (w *testEvents) Write(data []byte) (int, error) {
	w.pending.Write(data)
	for {
		line, _, found := bytes.Cut(w.pending.Bytes(), []byte{'\n'})
		if !found {
			break
		}
		var event struct{ Action, Test, Output string }
		if err := json.Unmarshal(line, &event); err != nil {
			return 0, fmt.Errorf("invalid go test event: %w", err)
		}
		w.pending.Next(len(line) + 1)
		if event.Output != "" {
			if _, err := io.WriteString(w.output, event.Output); err != nil {
				return 0, err
			}
		}
		if event.Test != "" && !strings.Contains(event.Test, "/") && (event.Action == "pass" || event.Action == "fail" || event.Action == "skip") {
			if _, duplicate := w.completed[event.Test]; duplicate {
				return 0, fmt.Errorf("duplicate completion for %s", event.Test)
			}
			w.completed[event.Test] = event.Action
		}
	}
	return len(data), nil
}

func (w *testEvents) verify(tests []string) error {
	if w.pending.Len() != 0 {
		return errors.New("incomplete go test event stream")
	}
	for _, test := range tests {
		if action := w.completed[test]; action != "pass" {
			return fmt.Errorf("planned test %s did not pass (completion=%q)", test, action)
		}
	}
	if len(w.completed) != len(tests) {
		return errors.New("go test executed tests outside the plan")
	}
	return nil
}

type synchronizedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *synchronizedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(data)
}
