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

package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/artifacts"
)

func TestLiveOutputIsNotTruncatedWithArtifactCapture(t *testing.T) {
	var output bytes.Buffer
	value := strings.Repeat("complete-stream-", 40)
	req := helperRequest("print", value)
	req.Stdout = &output
	result, err := (Runner{MaxOutputBytes: 16}).Run(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != value {
		t.Fatal("live output was truncated")
	}
	if len(result.Stdout) >= len(value) {
		t.Fatal("artifact capture is no longer bounded")
	}
}

func TestRunnerRedactsCommandAndOutput(t *testing.T) {
	store := newStore(t)
	r := Runner{Artifacts: store, Redactor: NewRedactor([]string{"hunter2"})}
	res, err := r.Run(context.Background(), helperRequest("print", "hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "hunter2") {
		t.Fatalf("result leaked secret: %q", res.Stdout)
	}
	data, err := os.ReadFile(store.Path("commands.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hunter2") {
		t.Fatalf("command artifact leaked secret: %s", data)
	}
	if !strings.Contains(string(data), "<redacted>") {
		t.Fatalf("command artifact did not record redaction: %s", data)
	}
}

func TestRunnerInvokesExecutableWithoutShellExpansion(t *testing.T) {
	res, err := newRunner(t).Run(context.Background(), helperRequest("print", "$(printf exploited)"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stdout) != "$(printf exploited)" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestRunnerCancellationKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := newRunner(t).Run(ctx, helperRequest("spawn-child", pidFile))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read child pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for processExists(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processExists(pid) {
		t.Fatalf("child process %d still exists after cancellation", pid)
	}
}

func TestRunnerReturnsExitCodeAndRedactedFailure(t *testing.T) {
	res, err := newRunner(t).Run(context.Background(), helperRequest("exit", "7", "private"))
	if err == nil {
		t.Fatal("Run succeeded")
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d", res.ExitCode)
	}
	if !strings.Contains(res.Stderr, "private") {
		t.Fatalf("stderr = %q", res.Stderr)
	}
}

func TestCommandHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_E2E_COMMAND_HELPER") != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		os.Exit(90)
	}
	args := os.Args[separator+1:]
	switch args[0] {
	case "print":
		fmt.Print(args[1])
	case "exit":
		fmt.Fprint(os.Stderr, args[2])
		code, err := strconv.Atoi(args[1])
		if err != nil {
			os.Exit(94)
		}
		os.Exit(code)
	case "spawn-child":
		child := exec.Command("sleep", "30")
		if err := child.Start(); err != nil {
			os.Exit(91)
		}
		if err := os.WriteFile(args[1], []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			os.Exit(92)
		}
		if err := child.Wait(); err != nil {
			os.Exit(95)
		}
	default:
		os.Exit(93)
	}
	os.Exit(0)
}

func helperRequest(args ...string) Request {
	return Request{
		Name: os.Args[0],
		Args: append([]string{"-test.run=TestCommandHelperProcess", "--"}, args...),
		Env:  append(os.Environ(), "GO_WANT_E2E_COMMAND_HELPER=1"),
	}
}

func newStore(t *testing.T) *artifacts.Store {
	t.Helper()
	store, err := artifacts.New(t.TempDir(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newRunner(t *testing.T) Runner {
	t.Helper()
	return Runner{Artifacts: newStore(t), Redactor: NewRedactor(nil)}
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || !errors.Is(err, syscall.ESRCH)
}
