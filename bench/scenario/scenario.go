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

// Package scenario runs reproducible, assertion-based test programs and preserves
// their evidence. Test programs own their setup, workload, assertions and teardown.
package scenario

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Suite is both the execution plan and the replayable artifact saved by Run.
// An empty Image executes Command on the host; otherwise it executes in Docker.
// Commands must return nonzero on any failed assertion or cleanup failure.
// The output directory is provided as SCENARIO_ARTIFACTS, mounted at /artifacts
// in containers. Command arguments and Env values may contain {artifacts} for this location.
// Input mounts are read-only; results belong in the artifacts directory.
type Suite struct {
	Name     string            `json:"name"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Cases    []Case            `json:"cases"`
}

// Case runs one test program; SuccessMarker can reject empty or skipped test selections.
type Case struct {
	Name          string            `json:"name"`
	Image         string            `json:"image,omitempty"`
	Command       []string          `json:"command"`
	Env           map[string]string `json:"env,omitempty"`
	Mounts        []Mount           `json:"mounts,omitempty"`
	Timeout       string            `json:"timeout"`
	Memory        string            `json:"memory,omitempty"`
	Dir           string            `json:"dir,omitempty"`
	SuccessMarker string            `json:"success_marker,omitempty"`
}

// Mount exposes a host input read-only inside a container.
type Mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// Result records the outcome after execution and cleanup.
type Result struct {
	Name    string    `json:"name"`
	Started time.Time `json:"started"`
	Seconds float64   `json:"seconds"`
	Passed  bool      `json:"passed"`
	Error   string    `json:"error,omitempty"`
}

// Validate rejects invalid plans before any test program starts.
func Validate(s Suite) error {
	if len(s.Cases) == 0 {
		return errors.New("suite has no cases")
	}
	seen := map[string]bool{}
	for _, c := range s.Cases {
		if c.Name == "" || c.Name == "." || c.Name == ".." || strings.ContainsAny(c.Name, "/\\") || seen[c.Name] {
			return fmt.Errorf("invalid or duplicate case name %q", c.Name)
		}
		seen[c.Name] = true
		if len(c.Command) == 0 {
			return fmt.Errorf("%s: command required", c.Name)
		}
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("%s: positive timeout required", c.Name)
		}
		if c.Image == "" && (len(c.Mounts) > 0 || c.Memory != "") {
			return fmt.Errorf("%s: mounts and memory require an image", c.Name)
		}
		for _, m := range c.Mounts {
			if !filepath.IsAbs(m.Source) || !strings.HasPrefix(m.Target, "/") {
				return fmt.Errorf("%s: mount paths must be absolute", c.Name)
			}
		}
	}
	return nil
}

func save(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// Run continues after individual case failures, but stops on parent cancellation.
// Output must not exist: previous evidence is never silently overwritten.
func Run(ctx context.Context, s Suite, output string, log io.Writer) ([]Result, error) {
	if err := Validate(s); err != nil {
		return nil, err
	}
	output, err := filepath.Abs(output)
	if err != nil {
		return nil, err
	}
	for i := range s.Cases {
		if s.Cases[i].Image == "" {
			dir := s.Cases[i].Dir
			if dir == "" {
				dir = "."
			}
			s.Cases[i].Dir, err = filepath.Abs(dir)
			if err != nil {
				return nil, err
			}
		}
	}
	if err = os.Mkdir(output, 0755); err != nil {
		return nil, err
	}
	if err = save(filepath.Join(output, "suite.json"), s); err != nil {
		return nil, err
	}
	var results []Result
	var failures error
	for _, c := range s.Cases {
		if ctx.Err() != nil {
			failures = errors.Join(failures, ctx.Err())
			break
		}
		r := runCase(ctx, c, filepath.Join(output, c.Name), log)
		results = append(results, r)
		if !r.Passed {
			failures = errors.Join(failures, fmt.Errorf("%s: %s", r.Name, r.Error))
		}
		if err = save(filepath.Join(output, "results.json"), results); err != nil {
			return results, errors.Join(failures, err)
		}
	}
	return results, failures
}

func runCase(parent context.Context, c Case, dir string, log io.Writer) (r Result) {
	r.Name = c.Name
	r.Started = time.Now()
	defer func() { r.Seconds = time.Since(r.Started).Seconds() }()
	err := os.Mkdir(dir, 0777)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	// Candidate images commonly use an unprivileged user.
	if err = os.Chmod(dir, 0777); err != nil {
		r.Error = err.Error()
		return r
	}
	file, err := os.Create(filepath.Join(dir, "test.log"))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer func() {
		if err := file.Close(); err != nil {
			r.Passed = false
			r.Error = errors.Join(errors.New(r.Error), err).Error()
		}
	}()
	timeout, _ := time.ParseDuration(c.Timeout) //nolint:errcheck // Validated before starting any cases.
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if _, err = fmt.Fprintf(log, "START %s (%s)\n", c.Name, c.Timeout); err != nil {
		r.Error = err.Error()
		return r
	}
	if c.Image == "" {
		err = runHost(ctx, c, dir, file)
	} else {
		err = runDocker(ctx, c, dir, file)
	}
	if err == nil && c.SuccessMarker != "" {
		var data []byte
		data, err = os.ReadFile(file.Name())
		if err == nil && !strings.Contains(string(data), c.SuccessMarker) {
			err = fmt.Errorf("missing success marker %q (empty or skipped test selection)", c.SuccessMarker)
		}
	}
	if err != nil {
		r.Error = err.Error()
	} else {
		r.Passed = true
	}
	_, logErr := fmt.Fprintf(
		log,
		"END %s passed=%t elapsed=%s error=%s\n",
		c.Name,
		r.Passed,
		time.Since(r.Started).Round(time.Millisecond),
		r.Error,
	)
	if logErr != nil {
		r.Passed = false
		r.Error = errors.Join(err, logErr).Error()
	}
	return r
}

func runHost(ctx context.Context, c Case, dir string, log io.Writer) error {
	command := expandCommand(c.Command, dir)
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = c.Dir
	// A Go test may start an origin or proxy; kill its process group on timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.Env = append(os.Environ(), "SCENARIO_ARTIFACTS="+dir)
	for k, v := range c.Env {
		cmd.Env = append(cmd.Env, k+"="+strings.ReplaceAll(v, "{artifacts}", dir))
	}
	err := cmd.Run()
	// Also stop owned helpers when a test program exits without running its cleanup.
	if cmd.Process != nil {
		cleanupErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(cleanupErr, syscall.ESRCH) {
			cleanupErr = nil
		}
		err = errors.Join(err, cleanupErr)
	}
	return errors.Join(err, ctx.Err())
}

func runDocker(ctx context.Context, c Case, dir string, log io.Writer) (err error) {
	command := expandCommand(c.Command, "/artifacts")
	name := fmt.Sprintf("agentio-scenario-%d-%d", os.Getpid(), time.Now().UnixNano())
	args := []string{
		"create",
		"--name",
		name,
		"--ulimit",
		"nofile=131072:131072",
		"--mount",
		"type=bind,src=" + dir + ",dst=/artifacts",
		"-e",
		"SCENARIO_ARTIFACTS=/artifacts",
	}
	if c.Memory != "" {
		args = append(args, "--memory", c.Memory, "--memory-swap", c.Memory)
	}
	if c.Dir != "" {
		args = append(args, "--workdir", c.Dir)
	}
	for _, m := range c.Mounts {
		args = append(args, "--mount", "type=bind,src="+m.Source+",dst="+m.Target+",readonly")
	}
	for k, v := range c.Env {
		args = append(args, "-e", k+"="+strings.ReplaceAll(v, "{artifacts}", "/artifacts"))
	}
	args = append(args, "--entrypoint", command[0], c.Image)
	args = append(args, command[1:]...)
	created := exec.CommandContext(ctx, "docker", args...)
	created.Stdout = log
	created.Stderr = log
	if err = created.Run(); err != nil {
		return err
	}
	// Even on timeout, record container state and remove only our own container.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		state, stateErr := exec.CommandContext(cleanup, "docker", "inspect", name).Output()
		err = errors.Join(err, stateErr, os.WriteFile(filepath.Join(dir, "container.json"), state, 0600))
		removed, removeErr := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput()
		if removeErr != nil {
			err = errors.Join(err, fmt.Errorf("container cleanup: %w: %s", removeErr, removed))
		}
	}()
	cmd := exec.CommandContext(ctx, "docker", "start", "--attach", name)
	cmd.Stdout = log
	cmd.Stderr = log
	err = errors.Join(cmd.Run(), ctx.Err())
	// docker start --attach may return zero even when the container failed.
	state, stateErr := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", name).
		Output()
	err = errors.Join(err, stateErr)
	if stateErr == nil && strings.TrimSpace(string(state)) != "0 false" {
		err = errors.Join(err, fmt.Errorf("container exit/OOM: %s", strings.TrimSpace(string(state))))
	}
	return err
}

func expandCommand(command []string, dir string) []string {
	args := make([]string, len(command))
	for i, arg := range command {
		args[i] = strings.ReplaceAll(arg, "{artifacts}", dir)
	}
	return args
}
