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
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := command(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func command(ctx context.Context, args []string) error {
	if len(args) == 2 && args[0] == "analyze" {
		return analyze(args[1], os.Stdout)
	}
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: connect-bench run -output DIR [flags] | analyze RESULTS.jsonl")
	}
	c, err := parseConfig(args[1:], os.Stderr)
	if err != nil {
		return err
	}
	return run(ctx, c, os.Stdout)
}

//nolint:gocyclo,funlen // Keep run artifact creation, failure recording, and cleanup in one scope.
func run(ctx context.Context, c config, out io.Writer) (result error) {
	if err := os.MkdirAll(c.Output, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(c.Output)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("output directory must be empty: %s", c.Output)
	}
	defer func() {
		if result != nil {
			result = errors.Join(
				result,
				os.WriteFile(filepath.Join(c.Output, "failure.txt"), []byte(result.Error()+"\n"), 0600),
			)
		}
	}()
	cpus, err := physicalCPUs()
	if err != nil {
		return err
	}
	version, err := exec.CommandContext(ctx, c.Envoy, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("Envoy version: %w: %s", err, version)
	}
	ticksText, err := exec.CommandContext(ctx, "getconf", "CLK_TCK").Output()
	if err != nil {
		return err
	}
	ticks, err := strconv.ParseFloat(strings.TrimSpace(string(ticksText)), 64)
	if err != nil || ticks <= 0 {
		return fmt.Errorf("invalid CLK_TCK %q", ticksText)
	}
	cpuInfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return err
	}
	model := ""
	for line := range strings.SplitSeq(string(cpuInfo), "\n") {
		if strings.HasPrefix(line, "model name") {
			model = line
			break
		}
	}
	rows, err := os.OpenFile(filepath.Join(c.Output, "results.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, rows.Close()) }()
	encoder := json.NewEncoder(io.MultiWriter(rows, out))
	balance := "default"
	if c.Suite == "capacity" || c.Suite == "overhead" || c.Suite == "isolation" || c.Suite == "buckets" ||
		c.Suite == "fairness" {
		balance = "exact"
	}
	env := map[string]any{
		"event":          "environment",
		"schema_version": 2,
		"affinity":       map[string]any{"envoy": cpus[:2], "load": cpus[2:6], "origin": cpus[6:]},
		"envoy": strings.TrimSpace(
			string(version),
		),
		"cpu_model":               model,
		"warmup_seconds":          c.Warmup.Seconds(),
		"measurement":             c.Duration.String(),
		"connection_balance":      balance,
		"connections":             c.Connections,
		"suite":                   c.Suite,
		"concurrency_limit":       c.ConcurrencyLimit,
		"ticks":                   ticks,
		"module":                  c.Module,
		"shared_bytes_per_second": c.SharedRate,
		"progress_interval":       c.ProgressInterval.String(),
	}
	if c.Suite == "buckets" {
		env["resident_buckets"], env["resident_mode"] = c.ResidentBuckets, c.ResidentMode
	}
	if err := encoder.Encode(env); err != nil {
		return err
	}
	configBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.Output, "config.json"), configBytes, 0600); err != nil {
		return err
	}
	cases := schedule(c)
	for i, s := range cases {
		row, err := runCase(ctx, c, s, i+1, cpus, ticks)
		if err != nil {
			return fmt.Errorf("case %d %s/%d/%s: %w", i+1, s.Mode, s.Streams, s.Direction, err)
		}
		row["event"] = "result"
		row["mode"] = s.Mode
		row["repeat"] = s.Repeat
		row["case"] = i + 1
		row["total"] = len(cases)
		row["concurrency_limit"] = c.ConcurrencyLimit
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

//nolint:funlen // Keep each process start beside its deferred cleanup.
func runCase(
	ctx context.Context,
	c config,
	s scenario,
	index int,
	cpus []int,
	ticks float64,
) (row map[string]any, result error) {
	if c.Suite == "buckets" {
		// Reusing one origin tuple carries TIME_WAIT pressure from earlier churn cases.
		c.BasePort += 4 * (index - 1)
	}
	root := filepath.Join(c.Output, fmt.Sprintf("%03d-%s-%d-%s-r%d", index, s.Mode, s.Streams, s.Direction, s.Repeat))
	if err := os.Mkdir(root, 0700); err != nil {
		return nil, err
	}
	data, err := envoyConfig(c, s)
	if err != nil {
		return nil, err
	}
	var reloadPath string
	if c.Reload {
		reloadPath, err = filepath.Abs(filepath.Join(root, "bandwidth-ecds.json"))
		if err != nil {
			return nil, err
		}
		data, err = discoverBandwidth(data, reloadPath)
		if err != nil {
			return nil, err
		}
	}
	path, err := filepath.Abs(filepath.Join(root, "envoy.json"))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	originLog, err := os.Create(filepath.Join(root, "origin.log"))
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, originLog.Close()) }()
	originAddr := fmt.Sprintf("127.0.0.1:%d", c.BasePort)
	statsAddr := fmt.Sprintf("127.0.0.1:%d", c.BasePort+3)
	origin, err := startProcess(
		cpus[6:],
		c.Load,
		[]string{"origin", "-origin=" + originAddr, "-stats=" + statsAddr},
		[]string{"GOMAXPROCS=2"},
		originLog,
	)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, origin.stop()) }()
	for _, addr := range []string{originAddr, statsAddr} {
		if err := origin.ready(ctx, addr); err != nil {
			return nil, err
		}
	}
	envoyLog, err := os.Create(filepath.Join(root, "envoy.log"))
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, envoyLog.Close()) }()
	envoy, err := startProcess(
		cpus[:2],
		c.Envoy,
		[]string{"-c", path, "--concurrency", "2", "--disable-hot-restart", "--log-level", "error"},
		nil,
		envoyLog,
	)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, envoy.stop()) }()
	target := fmt.Sprintf("127.0.0.1:%d", c.BasePort+2)
	if err := envoy.ready(ctx, target); err != nil {
		return nil, err
	}
	loadTimeout := c.Duration + c.Warmup + 45*time.Second
	if c.Suite == "buckets" {
		loadTimeout += 10*time.Minute + c.RecoveryWait
	}
	loadCtx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()
	cmd := pinnedCommand(
		loadCtx,
		cpus[2:6],
		c.Load,
		fmt.Sprintf("-streams=%d", s.Streams),
		fmt.Sprintf("-connections=%d", c.Connections),
		"-direction="+s.Direction,
		fmt.Sprintf(
			"-distinct=%t",
			s.Mode == "distinct" || s.Mode == "distinct-high" || s.Mode == "combined" || s.Mode == "concurrency",
		),
		fmt.Sprintf("-fast-stream=%t", s.Mode == "isolation"),
		"-duration="+c.Duration.String(),
		"-warmup="+c.Warmup.String(),
		"-progress-interval="+c.ProgressInterval.String(),
		"-target="+target,
		"-stats="+statsAddr,
		fmt.Sprintf(
			"-envoy-pid=%d",
			envoy.cmd.Process.Pid,
		),
		fmt.Sprintf("-origin-pid=%d", origin.cmd.Process.Pid),
		fmt.Sprintf("-ticks=%g", ticks),
	)
	if c.Suite == "buckets" {
		cmd.Args = append(cmd.Args,
			fmt.Sprintf("-probe-requests=%d", c.ProbeRequests),
			fmt.Sprintf("-resident-buckets=%d", c.ResidentBuckets), "-resident-mode="+c.ResidentMode,
			fmt.Sprintf("-debt-bytes=%d", c.DebtBytes), "-recovery-wait="+c.RecoveryWait.String(),
			fmt.Sprintf("-admin=127.0.0.1:%d", c.BasePort+1), "-setup-timeout=5m")
	}
	if c.Reload {
		cmd.Args = append(cmd.Args, "-reload-path="+reloadPath)
	}
	cmd.Env = append(os.Environ(), "GOMAXPROCS=4")
	loadLog, err := os.Create(filepath.Join(root, "load.log"))
	if err != nil {
		return nil, err
	}
	cmd.Stderr = loadLog
	output, runErr := cmd.Output()
	if err := errors.Join(
		runErr,
		loadLog.Close(),
		os.WriteFile(filepath.Join(root, "result.json"), output, 0600),
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(output, &row); err != nil {
		return nil, err
	}
	if row["errors"] != float64(0) || row["h2_connections"] != float64(min(s.Streams, c.Connections)) {
		return nil, fmt.Errorf("invalid measurement: %s", output)
	}
	return row, nil
}
