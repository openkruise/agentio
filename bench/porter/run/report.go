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
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func summarizeWorkers(workers []worker, concurrent bool) (map[string]any, error) {
	if len(workers) == 0 {
		return nil, fmt.Errorf("missing worker results")
	}
	start, finish := math.Inf(1), float64(0)
	operations, failures := 0, 0
	var loadCPU, porterCPU, rss, p99, maximum float64
	for _, w := range workers {
		v := w.Result
		start = min(start, v.StartedUnix)
		finish = max(finish, v.FinishedUnix)
		operations += v.Operations
		failures += v.Errors
		loadCPU += v.LoadCPUSeconds
		porterCPU += w.After.CPU - w.Before.CPU
		rss += w.After.RSS
		p99 = max(p99, v.P99MS)
		maximum = max(maximum, v.MaxMS)
	}
	seconds := finish - start
	if seconds <= 0 || operations <= 0 {
		return nil, fmt.Errorf("invalid worker interval or operation count")
	}
	row := map[string]any{
		"operations":                operations,
		"errors":                    failures,
		"global_qps":                float64(operations) / seconds,
		"duration_seconds":          seconds,
		"load_mean_cores":           loadCPU / seconds,
		"worst_p99_ms":              p99,
		"worst_max_ms":              maximum,
		"porter_cpu_us_per_request": nil,
		"porter_rss_mib":            rss / 1024,
	}
	if !concurrent {
		row["porter_cpu_us_per_request"] = porterCPU * 1e6 / float64(operations)
	}
	return row, nil
}

func metric(text, name string) (float64, error) {
	var total float64
	for line := range strings.SplitSeq(text, "\n") {
		if !strings.HasPrefix(line, name+" ") && !strings.HasPrefix(line, name+"{") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("invalid metric %q", line)
		}
		value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			return 0, err
		}
		total += value
	}
	return total, nil
}

func metricDelta(before, after, name string) (float64, error) {
	a, err := metric(before, name)
	if err != nil {
		return 0, err
	}
	b, err := metric(after, name)
	return b - a, err
}

func analyze(root string) error {
	return errors.Join(analyzePorter(root), analyzeControlPlane(root))
}

func analyzePorter(root string) error {
	files, err := filepath.Glob(filepath.Join(root, "*.summary.json"))
	if err != nil {
		return err
	}
	rows := []map[string]any{}
	admission, apply := []map[string]any{}, []map[string]any{}
	failed := false
	for _, file := range files {
		s, workers, err := readPhase(root, file)
		if err != nil {
			return err
		}
		row, err := analyzePhase(root, s, workers)
		if err != nil {
			return err
		}
		failed = failed || !row["passed"].(bool)
		rows = append(rows, row)
		start, finish := math.Inf(1), float64(0)
		for _, w := range workers {
			start = min(start, w.Result.StartedUnix)
			finish = max(finish, w.Result.FinishedUnix)
		}
		logs, err := filepath.Glob(filepath.Join(root, s.Name+".*.log"))
		if err != nil {
			return err
		}
		for _, path := range logs {
			a, b, err := logTimings(path, s.Name, start, finish)
			if err != nil {
				return err
			}
			admission = append(admission, a...)
			apply = append(apply, b...)
		}
	}
	for name, value := range map[string]any{"analysis.json": rows, "admission-timings.json": admission, "apply-timings.json": apply} {
		if err = writeJSON(filepath.Join(root, name), value); err != nil {
			return err
		}
	}
	if len(rows) > 0 {
		if err := writeCSV(root, rows); err != nil {
			return err
		}
	}
	_, failureErr := os.Stat(filepath.Join(root, "failure.txt"))
	if failureErr != nil && !errors.Is(failureErr, os.ErrNotExist) {
		return failureErr
	}
	failed = failed || failureErr == nil || len(rows) == 0
	if err = os.WriteFile(filepath.Join(root, "report.md"), []byte(report(rows, failed)), 0600); err != nil {
		return err
	}
	if failed {
		return fmt.Errorf("benchmark failed or has no completed phases; see %s", filepath.Join(root, "report.md"))
	}
	return nil
}

func readPhase(root, file string) (summary, []worker, error) {
	var err error
	var s summary
	if err = readJSON(file, &s); err != nil {
		return summary{}, nil, err
	}
	workerFiles, err := filepath.Glob(filepath.Join(root, s.Name+".porter-*.json"))
	if err != nil {
		return summary{}, nil, err
	}
	if len(workerFiles) != len(s.Results) {
		return summary{}, nil, fmt.Errorf("missing worker result: %s", s.Name)
	}
	workers := make([]worker, len(workerFiles))
	for i, path := range workerFiles {
		if err = readJSON(path, &workers[i]); err != nil {
			return summary{}, nil, err
		}
	}
	return s, workers, nil
}

func addControlPlaneStats(root string, s summary, row map[string]any) error {
	var err error
	var before, after snapshot
	if err = readJSON(filepath.Join(root, s.Name+".before.snapshot.json"), &before); err != nil {
		return err
	}
	if err = readJSON(filepath.Join(root, s.Name+".after.snapshot.json"), &after); err != nil {
		return err
	}
	same := len(before.ADS) == len(after.ADS)
	var cpu, wire, rejections, rss float64
	for id, stats := range after.ADS {
		rss += stats.Process.RSS
		old, found := before.ADS[id]
		if !found {
			same = false
			continue
		}
		cpu += stats.CPU - old.CPU
		wire += stats.Wire.Outbound - old.Wire.Outbound
	}
	row["cp_mean_cores"], row["ads_out_mib"], row["admission_rejections"] = nil, nil, nil
	if same && !s.Concurrent {
		if after.Time <= before.Time {
			return fmt.Errorf("invalid snapshot interval: %s", s.Name)
		}
		for id := range after.ADS {
			a, err := os.ReadFile(filepath.Join(root, s.Name+".before.ads-"+id+".metrics"))
			if err != nil {
				return err
			}
			b, err := os.ReadFile(filepath.Join(root, s.Name+".after.ads-"+id+".metrics"))
			if err != nil {
				return err
			}
			delta, err := metricDelta(string(a), string(b), "agentio_xds_request_rejections_total")
			if err != nil {
				return err
			}
			rejections += delta
		}
		row["cp_mean_cores"], row["ads_out_mib"], row["admission_rejections"] = cpu/(after.Time-before.Time), wire/(1024*1024), rejections
	}
	row["cp_rss_mib"] = rss / 1024
	return nil
}

func analyzePhase(root string, s summary, workers []worker) (map[string]any, error) {
	row, err := summarizeWorkers(workers, s.Concurrent)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.Name, err)
	}
	row["name"], row["variant"], row["phase"], row["concurrent"] = s.Name, s.Variant, s.Phase, s.Concurrent
	passed := row["operations"].(int) == s.Planned && row["errors"].(int) == 0 && len(s.RunErrors) == 0
	row["run_errors"] = s.RunErrors
	row["passed"] = passed
	if err := addControlPlaneStats(root, s, row); err != nil {
		return nil, err
	}
	var demands, waitSeconds float64
	for _, w := range workers {
		count, err := metricDelta(
			w.MetricsBefore,
			w.MetricsAfter,
			"agentio_xds_client_demand_wait_duration_seconds_count",
		)
		if err != nil {
			return nil, err
		}
		seconds, err := metricDelta(
			w.MetricsBefore,
			w.MetricsAfter,
			"agentio_xds_client_demand_wait_duration_seconds_sum",
		)
		if err != nil {
			return nil, err
		}
		demands += count
		waitSeconds += seconds
	}
	row["demand_waits"], row["mean_demand_wait_ms"] = nil, nil
	if !s.Concurrent {
		row["demand_waits"] = demands
		if demands != 0 {
			row["mean_demand_wait_ms"] = waitSeconds * 1000 / demands
		}
	}
	return row, nil
}

func writeCSV(root string, rows []map[string]any) error {
	var err error
	keys := make([]string, 0, len(rows[0]))
	for key := range rows[0] {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err = writer.Write(keys); err != nil {
		return err
	}
	for _, row := range rows {
		values := make([]string, len(keys))
		for i, key := range keys {
			if row[key] != nil {
				values[i] = fmt.Sprint(row[key])
			}
		}
		if err = writer.Write(values); err != nil {
			return err
		}
	}
	writer.Flush()
	if err = writer.Error(); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, "analysis.csv"), buffer.Bytes(), 0600); err != nil {
		return err
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func logTimings(path, phase string, start, end float64) (admission, apply []map[string]any, result error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	admission, apply = []map[string]any{}, []map[string]any{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 65536), 8*1024*1024)
	for scanner.Scan() {
		timestamp, body, ok := strings.Cut(scanner.Text(), " ")
		if !ok || !strings.HasPrefix(body, "{") {
			continue
		}
		var event map[string]any
		if err = json.Unmarshal([]byte(body), &event); err != nil {
			return nil, nil, fmt.Errorf("log %s: %w", path, err)
		}
		if event["event"] == "ads_first_request" {
			when, ok := event["started_unix"].(float64)
			if ok && when >= start && when <= end {
				event["phase"] = phase
				admission = append(admission, event)
			}
		}
		fields, ok := event["fields"].(map[string]any)
		if !ok || (fields["message"] != "applied ADS response" && fields["message"] != "invalidated ADS cache") {
			continue
		}
		when, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, nil, err
		}
		seconds := float64(when.UnixNano()) / 1e9
		if seconds >= start && seconds <= end {
			fields["phase"], fields["log"], fields["timestamp"] = phase, filepath.Base(path), timestamp
			apply = append(apply, fields)
		}
	}
	return admission, apply, scanner.Err()
}

func report(rows []map[string]any, failed bool) string {
	var out strings.Builder
	out.WriteString(
		"# Porter scale results\n\nP99/max are the worst worker, not merged quantiles. QPS uses the common wall interval. RSS is the sum of final process RSS, not live heap or simultaneous peak. CP mean CPU includes preparation/snapshot time. Concurrent phases omit overlapping CPU, wire and demand counters.\n\n| Variant | Phase | QPS | P99 ms | CPU µs/request | Porter RSS MiB |\n|---|---|---:|---:|---:|---:|\n",
	)
	operations, failures := 0, 0
	groups := map[string][]map[string]any{}
	repeated := regexp.MustCompile(`^(hot|reconnect)-\d+$`)
	for _, row := range rows {
		cpu := "—"
		if row["porter_cpu_us_per_request"] != nil {
			cpu = fmt.Sprintf("%.2f", row["porter_cpu_us_per_request"])
		}
		fmt.Fprintf(
			&out,
			"| %s | %s | %.0f | %.3f | %s | %.1f |\n",
			row["variant"],
			row["phase"],
			row["global_qps"],
			row["worst_p99_ms"],
			cpu,
			row["porter_rss_mib"],
		)
		operations += row["operations"].(int)
		failures += row["errors"].(int)
		if match := repeated.FindStringSubmatch(row["phase"].(string)); match != nil {
			key := row["variant"].(string) + " " + match[1]
			groups[key] = append(groups[key], row)
		}
	}
	out.WriteString("\nRepeated phases (median of per-run values):\n\n")
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		var qps, p99 []float64
		for _, row := range groups[key] {
			qps = append(qps, row["global_qps"].(float64))
			p99 = append(p99, row["worst_p99_ms"].(float64))
		}
		fmt.Fprintf(&out, "- %s: n=%d, QPS %.0f, P99 %.3f ms.\n", key, len(qps), median(qps), median(p99))
	}
	fmt.Fprintf(&out, "\nCompleted phases: %d; requests: %d; unexpected errors: %d.\n", len(rows), operations, failures)
	if failed {
		out.WriteString("\n**The run failed; these are partial results. See failure.txt.**\n")
	}
	return out.String()
}

func median(values []float64) float64 {
	sort.Float64s(values)
	middle := len(values) / 2
	if len(values)%2 == 0 {
		return (values[middle-1] + values[middle]) / 2
	}
	return values[middle]
}
