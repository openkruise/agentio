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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkruise/agentio/bench/load"
)

func TestSummaryUsesCommonInterval(t *testing.T) {
	workers := []worker{
		{
			Result: workerResult{
				Result:         load.Result{Operations: 100, StartedUnix: 0, FinishedUnix: 1, P99MS: 2, MaxMS: 5},
				LoadCPUSeconds: .2,
			},
			After: processStats{CPU: .1, RSS: 1024},
		},
		{
			Result: workerResult{
				Result:         load.Result{Operations: 100, StartedUnix: 1, FinishedUnix: 2, P99MS: 3, MaxMS: 6},
				LoadCPUSeconds: .2,
			},
			After: processStats{CPU: .3, RSS: 1024},
		},
	}
	row, err := summarizeWorkers(workers, false)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]float64{
		"global_qps":                100,
		"porter_cpu_us_per_request": 2000,
		"porter_rss_mib":            2,
		"worst_p99_ms":              3,
		"load_mean_cores":           .2,
	} {
		if row[key] != want {
			t.Errorf("%s: got %v, want %v", key, row[key], want)
		}
	}
	row, err = summarizeWorkers(workers, true)
	if err != nil || row["porter_cpu_us_per_request"] != nil {
		t.Fatalf("overlapping CPU was attributed: %v, %v", row, err)
	}
}

func TestFailedRunKeepsPartialReport(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "failure.txt"),
		[]byte("control plane failed to start\n"),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if err := analyze(root); err == nil {
		t.Fatal("failed run must return failure")
	}
	data, err := os.ReadFile(filepath.Join(root, "report.md"))
	if err != nil || !strings.Contains(string(data), "The run failed") {
		t.Fatalf("partial report not retained: %s, %v", data, err)
	}
}
