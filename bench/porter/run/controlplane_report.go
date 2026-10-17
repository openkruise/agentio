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
	"encoding/json"
	"math"
	"path/filepath"
	"slices"
	"strings"
)

type cpSample struct {
	CPU     float64           `json:"cpu_seconds"`
	Alloc   uint64            `json:"total_alloc"`
	Mallocs uint64            `json:"mallocs"`
	GC      uint64            `json:"num_gc"`
	Pause   uint64            `json:"gc_pause_ns"`
	Heap    uint64            `json:"heap_alloc"`
	Cgroup  map[string]uint64 `json:"cgroup_cpu"`
	Process struct {
		RSS  float64 `json:"VmRSS_kib"`
		Peak float64 `json:"VmHWM_kib"`
	} `json:"process"`
}

type cpSnapshot struct {
	Time float64             `json:"time"`
	ADS  map[string]cpSample `json:"ads"`
}

func cpDelta(before, after cpSnapshot) map[string]any {
	cpu, alloc, mallocs, gc, pause, rss, heap, throttled := 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
	missing := []string{}
	for name, a := range before.ADS {
		b, ok := after.ADS[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		cpu += b.CPU - a.CPU
		alloc += float64(b.Alloc) - float64(a.Alloc)
		mallocs += float64(b.Mallocs) - float64(a.Mallocs)
		gc += float64(b.GC) - float64(a.GC)
		pause += (float64(b.Pause) - float64(a.Pause)) / 1e6
		throttled += (float64(b.Cgroup["throttled_usec"]) - float64(a.Cgroup["throttled_usec"])) / 1e6
		rss += b.Process.RSS / 1024
		heap += float64(b.Heap) / (1024 * 1024)
	}
	return map[string]any{
		"cpu_seconds":            cpu,
		"allocated_mib":          alloc / (1024 * 1024),
		"allocations":            mallocs,
		"gc_cycles":              gc,
		"gc_pause_ms":            pause,
		"rss_end_mib":            rss,
		"heap_end_mib":           heap,
		"throttled_seconds":      throttled,
		"missing_control_planes": missing,
		"snapshot_seconds":       after.Time - before.Time,
	}
}

func analyzeControlPlane(root string) error {
	files, err := filepath.Glob(filepath.Join(root, "*.before.snapshot.json"))
	if err != nil {
		return err
	}
	rows := map[string]any{}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".before.snapshot.json")
		afterPath := filepath.Join(root, name+".after.snapshot.json")
		matches, err := filepath.Glob(afterPath)
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			continue
		}
		var before, after cpSnapshot
		if err := readJSON(file, &before); err != nil {
			return err
		}
		if err := readJSON(afterPath, &after); err != nil {
			return err
		}
		rows[name] = cpDelta(before, after)
	}
	if err := writeJSON(filepath.Join(root, "controlplane-analysis.json"), rows); err != nil {
		return err
	}
	timings := map[string]any{}
	for _, pattern := range []string{"*.controlplane.json", "*.trigger.json"} {
		files, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			return err
		}
		for _, file := range files {
			var event struct {
				Result json.RawMessage `json:"result"`
			}
			if err := readJSON(file, &event); err != nil {
				return err
			}
			events := []json.RawMessage{event.Result}
			if len(event.Result) > 0 && event.Result[0] == '[' {
				if err := json.Unmarshal(event.Result, &events); err != nil {
					return err
				}
			}
			for index, data := range events {
				var sample struct {
					Convergence struct {
						Participants int       `json:"participants"`
						Completed    int       `json:"completed"`
						Times        []float64 `json:"client_seconds"`
					} `json:"convergence"`
				}
				if err := json.Unmarshal(data, &sample); err != nil {
					return err
				}
				c := sample.Convergence
				if c.Participants == 0 {
					continue
				}
				times := append([]float64(nil), c.Times...)
				slices.Sort(times)
				quantile := func(q float64) float64 { return times[max(0, int(math.Ceil(float64(len(times))*q))-1)] * 1000 }
				name := filepath.Base(file)
				list, _ := timings[name].([]any)
				list = append(
					list,
					map[string]any{
						"event":     index,
						"clients":   c.Participants,
						"completed": c.Completed,
						"p50_ms":    quantile(.5),
						"p95_ms":    quantile(.95),
						"p99_ms":    quantile(.99),
						"max_ms":    quantile(1),
					},
				)
				timings[name] = list
			}
		}
	}
	return writeJSON(filepath.Join(root, "wds-convergence.json"), timings)
}
