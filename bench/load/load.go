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

// Package load schedules protocol-independent requests against logical identities.
package load

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Config separates logical identity count from request rate and worker count.
// Rate zero uses closed-loop concurrency. Positive Rate measures latency from
// the scheduled arrival, including generator queueing rather than hiding overload.
type Config struct {
	Requests    int
	Identities  int
	Offset      int
	Concurrency int
	Rate        int
	Duration    time.Duration
	Start       time.Time
	Started     func()
	Finished    func()
}

// Result is independent of the protocol and system being measured.
type Result struct {
	StartedUnix     float64                `json:"started_unix"`
	FinishedUnix    float64                `json:"finished_unix"`
	SecondsBins     map[int]map[string]int `json:"seconds_bins"`
	UniqueAttempted int                    `json:"unique_attempted"`
	ActiveTarget    int                    `json:"active_target"`
	Operations      int                    `json:"operations"`
	Concurrency     int                    `json:"concurrency"`
	OfferedRate     int                    `json:"offered_rate"`
	Seconds         float64                `json:"seconds"`
	OpsPerSecond    float64                `json:"ops_per_second"`
	P50MS           float64                `json:"p50_ms"`
	P95MS           float64                `json:"p95_ms"`
	P99MS           float64                `json:"p99_ms"`
	MaxMS           float64                `json:"max_ms"`
	Errors          int                    `json:"errors"`
	FirstError      string                 `json:"first_error"`
	BatchMeans      []float64              `json:"batch100_mean_ms"`
}

type sample struct {
	latency int64
	second  int
	err     error
	done    bool
}

// Run calls operation concurrently. The adapter owns connections, payloads and
// response validation; Run owns scheduling, cancellation and measurement.
// A canceled or duration-limited run returns partial counts, never planned counts.
func Run(ctx context.Context, cfg Config, operation func(context.Context, int) error) (Result, error) {
	if cfg.Requests <= 0 || cfg.Identities <= 0 || cfg.Concurrency <= 0 || cfg.Rate < 0 || cfg.Offset < 0 ||
		cfg.Duration <= 0 {
		return Result{}, fmt.Errorf("invalid load configuration")
	}
	if !cfg.Start.IsZero() {
		if !time.Now().Before(cfg.Start) {
			return Result{}, fmt.Errorf("missed scheduled start; increase preparation time")
		}
		if err := wait(ctx, time.Until(cfg.Start)); err != nil {
			return Result{}, err
		}
	}
	if cfg.Started != nil {
		cfg.Started()
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()
	samples := make([]sample, cfg.Requests)
	var next atomic.Int64
	var workers sync.WaitGroup
	for range cfg.Concurrency {
		workers.Go(func() {
			for ctx.Err() == nil {
				index := int(next.Add(1) - 1)
				if index >= cfg.Requests {
					return
				}
				arrival := time.Now()
				if cfg.Rate > 0 {
					arrival = start.Add(time.Duration(float64(index) / float64(cfg.Rate) * float64(time.Second)))
					if err := wait(ctx, time.Until(arrival)); err != nil {
						return
					}
				}
				err := operation(ctx, cfg.Offset+index%cfg.Identities)
				samples[index] = sample{
					latency: time.Since(arrival).Nanoseconds(),
					second:  int(time.Since(start).Seconds()),
					err:     err,
					done:    true,
				}
			}
		})
	}
	workers.Wait()
	finish := time.Now()
	if cfg.Finished != nil {
		cfg.Finished()
	}
	return summarize(cfg, samples, start, finish), ctx.Err()
}

func summarize(cfg Config, samples []sample, start, finish time.Time) Result {
	result := Result{
		StartedUnix:  float64(start.UnixNano()) / 1e9,
		FinishedUnix: float64(finish.UnixNano()) / 1e9,
		SecondsBins:  make(map[int]map[string]int),
		ActiveTarget: cfg.Identities,
		Concurrency:  cfg.Concurrency,
		OfferedRate:  cfg.Rate,
		Seconds:      finish.Sub(start).Seconds(),
	}
	latencies := make([]int64, 0, cfg.Requests)
	identities := make(map[int]struct{})
	for index, value := range samples {
		if !value.done {
			continue
		}
		identities[index%cfg.Identities] = struct{}{}
		latencies = append(latencies, value.latency)
		if result.SecondsBins[value.second] == nil {
			result.SecondsBins[value.second] = map[string]int{"success": 0, "error": 0}
		}
		outcome := "success"
		if value.err != nil {
			outcome = "error"
			result.Errors++
			if result.FirstError == "" {
				result.FirstError = value.err.Error()
			}
		}
		result.SecondsBins[value.second][outcome]++
	}
	result.Operations = len(latencies)
	result.UniqueAttempted = len(identities)
	if result.Seconds > 0 {
		result.OpsPerSecond = float64(result.Operations) / result.Seconds
	}
	for base := 0; base < len(latencies); base += 100 {
		batch := latencies[base:min(base+100, len(latencies))]
		var total int64
		for _, latency := range batch {
			total += latency
		}
		result.BatchMeans = append(result.BatchMeans, float64(total)/float64(len(batch))/1e6)
	}
	if len(latencies) > 0 {
		slices.Sort(latencies)
		quantile := func(p float64) float64 {
			return float64(latencies[min(int(float64(len(latencies))*p), len(latencies)-1)]) / 1e6
		}
		result.P50MS = quantile(.5)
		result.P95MS = quantile(.95)
		result.P99MS = quantile(.99)
		result.MaxMS = quantile(1)
	}
	return result
}

func wait(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
