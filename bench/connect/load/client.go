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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/openkruise/agentio/bench/load"
)

type transfers struct {
	config     config
	ctx        context.Context
	transports []*http2.Transport
	dials      atomic.Int64
	received   []atomic.Uint64
	completed  sync.WaitGroup
	mu         sync.Mutex
	failures   map[int]error
}

func (t *transfers) failed(i int, err error) {
	if t.ctx.Err() != nil {
		return
	}
	t.mu.Lock()
	t.failures[i] = err
	t.mu.Unlock()
}

func (t *transfers) establish(setup context.Context, i int) error {
	ctx, cancel := context.WithCancel(t.ctx)
	stop := context.AfterFunc(setup, cancel)
	defer stop() // Setup completion must not cancel the established tunnel.
	reader, writer := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "CONNECT", "http://plain:80", reader)
	if err != nil {
		cancel()
		return err
	}
	sandbox := "shared"
	if t.config.Distinct {
		sandbox = strconv.Itoa(i)
	}
	if t.config.FastStream && i == t.config.Streams-1 {
		sandbox = "fast"
	}
	req.Host = "plain:80"
	req.Header.Set("x-tenant", "perf")
	req.Header.Set("x-sandbox", sandbox)
	resp, err := t.transports[i%len(t.transports)].RoundTrip(req)
	if err != nil {
		cancel()
		return errors.Join(err, reader.Close(), writer.Close())
	}
	if resp.StatusCode != http.StatusOK {
		detail, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		cancel()
		return errors.Join(
			fmt.Errorf("CONNECT stream %d: %s: %s", i, resp.Status, detail),
			readErr,
			resp.Body.Close(),
			reader.Close(),
			writer.Close(),
		)
	}
	t.completed.Add(2)
	go func() {
		defer t.completed.Done()
		defer func() {
			if err := writer.Close(); err != nil {
				t.failed(i, err)
			}
		}()
		if _, err := fmt.Fprintf(writer, "%s %d\n", t.config.Direction, i); err != nil {
			t.failed(i, err)
			return
		}
		if t.config.Direction == "U" {
			buf := make([]byte, 65536)
			for {
				if _, err := writer.Write(buf); err != nil {
					t.failed(i, err)
					return
				}
			}
		}
	}()
	go func() {
		defer t.completed.Done()
		defer cancel()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.failed(i, err)
			}
		}()
		buf := make([]byte, 65536)
		for {
			n, err := resp.Body.Read(buf)
			t.received[i].Add(uint64(n))
			if err != nil {
				t.failed(i, err)
				return
			}
		}
	}()
	return nil
}

func (t *transfers) counters() ([]uint64, error) {
	values := make([]uint64, len(t.received))
	if t.config.Direction == "D" {
		for i := range values {
			values[i] = t.received[i].Load()
		}
		return values, nil
	}
	req, err := http.NewRequestWithContext(t.ctx, "GET", "http://"+t.config.Stats+"/bytes", nil)
	if err != nil {
		return nil, err
	}
	client := http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	m := map[string]uint64{}
	err = json.NewDecoder(response.Body).Decode(&m)
	err = errors.Join(err, response.Body.Close())
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("origin counters: %s", response.Status)
	}
	for i := range values {
		values[i] = m[strconv.Itoa(i)]
	}
	return values, nil
}

func runLoad(parent context.Context, c config) (map[string]any, error) {
	if c.EnvoyPID <= 0 || c.OriginPID <= 0 {
		return nil, fmt.Errorf("envoy-pid and origin-pid must be positive")
	}
	ctx, cancel := context.WithCancel(parent)
	t := &transfers{config: c, ctx: ctx, received: make([]atomic.Uint64, c.Streams), failures: map[int]error{}}
	for range min(c.Streams, c.Connections) {
		t.transports = append(t.transports, &http2.Transport{
			AllowHTTP:                  true,
			StrictMaxConcurrentStreams: true,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				t.dials.Add(1)
				return (&net.Dialer{}).DialContext(ctx, "tcp", c.Target)
			}})
	}
	defer func() {
		cancel()
		t.completed.Wait()
		for _, transport := range t.transports {
			transport.CloseIdleConnections()
		}
	}()
	setup, err := load.Run(
		ctx,
		load.Config{Requests: c.Streams, Identities: c.Streams, Concurrency: c.Streams, Duration: c.SetupTimeout},
		t.establish,
	)
	if err != nil {
		return nil, err
	}
	if setup.Errors != 0 || setup.Operations != c.Streams {
		return nil, fmt.Errorf(
			"CONNECT setup completed %d/%d, errors=%d: %s",
			setup.Operations,
			c.Streams,
			setup.Errors,
			setup.FirstError,
		)
	}
	if err := pause(ctx, c.Warmup); err != nil {
		return nil, err
	}
	result, err := t.measure()
	if err != nil {
		return nil, err
	}
	cancel()
	t.completed.Wait()
	result["connect_p50_ms"] = setup.P50MS
	result["connect_p95_ms"] = setup.P95MS
	result["h2_connections"] = t.dials.Load()
	t.mu.Lock()
	defer t.mu.Unlock()
	result["errors"] = len(t.failures)
	for _, err := range t.failures {
		result["first_error"] = err.Error()
		break
	}
	return result, nil
}

func (t *transfers) measure() (map[string]any, error) {
	c := t.config
	before, err := t.counters()
	if err != nil {
		return nil, err
	}
	pids := []int{c.EnvoyPID, os.Getpid(), c.OriginPID}
	startCPU, err := samples(pids, c.Ticks)
	if err != nil {
		return nil, err
	}
	peakRSS := startCPU[0].RSS
	started := time.Now()
	var progress *progressWindow
	if c.ProgressInterval > 0 {
		progress = newProgressWindow(before, started)
	}
	nextProgress := started.Add(c.ProgressInterval)
	for time.Since(started) < c.Duration {
		if err := pause(t.ctx, min(100*time.Millisecond, c.Duration-time.Since(started))); err != nil {
			return nil, err
		}
		sample, err := sample(c.EnvoyPID, c.Ticks)
		if err != nil {
			return nil, err
		}
		peakRSS = max(peakRSS, sample.RSS)
		if progress != nil && !time.Now().Before(nextProgress) {
			counts, err := t.counters()
			if err != nil {
				return nil, err
			}
			now := time.Now()
			progress.observe(counts, now)
			nextProgress = now.Add(c.ProgressInterval)
		}
	}
	after, err := t.counters()
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(started).Seconds()
	endCPU, err := samples(pids, c.Ticks)
	if err != nil {
		return nil, err
	}
	rates := make([]float64, c.Streams)
	var bytes uint64
	for i := range rates {
		delta := after[i] - before[i]
		bytes += delta
		rates[i] = float64(delta) / elapsed / 1048576
	}
	fastRate := rates[len(rates)-1]
	slices.Sort(rates)
	result := map[string]any{
		"streams":              c.Streams,
		"direction":            c.Direction,
		"distinct":             c.Distinct,
		"seconds":              elapsed,
		"mib_per_s":            float64(bytes) / elapsed / 1048576,
		"envoy_cpu_cores":      (endCPU[0].CPU - startCPU[0].CPU) / elapsed,
		"load_cpu_cores":       (endCPU[1].CPU - startCPU[1].CPU) / elapsed,
		"origin_cpu_cores":     (endCPU[2].CPU - startCPU[2].CPU) / elapsed,
		"envoy_rss_peak_mib":   float64(peakRSS) / 1048576,
		"envoy_rss_start_mib":  float64(startCPU[0].RSS) / 1048576,
		"stream_min_mib_per_s": rates[0],
		"stream_p50_mib_per_s": rates[len(rates)/2],
		"stream_max_mib_per_s": rates[len(rates)-1],
	}
	if progress != nil {
		progress.observe(after, time.Now())
		gaps := progress.finish(time.Now())
		result["stream_max_idle_ms"] = gaps
		result["max_idle_ms"] = slices.Max(gaps)
		result["progress_interval_ms"] = float64(c.ProgressInterval) / float64(time.Millisecond)
	}
	if c.FastStream {
		result["fast_mib_per_s"] = fastRate
		result["noisy_mib_per_s"] = float64(bytes)/elapsed/1048576 - fastRate
	}
	return result, nil
}

func pause(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(max(duration, 0))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
