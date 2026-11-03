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

package networklimits

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/bench/connect/fixture"
)

func streamTimeout() time.Duration {
	if os.Getenv("AGENTIO_NETWORK_SCENARIO") != "" {
		return 120 * time.Second
	}
	return 30 * time.Second
}

func TestEnvoyNetworkScenario(t *testing.T) {
	raw := os.Getenv("AGENTIO_NETWORK_SCENARIO")
	if raw == "" {
		t.Skip("opt-in stability scenario; use bench/connect/scenarios")
	}
	if os.Getenv("AGENTIO_TEST_ENVOY_BINARY") == "" {
		t.Fatal("scenario requires a real Envoy binary")
	}
	// Registered before fixtures, so their teardown failures suppress the marker.
	t.Cleanup(func() {
		if !t.Failed() {
			t.Log("SCENARIO_COMPLETED")
		}
	})
	version, err := exec.Command(os.Getenv("AGENTIO_TEST_ENVOY_BINARY"), "--version").Output()
	must(t, err)
	t.Logf("Envoy: %s", version)
	var c fixture.Scenario
	must(t, json.Unmarshal([]byte(raw), &c))
	if c.Workers <= 0 {
		t.Fatal("Workers must be positive")
	}
	t.Setenv("AGENTIO_TEST_WORKERS", strconv.Itoa(c.Workers))
	t.Logf("scenario=%s", raw)
	switch c.Kind {
	case "active", "reload":
		scenarioTransfers(t, c)
	case "churn":
		scenarioChurn(t, c)
	case "combined":
		scenarioCombined(t)
	default:
		t.Fatalf("unknown scenario kind %q", c.Kind)
	}
}

type scenarioTransfer struct {
	stream  *stream
	bytes   atomic.Int64
	gap     time.Duration
	elapsed time.Duration
	done    chan error
}

// Reads incrementally: the load generator does not retain one file per stream.
func startScenarioTransfer(s *stream, upload bool) *scenarioTransfer {
	x := &scenarioTransfer{stream: s, done: make(chan error, 1)}
	go func() {
		started, last := time.Now(), time.Now()
		written := make(chan error, 1)
		go func() {
			command := "D"
			if upload {
				command = "P"
			}
			_, err := fmt.Fprintf(s.writer, "%s %d\n", command, size)
			if err == nil && upload {
				_, err = s.writer.Write(payload(size))
			}
			written <- errors.Join(err, s.writer.Close())
		}()
		buf := make([]byte, 16384)
		var tail []byte
		var readErr error
		for {
			n, err := s.response.Body.Read(buf)
			if n > 0 {
				now := time.Now()
				x.gap = max(x.gap, now.Sub(last))
				last = now
				x.bytes.Add(int64(n))
				if upload {
					tail = append(tail, buf[:n]...)
				} else if !bytes.Equal(buf[:n], payload(n)) {
					readErr = errors.New("corrupt download payload")
					break
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					readErr = err
				}
				break
			}
		}
		if readErr != nil {
			s.cancel()
		}
		err := errors.Join(readErr, <-written)
		if err == nil && upload && !bytes.Equal(tail, append(bytes.Repeat([]byte("p"), size/16384), []byte("OK")...)) {
			err = errors.New("upload origin acknowledgement mismatch")
		}
		if err == nil && !upload && x.bytes.Load() != size {
			err = fmt.Errorf("download bytes=%d want=%d", x.bytes.Load(), size)
		}
		x.elapsed = time.Since(started)
		x.done <- err
	}()
	return x
}

func scenarioPolicy(p object, count, bandwidth int) {
	p["max_dynamic_buckets"] = count + 16
	p["descriptors"] = p["descriptors"].([]any)[:1]
	limit := nested(p["descriptors"].([]any)[0], "bandwidth_limit")
	limit["upload_bytes_per_second"] = bandwidth
	limit["download_bytes_per_second"] = bandwidth
}

func scenarioStreams(t *testing.T, r *runtime, c fixture.Scenario, prefix string) []*stream {
	t.Helper()
	if c.Sandboxes <= 0 || c.Flows <= 0 {
		t.Fatal("Sandboxes and Flows must be positive")
	}
	streams := make([]*stream, 0, c.Sandboxes*c.Flows)
	var client *h2client
	for sandbox := range c.Sandboxes {
		for range c.Flows {
			if len(streams)%64 == 0 {
				client = newClient(t, r.port)
			}
			streams = append(streams, client.open(t, "test", fmt.Sprintf("%s-%d", prefix, sandbox), "plain:80", 200))
		}
	}
	return streams
}

func scenarioTransfers(t *testing.T, c fixture.Scenario) {
	origin := startOrigin(t, false)
	bandwidth := rate
	if c.Sandboxes == 1 {
		bandwidth = 8 * 1048576
	}
	r := startEnvoyConfig(
		t,
		origin.port(),
		freePort(t),
		func(l object) { scenarioPolicy(policy(filters(l)[1]), c.Sandboxes, bandwidth) },
		true,
	)
	streams := scenarioStreams(t, r, c, "sandbox")
	started := time.Now()
	transfers := make([]*scenarioTransfer, len(streams))
	for i, s := range streams {
		transfers[i] = startScenarioTransfer(s, c.Upload)
	}
	cancelled := make(map[int]bool)
	if c.Kind == "reload" {
		// Wait for real payload on every stream before moving queued work to a new grouping.
		eventually(t, func() bool {
			for _, x := range transfers {
				if x.bytes.Load() == 0 {
					return false
				}
			}
			return true
		})
		r.reloadECDS(t, "agentio.bandwidth", func(p object) {
			scenarioPolicy(p, c.Sandboxes, 2*rate)
			nested(p["descriptors"].([]any)[0], "bandwidth_limit")["download_burst_bytes"] = 65536
		}, false)
		// All identities become one tenant bucket; existing queues must be rebound.
		r.reloadECDS(t, "agentio.bandwidth", func(p object) {
			p["rate_limits"] = []any{
				object{
					"actions": []any{object{"filter_state": object{"key": "tenant.id", "descriptor_key": "tenant"}}},
				},
			}
			p["descriptors"] = []any{
				object{
					"entries":         []any{object{"key": "tenant"}},
					"bandwidth_limit": object{"download_bytes_per_second": 1048576},
				},
			}
		}, false)
		for i, s := range streams {
			if i%4 == 0 {
				cancelled[i] = true
				s.close()
			}
		}
		// A rejected update must leave the accepted policy untouched.
		r.reloadECDS(t, "agentio.bandwidth", func(p object) { p["enabled"] = false }, true)
		r.reloadECDS(t, "agentio.bandwidth", func(p object) { p["enabled"] = false }, false)
	}
	var gap time.Duration
	completed := make([]time.Duration, c.Sandboxes)
	for i, x := range transfers {
		err := <-x.done
		if !cancelled[i] {
			must(t, err)
			gap = max(gap, x.gap)
			bucket := i / c.Flows
			completed[bucket] = max(completed[bucket], x.elapsed)
		}
	}
	elapsed := time.Since(started)
	if c.Kind == "active" {
		ideal := float64(c.Flows*size) / float64(bandwidth)
		for bucket, elapsed := range completed {
			if elapsed.Seconds() < ideal*0.7 {
				t.Fatalf("bucket %d quota bypass: completion=%s ideal=%fs", bucket, elapsed, ideal)
			}
		}
		bound := max(
			30*time.Second,
			time.Duration(float64(c.Flows*131072)/float64(bandwidth)*float64(time.Second))+5*time.Second,
		)
		if gap > bound {
			t.Fatalf("starvation: max gap=%s bound=%s", gap, bound)
		}
	} else {
		r.reloadECDS(t, "agentio.bandwidth", func(p object) {
			p["enabled"] = true
			p["rate_limits"] = []any{
				object{
					"actions": []any{
						object{"filter_state": object{"key": "agentio.sandbox.uid", "descriptor_key": "sandbox"}},
					},
				},
			}
			p["descriptors"] = []any{
				object{
					"entries":         []any{object{"key": "sandbox"}},
					"bandwidth_limit": object{"download_bytes_per_second": rate},
				},
			}
		}, false)
		probe := startScenarioTransfer(newClient(t, r.port).open(t, "test", "reconnected", "plain:80", 200), false)
		must(t, <-probe.done)
		durationBetween(t, probe.elapsed, 2.5, 15)
	}
	t.Logf(
		"verified=%d cancelled=%d sandboxes=%d workers=%d elapsed=%s longest_gap=%s Envoy_RSS=%d",
		len(streams)-len(cancelled),
		len(cancelled),
		c.Sandboxes,
		c.Workers,
		elapsed,
		gap,
		rss(t, r.cmd.Process.Pid),
	)
}

func scenarioChurn(t *testing.T, c fixture.Scenario) {
	if c.Seconds <= 0 {
		t.Fatal("Seconds must be positive")
	}
	origin := startOrigin(t, false)
	r := startEnvoy(t, origin.port(), freePort(t), func(l object) {
		scenarioPolicy(policy(filters(l)[1]), c.Sandboxes, 1048576)
		policy(filters(l)[1])["max_dynamic_buckets"] = c.Sandboxes
	})
	started := time.Now()
	var baselineRSS int64
	var baselineFD int
	for cycle := 0; time.Since(started) < time.Duration(c.Seconds)*time.Second; cycle++ {
		if !t.Run(fmt.Sprintf("cycle-%d", cycle), func(t *testing.T) {
			streams := scenarioStreams(t, r, c, fmt.Sprintf("cycle-%d", cycle))
			started := make(chan error, len(streams))
			for _, s := range streams {
				go func() {
					_, err := fmt.Fprintf(s.writer, "B %d\n", 64*1048576)
					if err == nil {
						_, err = io.ReadFull(s.response.Body, make([]byte, 1))
					}
					started <- err
				}()
			}
			for range streams {
				must(t, <-started)
			}
			// Every bucket has debt and pending download work when its last owner leaves.
			for _, s := range streams {
				s.close()
			}
		}) {
			return
		}
		eventually(t, func() bool { return r.stat(t, "cluster.plain.upstream_cx_active") == 0 })
		// Allow the charged watermark batch to recover, then require ALL slots for new keys next cycle.
		time.Sleep(300 * time.Millisecond)
		memory := rss(t, r.cmd.Process.Pid)
		files, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", r.cmd.Process.Pid))
		must(t, err)
		if cycle == 4 {
			baselineRSS = memory
			baselineFD = len(files)
		}
		if cycle > 4 && (memory > baselineRSS+128*1048576 || len(files) > baselineFD+16) {
			t.Fatalf(
				"resource growth after warmup: RSS %d -> %d, FD %d -> %d",
				baselineRSS,
				memory,
				baselineFD,
				len(files),
			)
		}
		t.Logf(
			"cycle=%d new_buckets=%d RSS=%d FD=%d elapsed=%s",
			cycle,
			c.Sandboxes,
			memory,
			len(files),
			time.Since(started),
		)
	}
}

func scenarioCombined(t *testing.T) {
	origin := startOrigin(t, false)
	r := startEnvoy(t, origin.port(), freePort(t), func(l object) {
		concurrencyConfig(t, l, true)
		nested(filters(l)[1], "typed_config")["token_bucket"] = object{
			"max_tokens":      8,
			"tokens_per_fill": 8,
			"fill_interval":   "1s",
		}
	})
	a, b := newClient(t, r.port), newClient(t, r.port)
	slow := a.open(t, "test", "slow", "plain:80", 200)
	other := b.open(t, "test", "slow", "plain:80", 200)
	a.open(t, "test", "slow", "plain:80", 429).close()
	if r.stat(t, "connect_rate.*rate_limited") != 0 {
		t.Fatal("expected concurrency rejection before rate exhaustion")
	}
	baseline := rss(t, r.cmd.Process.Pid)
	_, err := fmt.Fprintf(slow.writer, "B %d\n", 64*1048576)
	must(t, err)
	_, err = io.ReadFull(slow.response.Body, make([]byte, 1))
	must(t, err)
	fast := startScenarioTransfer(b.open(t, "vip", "fast", "plain:80", 200), false)
	must(t, <-fast.done)
	durationBetween(t, fast.elapsed, 0, 2)
	// The slow body is deliberately not consumed while other traffic proceeds.
	time.Sleep(2 * time.Second)
	produced := origin.produced.Load()
	if produced >= 8*1048576 || rss(t, r.cmd.Process.Pid) > baseline+32*1048576 {
		t.Fatalf("unbounded slow-reader buffering: produced=%d", produced)
	}
	// Exhaust the native admission bucket with an already-full sandbox.
	for range 20 {
		a.open(t, "test", "slow", "plain:80", 429).close()
	}
	if r.stat(t, "connect_rate.*rate_limited") == 0 {
		t.Fatal("native connection rate limiter never enforced")
	}
	slow.close()
	other.close()
	time.Sleep(1100 * time.Millisecond)
	finish(t, a.eventuallyOpen(t, "slow"))
	t.Logf(
		"concurrency rejection, native rate rejection, recovery, independent progress and backpressure verified; produced=%d",
		produced,
	)
}
