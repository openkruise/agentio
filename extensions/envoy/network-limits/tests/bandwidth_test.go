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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openkruise/agentio/internal/testutil"
)

type transfer struct {
	tenant    string
	sandbox   string
	direction string
	size      int
}

func multiplex(t *testing.T, port int, transfers []transfer) []time.Duration {
	t.Helper()
	client := newClient(t, port)
	times := make([]time.Duration, len(transfers))
	var wg sync.WaitGroup
	started := time.Now()
	for i, tr := range transfers {
		wg.Go(func() {
			s := client.open(t, tr.tenant, tr.sandbox, "plain:80", 200)
			sent := make(chan error, 1)
			go func() {
				_, err := fmt.Fprintf(s.writer, "%s %d\n", tr.direction, tr.size)
				if err == nil && (tr.direction == "U" || tr.direction == "E") {
					_, err = s.writer.Write(payload(tr.size))
				}
				closeErr := s.writer.Close()
				if err == nil {
					err = closeErr
				}
				sent <- err
			}()
			data, err := io.ReadAll(s.response.Body)
			must(t, err)
			must(t, <-sent)
			want := payload(tr.size)
			if tr.direction == "U" {
				want = []byte("OK")
			}
			if !bytes.Equal(data, want) {
				t.Errorf("%s: received %d bytes, want %d", tr.direction, len(data), len(want))
			}
			times[i] = time.Since(started)
			s.close()
		})
	}
	wg.Wait()
	return times
}
func durationBetween(t *testing.T, d time.Duration, lo, hi float64) {
	t.Helper()
	if d.Seconds() < lo || d.Seconds() >= hi {
		t.Fatalf("duration %s outside [%g,%g)s", d, lo, hi)
	}
}
func readWindow(t *testing.T, c net.Conn, duration time.Duration) float64 {
	t.Helper()
	started := time.Now()
	total := 0
	buf := make([]byte, 65536)
	for time.Since(started) < duration {
		n, err := c.Read(buf)
		must(t, err)
		if n == 0 || !bytes.Equal(buf[:n], payload(n)) {
			t.Fatal("invalid download payload")
		}
		total += n
	}
	return float64(total) / time.Since(started).Seconds()
}
func rss(t *testing.T, pid int) int64 {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	must(t, err)
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			n, err := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
			must(t, err)
			return n * 1024
		}
	}
	t.Fatal("VmRSS missing")
	return 0
}

func TestEnvoyBandwidthBucketRelease(t *testing.T) {
	if os.Getenv("AGENTIO_TEST_ENVOY_BINARY") == "" {
		t.Skip("real Envoy test; run bin/test_network_limits.sh")
	}
	origin := startOrigin(t, false)
	r := startEnvoy(t, origin.port(), freePort(t), func(l object) {
		policy(filters(l)[1])["max_dynamic_buckets"] = 1
	})
	a, b := newClient(t, r.port), newClient(t, r.port)
	first := a.open(t, "test", "a", "plain:80", 200)
	second := b.open(t, "test", "a", "plain:80", 200)
	a.open(t, "test", "b", "plain:80", 503).close()
	first.close()
	a.open(t, "test", "b", "plain:80", 503).close()
	second.close()
	for _, sandbox := range []string{"b", "c", "d"} {
		var admitted *stream
		testutil.Eventually(t, func() bool {
			s := b.open(t, "test", sandbox, "plain:80", 0)
			if s.response.StatusCode == 200 {
				admitted = s
				return true
			}
			if s.response.StatusCode != 503 {
				t.Fatalf("unexpected admission status: %d", s.response.StatusCode)
			}
			s.close()
			return false
		}, "sandbox admission succeeds")
		admitted.close()
	}
}

func TestEnvoyBandwidthBurst(t *testing.T) {
	if os.Getenv("AGENTIO_TEST_ENVOY_BINARY") == "" {
		t.Skip("real Envoy test; run bin/test_network_limits.sh")
	}
	origin := startOrigin(t, false)
	r := startEnvoy(t, origin.port(), freePort(t), func(l object) {
		d := policy(filters(l)[1])["descriptors"].([]any)[0]
		limit := nested(d, "bandwidth_limit")
		limit["upload_burst_bytes"] = strconv.Itoa(size)
		limit["download_burst_bytes"] = strconv.Itoa(size)
	})
	for _, direction := range []string{"U", "D"} {
		t.Run(direction, func(t *testing.T) {
			transfers := []transfer{
				{"burst", direction, direction, size / 2},
				{"burst", direction, direction, size / 2},
			}
			first := multiplex(t, r.port, transfers)
			durationBetween(t, max(first[0], first[1]), 0, 1.5)
			// multiplex opens a fresh H2 connection: reconnecting must not grant new credit.
			next := multiplex(t, r.port, transfers)
			durationBetween(t, max(next[0], next[1]), 2.5, 10)
			t.Logf("initial shared burst: %s; same-key reconnect: %s",
				max(first[0], first[1]), max(next[0], next[1]))
			independent := multiplex(t, r.port, []transfer{{"burst", direction + "-other", direction, size / 2}})
			durationBetween(t, independent[0], 0, 1.5)
		})
	}
}

func TestEnvoyOversizedBatchDebt(t *testing.T) {
	if os.Getenv("AGENTIO_TEST_ENVOY_BINARY") == "" {
		t.Skip("real Envoy test; run bin/test_network_limits.sh")
	}
	origin := startOrigin(t, false)
	r := startEnvoy(t, origin.port(), freePort(t), func(l object) {
		limit := nested(policy(filters(l)[1])["descriptors"].([]any)[0], "bandwidth_limit")
		limit["upload_burst_bytes"] = 4096
		limit["download_burst_bytes"] = 4096
	})
	for _, direction := range []string{"U", "D"} {
		t.Run(direction, func(t *testing.T) {
			started := time.Now()
			for range 3 {
				// Each transfer uses a fresh H2 connection; oversized callbacks must
				// be charged in full and leave their unpaid debt for the next one.
				multiplex(t, r.port, []transfer{{"oversized", direction, direction, size / 2}})
			}
			elapsed := time.Since(started)
			durationBetween(t, elapsed, 5, 12)
			t.Logf("768 KiB across three reconnects at 128 KiB/s: %s", elapsed)
			independent := multiplex(t, r.port, []transfer{{"oversized", direction + "-other", direction, 32768}})
			durationBetween(t, independent[0], 0, 1.5)
		})
	}
}

func TestEnvoyBandwidth(t *testing.T) {
	if os.Getenv("AGENTIO_TEST_ENVOY_BINARY") == "" {
		t.Skip("real Envoy test; run bin/test_network_limits.sh")
	}
	plain, encrypted := startOrigin(t, false), startOrigin(t, true)
	r := startEnvoy(t, plain.port(), encrypted.port(), nil)
	for _, direction := range []string{"U", "D"} {
		t.Run("aggregate_"+direction, func(t *testing.T) {
			results := multiplex(
				t,
				r.port,
				[]transfer{
					{"aggregate", direction, direction, size / 2},
					{"aggregate", direction, direction, size / 2},
				},
			)
			durationBetween(t, max(results[0], results[1]), 3, 15)
		})
	}
	t.Run("full_duplex", func(t *testing.T) {
		durationBetween(t, multiplex(t, r.port, []transfer{{"duplex", "echo", "E", size}})[0], 3, 15)
	})
	t.Run("retry_rejected", func(t *testing.T) {
		for _, header := range []string{"x-envoy-retry-on: 5xx", "x-envoy-retry-grpc-on: unavailable"} {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", r.port), time.Second)
			must(t, err)
			defer closeTest(t, c)
			must(t, c.SetDeadline(time.Now().Add(2*time.Second)))
			_, err = fmt.Fprintf(
				c,
				"CONNECT plain:80 HTTP/1.1\r\nHost: plain:80\r\nx-forwarded-for: 127.0.0.1\r\nx-tenant: retry\r\nx-sandbox: retry\r\n%s\r\n\r\n",
				header,
			)
			must(t, err)
			response, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
			must(t, err)
			must(t, response.Body.Close())
			if response.StatusCode != 400 {
				t.Fatal(response.Status)
			}
		}
	})
	t.Run("separate_budgets_on_one_h2_connection", func(t *testing.T) {
		results := multiplex(t, r.port, []transfer{{"isolation", "slow", "D", size}, {"vip", "fast", "D", size}})
		durationBetween(t, results[0], 3, 15)
		durationBetween(t, results[1], 0, 2)
	})
	t.Run("composite_keys", func(t *testing.T) {
		for _, d := range multiplex(t, r.port, []transfer{{"tenant-a", "same", "D", size}, {"tenant-b", "same", "D", size}}) {
			durationBetween(t, d, 3, 6)
		}
	})
	t.Run("http_tls_shared_bytes", func(t *testing.T) {
		var wg sync.WaitGroup
		durations := make([]time.Duration, 2)
		for i, encrypted := range []bool{false, true} {
			wg.Go(func() {
				started := time.Now()
				c := tunnel(t, r.port, "shared-http-tls", encrypted)
				defer closeTest(t, c)
				_, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
				must(t, err)
				resp, err := http.ReadResponse(bufio.NewReader(c), nil)
				must(t, err)
				data, err := io.ReadAll(resp.Body)
				must(t, err)
				must(t, resp.Body.Close())
				if resp.StatusCode != 200 || !bytes.Equal(data, payload(size)) {
					t.Errorf("HTTP/TLS payload: status %s, bytes %d", resp.Status, len(data))
				}
				durations[i] = time.Since(started)
			})
		}
		wg.Wait()
		durationBetween(t, max(durations[0], durations[1]), 6.5, 20)
	})
	t.Run(
		"missing_identity",
		func(t *testing.T) { newClient(t, r.port).open(t, "tenant-a", "", "plain:80", 403).close() },
	)
	t.Run("backpressure", func(t *testing.T) {
		baseline := rss(t, r.cmd.Process.Pid)
		peak := baseline
		c := tunnel(t, r.port, "backpressure", false)
		defer closeTest(t, c)
		produced := plain.produced.Load()
		_, err := io.WriteString(c, "B 67108864\n")
		must(t, err)
		started := time.Now()
		received := 0
		buf := make([]byte, 65536)
		for time.Since(started) < 3*time.Second {
			n, err := c.Read(buf)
			must(t, err)
			if n == 0 || !bytes.Equal(buf[:n], payload(n)) {
				t.Fatal("invalid body")
			}
			received += n
			peak = max(peak, rss(t, r.cmd.Process.Pid))
		}
		if float64(received) > rate*time.Since(started).Seconds()+131072 ||
			plain.produced.Load()-produced >= 8*1024*1024 ||
			peak-baseline >= 16*1024*1024 {
			t.Fatalf(
				"backpressure: received=%d produced=%d RSS growth=%d",
				received,
				plain.produced.Load()-produced,
				peak-baseline,
			)
		}
	})
	t.Run("cancel_pending_timers", func(t *testing.T) {
		for range 20 {
			c := tunnel(t, r.port, "cancel", false)
			_, err := fmt.Fprintf(c, "D %d\n", size)
			must(t, err)
			_, err = c.Read(make([]byte, 1))
			must(t, err)
			must(t, c.Close())
		}
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://%s/ready", r.admin))
		must(t, err)
		must(t, resp.Body.Close())
		if resp.StatusCode != 200 {
			t.Fatal(resp.Status)
		}
	})
	t.Run("lds_rate_changes_and_rollback", func(t *testing.T) {
		c := tunnel(t, r.port, "reload", false)
		defer closeTest(t, c)
		_, err := io.WriteString(c, "B 67108864\n")
		must(t, err)
		update := func(n int, reject bool) {
			r.reload(t, func(l object) {
				d := policy(filters(l)[1])["descriptors"].([]any)[0]
				nested(d, "bandwidth_limit")["download_bytes_per_second"] = strconv.Itoa(n)
			}, reject)
		}
		before := readWindow(t, c, 2*time.Second)
		update(4*rate, false)
		faster := readWindow(t, c, 2*time.Second)
		update(rate/2, false)
		slower := readWindow(t, c, 3*time.Second)
		update(8*rate, true)
		rollback := readWindow(t, c, 3*time.Second)
		if before < .5*rate || before > 1.6*rate || faster < 2.5*rate || faster > 5*rate || slower < .2*rate ||
			slower > rate ||
			rollback < .2*rate ||
			rollback > rate {
			t.Fatalf("rates before/fast/slow/rollback: %g %g %g %g", before, faster, slower, rollback)
		}
	})
}
