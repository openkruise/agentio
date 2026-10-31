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
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/openkruise/agentio/bench/load"
)

// Background streams use a different tenant from throughput and admission probes.
type residents struct {
	ctx        context.Context
	c          config
	transports []*http2.Transport
}

func (r *residents) open(setup context.Context, tenant string, i int, debt bool) (func() error, error) {
	ctx, cancel := context.WithCancel(r.ctx)
	stop := context.AfterFunc(setup, cancel)
	defer stop()
	reader, writer := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "CONNECT", "http://plain:80", reader)
	if err != nil {
		cancel()
		return nil, errors.Join(err, reader.Close(), writer.Close())
	}
	req.Header.Set("x-tenant", tenant)
	req.Header.Set("x-sandbox", fmt.Sprintf("bucket-%d", i))
	response, err := r.transports[i%len(r.transports)].RoundTrip(req)
	if err != nil {
		cancel()
		return nil, errors.Join(err, reader.Close(), writer.Close())
	}
	closeStream := func() error {
		cancel()
		return errors.Join(writer.Close(), reader.Close(), response.Body.Close())
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.Join(fmt.Errorf("CONNECT %s/%d: %s", tenant, i, response.Status), closeStream())
	}
	if debt {
		// One DATA frame charges a known number of bytes; an origin ACK proves forwarding.
		_, err = io.WriteString(writer, "B "+strings.Repeat("x", r.c.DebtBytes-3)+"\n")
		err = errors.Join(err, writer.Close())
		if err == nil {
			var ack [1]byte
			_, err = io.ReadFull(response.Body, ack[:])
			if err == nil && ack[0] != 'K' {
				err = fmt.Errorf("invalid bucket seed acknowledgement: %q", ack)
			}
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
			}
		}
		return nil, errors.Join(err, closeStream())
	}
	return func() error {
		// Graceful EOF avoids measuring HTTP/2 reset-flood protection as bucket overhead.
		err := writer.Close()
		_, readErr := io.Copy(io.Discard, response.Body)
		return errors.Join(err, readErr, closeStream())
	}, nil
}

func activeUpstreams(ctx context.Context, address string) (uint64, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		"http://"+address+"/stats?format=json&filter=upstream_cx_active",
		nil,
	)
	if err != nil {
		return 0, err
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	var data struct {
		Stats []struct {
			Value uint64 `json:"value"`
		} `json:"stats"`
	}
	err = errors.Join(json.NewDecoder(response.Body).Decode(&data), response.Body.Close())
	if err != nil {
		return 0, err
	}
	if response.StatusCode != http.StatusOK || len(data.Stats) == 0 {
		return 0, fmt.Errorf("missing upstream gauges: %s", response.Status)
	}
	var total uint64
	for _, stat := range data.Stats {
		total += stat.Value
	}
	return total, nil
}

func waitUpstreams(ctx context.Context, address string, want uint64) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		got, err := activeUpstreams(ctx, address)
		if err != nil {
			return err
		}
		if got == want {
			return nil
		}
		if err := pause(ctx, 20*time.Millisecond); err != nil {
			return fmt.Errorf("active upstreams=%d, want %d: %w", got, want, err)
		}
	}
}

//nolint:gocyclo,funlen // Keep population, probes, and quiet recovery in one measured lifecycle.
func runBuckets(ctx context.Context, c config) (result map[string]any, resultErr error) {
	r := residents{ctx: ctx, c: c}
	for range c.Connections {
		r.transports = append(r.transports, &http2.Transport{
			AllowHTTP:                  true,
			StrictMaxConcurrentStreams: true,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", c.Target)
			},
		})
	}
	leases := make([]func() error, c.ResidentBuckets)
	defer func() {
		for _, closeStream := range leases {
			if closeStream != nil {
				resultErr = errors.Join(resultErr, closeStream())
			}
		}
		for _, tr := range r.transports {
			tr.CloseIdleConnections()
		}
	}()
	before, err := sample(c.EnvoyPID, c.Ticks)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	var populated load.Result
	if c.ResidentBuckets > 0 {
		populated, err = load.Run(ctx, load.Config{
			Requests:    c.ResidentBuckets,
			Identities:  c.ResidentBuckets,
			Concurrency: 32,
			Duration:    c.SetupTimeout,
		}, func(setup context.Context, i int) error {
			var err error
			leases[i], err = r.open(setup, "resident", i, c.ResidentMode == "debt")
			return err
		})
		if err != nil || populated.Errors != 0 || populated.Operations != c.ResidentBuckets {
			return nil, errors.Join(
				fmt.Errorf(
					"bucket population %d/%d errors=%d: %s",
					populated.Operations,
					c.ResidentBuckets,
					populated.Errors,
					populated.FirstError,
				),
				err,
			)
		}
	}
	want := uint64(0)
	if c.ResidentMode == "active" {
		want = uint64(c.ResidentBuckets)
	}
	if err := waitUpstreams(ctx, c.Admin, want); err != nil {
		return nil, err
	}
	if c.ResidentMode == "active" {
		// A CONNECT response does not mean the origin/generator has settled after mass setup.
		if err := pause(ctx, c.Warmup); err != nil {
			return nil, err
		}
	}
	filled, err := sample(c.EnvoyPID, c.Ticks)
	if err != nil {
		return nil, err
	}
	churnStart := time.Now()
	churn, err := load.Run(
		ctx,
		load.Config{Requests: c.ProbeRequests, Identities: c.ProbeRequests, Concurrency: 32, Duration: c.SetupTimeout},
		func(setup context.Context, i int) error {
			closeStream, err := r.open(setup, "perf", i, false)
			if err != nil {
				return err
			}
			return closeStream()
		},
	)
	if err != nil || churn.Errors != 0 || churn.Operations != c.ProbeRequests {
		return nil, errors.Join(
			fmt.Errorf(
				"admission probe %d/%d errors=%d: %s",
				churn.Operations,
				c.ProbeRequests,
				churn.Errors,
				churn.FirstError,
			),
			err,
		)
	}
	if err := waitUpstreams(ctx, c.Admin, want); err != nil {
		return nil, err
	}
	churnEnd, err := sample(c.EnvoyPID, c.Ticks)
	if err != nil {
		return nil, err
	}
	churnElapsed := time.Since(churnStart)
	result, err = runLoad(ctx, c)
	if err != nil {
		return nil, err
	}
	debtLifetime := float64(c.DebtBytes)
	if c.ReloadPath != "" {
		debtLifetime /= 2
	}
	if c.ResidentBuckets > 0 && c.ResidentMode == "debt" && time.Since(started).Seconds() >= debtLifetime {
		return nil, fmt.Errorf("seed debt expired during measurement; increase -debt-bytes")
	}
	result["resident_buckets"], result["resident_mode"] = c.ResidentBuckets, c.ResidentMode
	result["population"], result["admission"] = populated, churn
	result["population_envoy_cpu_seconds"] = filled.CPU - before.CPU
	result["admission_envoy_cpu_seconds"] = churnEnd.CPU - filled.CPU
	result["admission_wall_seconds"] = churnElapsed.Seconds()
	result["rss_empty_mib"], result["rss_populated_mib"] = float64(before.RSS)/1048576, float64(filled.RSS)/1048576
	released := time.Now()
	for i, closeStream := range leases {
		if closeStream != nil {
			if err := closeStream(); err != nil {
				return nil, err
			}
			leases[i] = nil
		}
	}
	if err := waitUpstreams(ctx, c.Admin, 0); err != nil {
		return nil, err
	}
	result["release_ms"] = time.Since(released).Seconds() * 1000
	var recovery []map[string]any
	for until := time.Now().Add(c.RecoveryWait); time.Now().Before(until); {
		if err := pause(ctx, min(time.Second, time.Until(until))); err != nil {
			return nil, err
		}
		value, err := sample(c.EnvoyPID, c.Ticks)
		if err != nil {
			return nil, err
		}
		recovery = append(
			recovery,
			map[string]any{
				"elapsed_seconds": time.Since(started).Seconds(),
				"rss_mib":         float64(value.RSS) / 1048576,
				"cpu_seconds":     value.CPU,
			},
		)
	}
	result["recovery"] = recovery
	final, err := sample(c.EnvoyPID, c.Ticks)
	if err != nil {
		return nil, err
	}
	result["rss_released_mib"] = float64(final.RSS) / 1048576
	return result, nil
}
