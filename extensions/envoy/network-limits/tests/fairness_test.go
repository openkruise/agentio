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
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func TestEnvoySharedBucketProgress(t *testing.T) {
	for _, direction := range []string{"P", "D"} {
		for _, count := range []int{8, 32} {
			t.Run(fmt.Sprintf("%s/%d", direction, count), func(t *testing.T) {
				origin := startOrigin(t, false)
				r := startEnvoy(t, origin.port(), freePort(t), func(l object) {
					limits := nested(obj(policy(filters(l)[1])["descriptors"].([]any)[0]), "bandwidth_limit")
					limits["upload_bytes_per_second"] = 1048576
					limits["download_bytes_per_second"] = 1048576
				})
				clients := []*h2client{
					newClient(t, r.port),
					newClient(t, r.port),
					newClient(t, r.port),
					newClient(t, r.port),
				}
				streams := make([]*stream, count)
				for i := range streams {
					streams[i] = clients[i%len(clients)].open(t, "test", "shared", "plain:80", 200)
				}
				type result struct {
					gap time.Duration
					err error
				}
				results := make(chan result, count)
				start := make(chan struct{})
				var writers sync.WaitGroup
				writerErrors := make(chan error, count)
				for _, s := range streams {
					writers.Go(func() {
						<-start
						_, err := fmt.Fprintf(s.writer, "%s %d\n", direction, size)
						if err == nil && direction == "P" {
							_, err = s.writer.Write(payload(size))
						}
						writerErrors <- errors.Join(err, s.writer.Close())
					})
					go func() {
						<-start
						last := time.Now()
						var gap time.Duration
						var body bytes.Buffer
						buf := make([]byte, 16384)
						for {
							n, err := s.response.Body.Read(buf)
							if n > 0 {
								now := time.Now()
								gap = max(gap, now.Sub(last))
								last = now
								body.Write(buf[:n])
							}
							if err != nil {
								if errors.Is(err, io.EOF) {
									err = nil
								}
								expected := payload(size)
								if direction == "P" {
									expected = append(bytes.Repeat([]byte("p"), size/16384), []byte("OK")...)
								}
								if err == nil && !bytes.Equal(body.Bytes(), expected) {
									err = fmt.Errorf(
										"invalid transfer: received %d bytes, expected %d",
										body.Len(),
										len(expected),
									)
								}
								results <- result{gap, err}
								return
							}
						}
					}()
				}
				begun := time.Now()
				close(start)
				var gap time.Duration
				var transferError error
				for range count {
					result := <-results
					transferError = errors.Join(transferError, result.err)
					gap = max(gap, result.gap)
				}
				writers.Wait()
				for range count {
					transferError = errors.Join(transferError, <-writerErrors)
				}
				must(t, transferError)
				elapsed := time.Since(begun)
				// Allow two 64 KiB watermark batches per flow plus dispatcher jitter per round.
				bound := time.Duration(count)*time.Second/8 + time.Second
				if gap > bound {
					t.Fatalf("longest no-progress interval %s exceeds %s", gap, bound)
				}
				rate := float64(count*size) / elapsed.Seconds() / 1048576
				if rate < 0.85 || rate > 1.15 {
					t.Fatalf("aggregate %.3f MiB/s, expected 1 MiB/s", rate)
				}
				t.Logf("%d streams, aggregate %.3f MiB/s, longest gap %s; every payload verified", count, rate, gap)
			})
		}
	}
}
