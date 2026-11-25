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

package xdsclient

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Block the backend until every caller is waiting. TTL zero makes each wave
// cold, even when all callers requested the same name in the previous wave.
func BenchmarkSandboxQueryColdWave(b *testing.B) {
	const workers = 64
	for _, keys := range []int{1, workers} {
		b.Run(fmt.Sprintf("Keys%d", keys), func(b *testing.B) {
			value, err := anypb.New(wrapperspb.String("policy"))
			if err != nil {
				b.Fatal(err)
			}
			var calls, waits atomic.Int64
			var gate chan struct{}
			c := benchmarkWatch(
				b,
				Watch{
					TypeURL: testType,
					Query: func(_ context.Context, name string) (string, *anypb.Any, time.Duration, error) {
						calls.Add(1)
						<-gate
						return name, value, 0, nil
					},
				},
			)
			leases := make([]*Subscription, keys)
			for i := range keys {
				leases[i], err = c.Acquire(testType, fmt.Sprintf("sandbox:%06d", i))
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(leases[i].Release)
			}
			b.ReportAllocs()
			for b.Loop() {
				gate = make(chan struct{})
				ready := make(chan struct{}, workers)
				done := make(chan error, workers)
				for i := range workers {
					go func() {
						ctx := &benchmarkWaitContext{Context: b.Context(), ready: ready, waits: &waits}
						_, err := leases[i%keys].Demand(ctx)
						done <- err
					}()
				}
				for range workers {
					<-ready
				}
				close(gate)
				for range workers {
					if err := <-done; err != nil {
						b.Fatal(err)
					}
				}
			}
			got := calls.Load()
			b.ReportMetric(float64(got)/float64(b.N), "lookups/wave")
			if got != int64(keys)*int64(b.N) {
				b.Fatalf("unexpected backend lookup count: %d", got)
			}
		})
	}
}
