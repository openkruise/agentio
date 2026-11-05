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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Done is evaluated whenever a demand parks. Count rechecks without changing the
// client's notification path; ready lets the publisher wait for all cold callers.
type benchmarkWaitContext struct {
	context.Context
	ready   chan<- struct{}
	waits   *atomic.Int64
	started bool
}

func (c *benchmarkWaitContext) Done() <-chan struct{} {
	c.waits.Add(1)
	if !c.started {
		c.started = true
		c.ready <- struct{}{}
	}
	return c.Context.Done()
}

// One operation is a wave of N different demands, fulfilled one at a time. All
// callers have reached their wait before the first resource is published.
func BenchmarkDemandColdWave(b *testing.B) {
	for _, n := range []int{32, 256, 1024} {
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			c := benchmarkClient(b, false)
			value, err := anypb.New(wrapperspb.String("value"))
			if err != nil {
				b.Fatal(err)
			}
			responses := make([]*discovery.DeltaDiscoveryResponse, n)
			for i := range n {
				responses[i] = &discovery.DeltaDiscoveryResponse{
					TypeUrl:   testType,
					Resources: []*discovery.Resource{{Name: fmt.Sprintf("resource-%d", i), Resource: value}},
				}
			}
			var waits atomic.Int64
			b.ReportAllocs()
			for b.Loop() {
				c.reset()
				ready := make(chan struct{}, n)
				done := make([]chan error, n)
				for i := range n {
					done[i] = make(chan error, 1)
					go func() {
						ctx := &benchmarkWaitContext{Context: b.Context(), ready: ready, waits: &waits}
						_, err := c.Demand(ctx, testType, responses[i].Resources[0].Name)
						done[i] <- err
					}()
				}
				for range n {
					<-ready
				}
				for i, r := range responses {
					if err := c.apply(r); err != nil {
						b.Fatal(err)
					}
					if err := <-done[i]; err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(waits.Load())/float64(b.N*n), "waits/demand")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n), "ns/demand")
		})
	}
}

// Use the same subscribed resources and typed decoding in pure and mixed loads.
func benchmarkTypedBatch(b *testing.B, size int) (*Client, *discovery.DeltaDiscoveryResponse) {
	b.Helper()
	c := benchmarkClient(b, false)
	c.types[testType].watch.Transform = func(a *anypb.Any) (any, error) {
		v := &wrapperspb.StringValue{}
		return v, a.UnmarshalTo(v)
	}
	value, err := anypb.New(wrapperspb.String(strings.Repeat("v", 256)))
	if err != nil {
		b.Fatal(err)
	}
	batch := &discovery.DeltaDiscoveryResponse{TypeUrl: testType}
	for i := range size {
		if _, err := c.Acquire(testType, fmt.Sprintf("resource-%d", i)); err != nil {
			b.Fatal(err)
		}
		batch.Resources = append(
			batch.Resources,
			&discovery.Resource{Name: fmt.Sprintf("resource-%d", i), Resource: value},
		)
	}
	if err := c.apply(batch); err != nil {
		b.Fatal(err)
	}
	return c, batch
}

// Measure the writer alone, with the same typed resources as the mixed load.
func BenchmarkDemandBatchApply(b *testing.B) {
	for _, n := range []int{1, 1024} {
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			c, batch := benchmarkTypedBatch(b, n)
			b.ReportAllocs()
			for b.Loop() {
				if err := c.apply(batch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Background typed decoding competes with hot requests. Report update throughput
// as well as sampled request P99, so reader gains cannot hide writer starvation.
func BenchmarkDemandDuringBatch(b *testing.B) {
	benchmarkDemandDuringBatch(b, 0)
}

// Keep the offered update rate below saturation to separate update cost from
// reader/writer CPU competition. Report achieved rate rather than assume it.
func BenchmarkDemandDuringPacedBatch(b *testing.B) {
	benchmarkDemandDuringBatch(b, 2*time.Millisecond)
}

func benchmarkDemandDuringBatch(b *testing.B, interval time.Duration) {
	c, batch := benchmarkTypedBatch(b, 1024)
	if _, err := c.Acquire(testType, "hot"); err != nil {
		b.Fatal(err)
	}
	hot := &discovery.DeltaDiscoveryResponse{
		TypeUrl:   testType,
		Resources: []*discovery.Resource{{Name: "hot", Resource: batch.Resources[0].Resource}},
	}
	if err := c.apply(hot); err != nil {
		b.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	var updates atomic.Int64
	var mu sync.Mutex
	var samples []int64
	var ticks <-chan time.Time
	if interval > 0 {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		ticks = ticker.C
	}
	b.ResetTimer()
	go func() {
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if ticks != nil {
				select {
				case <-stop:
					done <- nil
					return
				case <-ticks:
				}
			}
			if err := c.apply(batch); err != nil {
				done <- err
				return
			}
			updates.Add(1)
		}
	}()
	b.RunParallel(func(pb *testing.PB) {
		var local []int64
		calls := 0
		for pb.Next() {
			var start time.Time
			if calls%128 == 0 {
				start = time.Now()
			}
			if _, err := c.Demand(b.Context(), testType, "hot"); err != nil {
				b.Error(err)
			}
			if !start.IsZero() {
				local = append(local, time.Since(start).Nanoseconds())
			}
			calls++
		}
		mu.Lock()
		samples = append(samples, local...)
		mu.Unlock()
	})
	b.StopTimer()
	close(stop)
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	slices.Sort(samples)
	b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), "p99-ns")
	b.ReportMetric(float64(updates.Load())/b.Elapsed().Seconds(), "batches/s")
}
