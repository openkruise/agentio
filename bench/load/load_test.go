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

package load

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestIdentityDistributionAndConcurrency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		seen := map[int]int{}
		inFlight, peak := 0, 0
		result, err := Run(t.Context(), Config{
			Requests:    100,
			Identities:  10,
			Offset:      50,
			Concurrency: 4,
			Duration:    time.Minute,
		}, func(ctx context.Context, identity int) error {
			mu.Lock()
			seen[identity]++
			inFlight++
			peak = max(peak, inFlight)
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			return nil
		})
		if err != nil || result.Operations != 100 || result.UniqueAttempted != 10 || peak != 4 {
			t.Fatalf("result=%+v peak=%d error=%v", result, peak, err)
		}
		for i := 50; i < 60; i++ {
			if seen[i] != 10 {
				t.Fatalf("identity %d: got %d calls", i, seen[i])
			}
		}
	})
}

func TestRateLatencyIncludesQueueing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		result, err := Run(t.Context(), Config{
			Requests:    3,
			Identities:  3,
			Concurrency: 1,
			Rate:        10,
			Duration:    time.Minute,
		}, func(context.Context, int) error {
			time.Sleep(200 * time.Millisecond)
			return nil
		})
		if err != nil || result.P50MS != 300 || result.MaxMS != 400 || result.Seconds != .6 {
			t.Fatalf("queue delay missing: %+v, %v", result, err)
		}
	})
}

func TestCancellationDoesNotCountScheduledRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		result, err := Run(ctx, Config{
			Requests:    100,
			Identities:  100,
			Concurrency: 4,
			Rate:        10,
			Duration:    time.Minute,
		}, func(context.Context, int) error {
			return nil
		})
		if !errors.Is(err, context.Canceled) || result.Operations != 1 || result.UniqueAttempted != 1 {
			t.Fatalf("unsent requests counted: %+v, %v", result, err)
		}
	})
}

func TestDurationCancelsInFlightRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		result, err := Run(t.Context(), Config{
			Requests:    10,
			Identities:  10,
			Concurrency: 2,
			Duration:    time.Second,
		}, func(ctx context.Context, _ int) error {
			<-ctx.Done()
			return ctx.Err()
		})
		if !errors.Is(err, context.DeadlineExceeded) || result.Operations != 2 || result.Errors != 2 {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
}

func TestCommonStartAndMeasurementWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now().Add(time.Second)
		var started, finished time.Time
		cfg := Config{
			Requests:    1,
			Identities:  1,
			Concurrency: 1,
			Duration:    time.Second,
			Start:       start,
			Started: func() {
				started = time.Now()
			},
			Finished: func() {
				finished = time.Now()
			},
		}
		result, err := Run(t.Context(), cfg, func(context.Context, int) error {
			time.Sleep(time.Millisecond)
			return nil
		})
		if err != nil || !started.Equal(start) || finished.Sub(started) != time.Millisecond || result.Seconds != .001 {
			t.Fatalf("incorrect measurement window: %+v %v %v %v", result, started, finished, err)
		}
		if _, err := Run(t.Context(), cfg, func(context.Context, int) error {
			t.Fatal("late run should not invoke operation")
			return nil
		}); err == nil {
			t.Fatal("missed start must fail")
		}
	})
}
