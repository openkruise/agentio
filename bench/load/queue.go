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
	"math"
	"sync"
	"time"
)

type arrival struct {
	sequence  int
	scheduled time.Time
}

// Queue is a fixed-capacity open-loop scheduler for a single continuous run.
type Queue struct {
	jobs chan arrival
}

// NewQueue bounds how many offered arrivals can wait for a worker.
func NewQueue(capacity int) *Queue {
	return &Queue{jobs: make(chan arrival, capacity)}
}

// Pending reports how many arrivals are waiting for a worker.
func (q *Queue) Pending() int {
	return len(q.jobs)
}

// Run schedules arrivals at the supplied rate and calls drop when the queue is full.
// An update changes the rate without restarting workers. A nonpositive rate pauses arrivals.
// Cancellation stops new arrivals and drains the queue before returning.
func (q *Queue) Run(
	ctx context.Context,
	workers int,
	rate float64,
	rates <-chan float64,
	operation func(worker, sequence int, scheduled time.Time),
	drop func(),
) {
	var active sync.WaitGroup
	for worker := range workers {
		active.Go(func() {
			for job := range q.jobs {
				operation(worker, job.sequence, job.scheduled)
			}
		})
	}
	defer func() {
		close(q.jobs)
		active.Wait()
	}()

	timer := time.NewTimer(0)
	defer timer.Stop()
	next := time.Now()
	interval := rateInterval(rate)
	sequence := 0
	for ctx.Err() == nil {
		var tick <-chan time.Time
		if interval > 0 {
			timer.Reset(time.Until(next))
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case updated, ok := <-rates:
			if !ok {
				rates = nil
				continue
			}
			interval = rateInterval(updated)
			next = time.Now()
		case <-tick:
			select {
			case q.jobs <- arrival{sequence, next}:
			default:
				drop()
			}
			next = next.Add(interval)
			sequence++
		}
	}
}

func rateInterval(rate float64) time.Duration {
	if rate <= 0 {
		return 0
	}
	nanoseconds := float64(time.Second) / rate
	if nanoseconds >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	return max(time.Nanosecond, time.Duration(nanoseconds))
}
