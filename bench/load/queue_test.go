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
	"testing"
	"time"
)

func TestQueueChangesRateAndDrainsAfterOverflow(t *testing.T) {
	queue := NewQueue(1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rates := make(chan float64, 1)
	executed := make(chan int, 2)
	release := make(chan struct{})
	dropped := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		queue.Run(ctx, 1, 0, rates, func(worker, sequence int, scheduled time.Time) {
			executed <- sequence
			<-release
		}, func() {
			select {
			case dropped <- struct{}{}:
			default:
			}
		})
	}()
	defer func() {
		cancel()
		close(release)
		<-done
	}()
	select {
	case sequence := <-executed:
		t.Fatalf("paused scheduler ran sequence %d", sequence)
	case <-time.After(20 * time.Millisecond):
	}
	rates <- 1.0 / 60
	select {
	case sequence := <-executed:
		if sequence != 0 {
			t.Fatalf("first sequence = %d, want 0", sequence)
		}
	case <-ctx.Done():
		t.Fatal("first rate update did not start traffic")
	}
	rates <- 1000
	select {
	case <-dropped:
	case <-ctx.Done():
		t.Fatal("rate update did not fill the queue")
	}
	if got := queue.Pending(); got != 1 {
		t.Fatalf("pending = %d, want 1", got)
	}
	cancel()
	select {
	case <-done:
		t.Fatal("scheduler returned before the accepted work drained")
	default:
	}
	// Release and assert the queued request is delivered after cancellation.
	release <- struct{}{}
	select {
	case sequence := <-executed:
		if sequence != 1 {
			t.Fatalf("queued sequence = %d, want 1", sequence)
		}
	case <-time.After(time.Second):
		t.Fatal("queued request was not drained")
	}
}
