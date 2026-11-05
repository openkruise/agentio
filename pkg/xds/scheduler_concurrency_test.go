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

package xds

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// Force dispatch/completion into the unlocked merge window. An add followed by
// a delete is empty only if the add has not been dispatched; otherwise the
// client must receive the delete. This catches replay of already-consumed work.
func TestPushSchedulerMergeInterleavings(t *testing.T) {
	for _, tc := range []struct {
		name       string
		processing bool
		action     string
		consumed   bool
	}{
		{name: "pending"},
		{name: "pending_dispatched", action: "dispatch", consumed: true},
		{name: "pending_completed", action: "complete", consumed: true},
		{name: "processing", processing: true},
		{name: "processing_requeued", processing: true, action: "requeue"},
		{name: "processing_requeued_and_dispatched", processing: true, action: "dispatch", consumed: true},
		{name: "processing_requeued_and_completed", processing: true, action: "complete", consumed: true},
		{name: "pending_cancelled", action: "cancel"},
		{name: "processing_cancelled", processing: true, action: "cancel"},
		{name: "pending_closed", action: "close"},
		{name: "processing_closed", processing: true, action: "close"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheduler := NewPushScheduler(2)
			t.Cleanup(scheduler.Close)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			connection := newPushConnection(ctx)
			resource := addressResource(t, "workload-a", "one")
			added := updateFromChanges(t, []model.ResourceChange{{Key: resource.Key, New: &resource}})
			removed := updateFromChanges(t, []model.ResourceChange{{Key: resource.Key, Old: &resource}})
			var active *scheduledPush
			if tc.processing {
				scheduler.Enqueue(connection, fullUpdate(t, "initial"))
				active = nextSchedulerPush(t, scheduler)
			}
			scheduler.Enqueue(connection, added)
			scheduler.mu.Lock()
			entry, _ := scheduler.queuedLocked(connection)
			scheduler.mu.Unlock()

			entered, resume, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var release sync.Once
			unblock := func() { release.Do(func() { close(resume) }) }
			t.Cleanup(func() { unblock(); awaitSchedulerOperation(t, finished) })
			go func() {
				defer close(finished)
				scheduler.enqueue(connection, removed, func(older, newer xdsstore.Update) xdsstore.Update {
					close(entered)
					<-resume
					return xdsstore.Merge(older, newer)
				})
			}()
			awaitSchedulerOperation(t, entered)

			// An unrelated connection can enqueue, dispatch and finish even
			// while this connection's merge is deliberately stalled.
			progressed := make(chan struct{})
			go func() {
				defer close(progressed)
				other := newPushConnection(context.Background())
				scheduler.Enqueue(other, added)
				if tc.action == "cancel" {
					cancel()
					// Race explicit cleanup with the context callback.
					scheduler.cancel(connection)
					return
				}
				if tc.action == "close" {
					scheduler.Close()
					return
				}
				if tc.processing && tc.action != "" {
					scheduler.Done(active)
					active = nil
				}
				if !tc.processing && tc.consumed {
					active = nextSchedulerPush(t, scheduler)
					if active.Connection != connection {
						t.Error("FIFO head changed during merge")
					}
				}
				// A pending, unconsumed connection is the FIFO head; leave it
				// in place. In every other case the unrelated entry is next.
				if tc.processing || tc.consumed {
					otherPush := nextSchedulerPush(t, scheduler)
					if otherPush.Connection != other {
						t.Error("unrelated connection lost its FIFO position")
					}
					scheduler.Done(otherPush)
				}
				if tc.processing && tc.consumed {
					active = nextSchedulerPush(t, scheduler)
					if active.Connection != connection {
						t.Error("requeued entry was not dispatched")
					}
				}
				if tc.action == "complete" {
					scheduler.Done(active)
					active = nil
				}
			}()
			awaitSchedulerOperation(t, progressed)
			unblock()
			awaitSchedulerOperation(t, finished)
			if active != nil {
				scheduler.Done(active)
			}
			if tc.action == "cancel" || tc.action == "close" {
				scheduler.mu.Lock()
				_, pending := scheduler.pending[connection]
				_, processing := scheduler.processing[connection]
				_, registered := scheduler.cancellations[connection]
				scheduler.mu.Unlock()
				if pending || processing || registered {
					t.Fatal("merge revived a cancelled/closed connection")
				}
				// AfterFunc can remove the entry before releasing its slot.
				testutil.Eventually(t, func() bool { return len(scheduler.slots) == 0 }, "scheduler capacity was not released")
				return
			}
			push := nextSchedulerPush(t, scheduler)
			if push.Connection != connection {
				t.Fatal("merged update scheduled for the wrong connection")
			}
			want := xdsstore.Merge(added, removed)
			if tc.consumed {
				want = removed
			} else if !push.Started.Equal(entry.Started) {
				t.Fatal("merge lost the first enqueue timestamp")
			}
			assertSchedulerUpdate(t, push.Update, want)
			assertSchedulerUpdate(t, entry.Update, added)
			scheduler.Done(push)
		})
	}
}

func TestPushSchedulerSerializesEnqueueDuringMerge(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connection := newPushConnection(context.Background())
	one := addressResource(t, "workload-a", "one")
	two := addressResource(t, "workload-a", "two")
	added := updateFromChanges(t, []model.ResourceChange{{Key: one.Key, New: &one}})
	removed := updateFromChanges(t, []model.ResourceChange{{Key: one.Key, Old: &one}})
	readded := updateFromChanges(t, []model.ResourceChange{{Key: two.Key, New: &two}})
	scheduler.Enqueue(connection, added)
	entered, resume, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(resume) }) }
	t.Cleanup(func() { unblock(); awaitSchedulerOperation(t, finished) })
	go func() {
		defer close(finished)
		scheduler.enqueue(connection, removed, func(older, newer xdsstore.Update) xdsstore.Update {
			close(entered)
			<-resume
			return xdsstore.Merge(older, newer)
		})
	}()
	awaitSchedulerOperation(t, entered)
	if connection.enqueueMu.TryLock() {
		connection.enqueueMu.Unlock()
		t.Fatal("merge did not retain exclusive enqueue ownership")
	}
	laterFinished := make(chan struct{})
	go func() { scheduler.Enqueue(connection, readded); close(laterFinished) }()
	unblock()
	awaitSchedulerOperation(t, finished)
	awaitSchedulerOperation(t, laterFinished)
	push := nextSchedulerPush(t, scheduler)
	assertSchedulerUpdate(t, push.Update, xdsstore.Merge(xdsstore.Merge(added, removed), readded))
	scheduler.Done(push)
}

func TestPushSchedulerPreservesZeroUpdate(t *testing.T) {
	for _, processing := range []bool{false, true} {
		name := "pending"
		if processing {
			name = "processing"
		}
		t.Run(name, func(t *testing.T) {
			scheduler := NewPushScheduler(1)
			t.Cleanup(scheduler.Close)
			connection := newPushConnection(context.Background())
			var first *scheduledPush
			if processing {
				scheduler.Enqueue(connection, fullUpdate(t, "first"))
				first = nextSchedulerPush(t, scheduler)
			}

			before := time.Now()
			scheduler.Enqueue(connection, xdsstore.Update{})
			after := time.Now()
			scheduler.Done(first)

			push := nextSchedulerPush(t, scheduler)
			if push.Connection != connection {
				t.Fatal("zero update was not delivered to its connection")
			}
			assertSchedulerUpdate(t, push.Update, xdsstore.Update{})
			if push.Started.Before(before) || push.Started.After(after) {
				t.Fatalf("started = %v, want zero-update enqueue window [%v, %v]", push.Started, before, after)
			}
			scheduler.Done(push)
		})
	}
}

func nextSchedulerPush(t *testing.T, scheduler *PushScheduler) *scheduledPush {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	push := scheduler.Next(ctx)
	if push == nil {
		t.Fatal("scheduler failed to dispatch before timeout")
	}
	return push
}

func awaitSchedulerOperation(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scheduler operation blocked during merge")
	}
}

func assertSchedulerUpdate(t *testing.T, got, want xdsstore.Update) {
	t.Helper()
	if got.Version() != want.Version() || got.FullFor(model.AddressType) != want.FullFor(model.AddressType) ||
		!reflect.DeepEqual(got.Candidates(model.AddressType), want.Candidates(model.AddressType)) {
		t.Fatalf("update = %#v, want %#v", got, want)
	}
}
