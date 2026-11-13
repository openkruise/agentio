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
	"testing"
	"time"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func TestPushSchedulerMergesPendingUpdatesAndKeepsFIFOOrder(t *testing.T) {
	scheduler := NewPushScheduler(2)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	connectionB := newPushConnection(context.Background())
	resourceA0 := addressResource(t, "cluster//Pod/demo/a", "a-0")
	resourceA1 := addressResource(t, "cluster//Pod/demo/a", "a-1")
	resourceA2 := addressResource(t, "cluster//Pod/demo/a", "a-2")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	updateA1 := updateFromChanges(t, []model.ResourceChange{{Key: resourceA1.Key, Old: &resourceA0, New: &resourceA1}})
	updateA2 := updateFromChanges(t, []model.ResourceChange{{Key: resourceA2.Key, Old: &resourceA1, New: &resourceA2}})
	updateB := updateFromChanges(t, []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}})

	scheduler.Enqueue(connectionA, updateA1)
	scheduler.Enqueue(connectionB, updateB)
	scheduler.Enqueue(connectionA, updateA2)

	first := scheduler.Next(context.Background())
	if first == nil || first.Connection != connectionA {
		t.Fatalf("first scheduled connection = %v, want connection A", first)
	}
	changes := first.Update.Candidates(model.AddressType)
	if first.Update.Version() != updateA2.Version() || len(changes) != 1 || changes[0].Key != resourceA0.Key {
		t.Fatalf("merged update lost candidate: %#v", first.Update)
	}
	second := scheduler.Next(context.Background())
	if second == nil || second.Connection != connectionB {
		t.Fatalf("second scheduled connection = %v, want connection B", second)
	}
	scheduler.Done(first)
	scheduler.Done(second)
}

func TestPushSchedulerRequeuesMergedUpdateAfterProcessing(t *testing.T) {
	scheduler := NewPushScheduler(2)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	connectionB := newPushConnection(context.Background())
	resourceA0 := addressResource(t, "cluster//Pod/demo/a", "a-0")
	resourceA1 := addressResource(t, "cluster//Pod/demo/a", "a-1")
	resourceA2 := addressResource(t, "cluster//Pod/demo/a", "a-2")
	resourceA3 := addressResource(t, "cluster//Pod/demo/a", "a-3")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	updateA1 := updateFromChanges(t, []model.ResourceChange{{Key: resourceA1.Key, Old: &resourceA0, New: &resourceA1}})
	updateA2 := updateFromChanges(t, []model.ResourceChange{{Key: resourceA2.Key, Old: &resourceA1, New: &resourceA2}})
	updateA3 := updateFromChanges(t, []model.ResourceChange{{Key: resourceA3.Key, Old: &resourceA2, New: &resourceA3}})
	updateB := updateFromChanges(t, []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}})

	scheduler.Enqueue(connectionA, updateA1)
	first := scheduler.Next(context.Background())
	scheduler.Enqueue(connectionA, updateA2)
	scheduler.Enqueue(connectionB, updateB)
	scheduler.Enqueue(connectionA, updateA3)
	scheduler.Done(first)

	second := scheduler.Next(context.Background())
	if second == nil || second.Connection != connectionB {
		t.Fatalf("second scheduled connection = %v, want already-pending connection B", second)
	}
	scheduler.Done(second)
	third := scheduler.Next(context.Background())
	if third == nil || third.Connection != connectionA {
		t.Fatalf("third scheduled connection = %v, want requeued connection A", third)
	}
	changes := third.Update.Candidates(model.AddressType)
	if third.Update.Version() != updateA3.Version() || len(changes) != 1 || changes[0].Key != resourceA1.Key {
		t.Fatalf("merged update lost candidate: %#v", third.Update)
	}
	scheduler.Done(third)
}

func TestPushSchedulerPendingMergeKeepsFirstStartTime(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connection := newPushConnection(context.Background())

	before := time.Now()
	scheduler.Enqueue(connection, fullUpdate(t, "one"))
	after := time.Now()
	scheduler.Enqueue(connection, fullUpdate(t, "two"))

	push := scheduler.Next(context.Background())
	if push.Started.Before(before) || push.Started.After(after) {
		t.Fatalf("started = %v, want first enqueue window [%v, %v]", push.Started, before, after)
	}
	scheduler.Done(push)
}

func TestPushSchedulerProcessingMergeKeepsLaterBatchStartTime(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connection := newPushConnection(context.Background())
	scheduler.Enqueue(connection, fullUpdate(t, "one"))
	first := scheduler.Next(context.Background())

	beforeLater := time.Now()
	scheduler.Enqueue(connection, fullUpdate(t, "two"))
	afterLater := time.Now()
	scheduler.Enqueue(connection, fullUpdate(t, "three"))
	scheduler.Done(first)

	second := scheduler.Next(context.Background())
	if second.Started.Before(beforeLater) || second.Started.After(afterLater) {
		t.Fatalf("started = %v, want later-batch window [%v, %v]", second.Started, beforeLater, afterLater)
	}
	scheduler.Done(second)
}

func TestPushSchedulerAcquiresCapacityBeforeAssignment(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	connectionB := newPushConnection(context.Background())
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	scheduler.Enqueue(connectionA, updateFromChanges(t, []model.ResourceChange{{Key: resourceA.Key, New: &resourceA}}))
	scheduler.Enqueue(connectionB, updateFromChanges(t, []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}}))

	first := scheduler.Next(context.Background())
	next := make(chan *scheduledPush, 1)
	go func() { next <- scheduler.Next(context.Background()) }()
	select {
	case push := <-next:
		t.Fatalf("second push was assigned without capacity: %#v", push)
	case <-time.After(25 * time.Millisecond):
	}
	scheduler.Done(first)
	select {
	case push := <-next:
		if push == nil || push.Connection != connectionB {
			t.Fatalf("push after capacity release = %v, want connection B", push)
		}
		scheduler.Done(push)
	case <-time.After(time.Second):
		t.Fatal("second push was not assigned after capacity release")
	}
}

func TestPushSchedulerCancellationReleasesProcessingCapacity(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connectionContext, cancelConnection := context.WithCancel(context.Background())
	connectionA := newPushConnection(connectionContext)
	connectionB := newPushConnection(context.Background())
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	scheduler.Enqueue(connectionA, updateFromChanges(t, []model.ResourceChange{{Key: resourceA.Key, New: &resourceA}}))
	first := scheduler.Next(context.Background())
	scheduler.Enqueue(connectionB, updateFromChanges(t, []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}}))

	cancelConnection()
	nextContext, cancelNext := context.WithTimeout(context.Background(), time.Second)
	defer cancelNext()
	second := scheduler.Next(nextContext)
	if second == nil || second.Connection != connectionB {
		t.Fatalf("push after connection cancellation = %v, want connection B", second)
	}
	// Completion may race cancellation, but it must remain idempotent and must
	// not release connection B's permit.
	scheduler.Done(first)
	scheduler.Done(second)
}

func TestPushSchedulerCanceledNextDoesNotConsumeCapacity(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	connectionB := newPushConnection(context.Background())
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	scheduler.Enqueue(connectionA, updateFromChanges(t, []model.ResourceChange{{Key: resourceA.Key, New: &resourceA}}))
	first := scheduler.Next(context.Background())
	scheduler.Enqueue(connectionB, updateFromChanges(t, []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}}))

	nextContext, cancelNext := context.WithCancel(context.Background())
	cancelNext()
	if push := scheduler.Next(nextContext); push != nil {
		t.Fatalf("Next with canceled context = %#v, want nil", push)
	}
	scheduler.Done(first)
	second := scheduler.Next(context.Background())
	if second == nil || second.Connection != connectionB {
		t.Fatalf("push after canceled Next = %v, want connection B", second)
	}
	scheduler.Done(second)
}

func TestPushSchedulerDropsCanceledPendingConnection(t *testing.T) {
	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connectionA := newPushConnection(context.Background())
	canceledContext, cancelConnection := context.WithCancel(context.Background())
	connectionB := newPushConnection(canceledContext)
	connectionC := newPushConnection(context.Background())
	resourceA := addressResource(t, "cluster//Pod/demo/a", "a")
	resourceB := addressResource(t, "cluster//Pod/demo/b", "b")
	resourceC := addressResource(t, "cluster//Pod/demo/c", "c")
	scheduler.Enqueue(connectionA, updateFromChanges(t, []model.ResourceChange{{Key: resourceA.Key, New: &resourceA}}))
	first := scheduler.Next(context.Background())
	scheduler.Enqueue(connectionB, updateFromChanges(t, []model.ResourceChange{{Key: resourceB.Key, New: &resourceB}}))
	scheduler.Enqueue(connectionC, updateFromChanges(t, []model.ResourceChange{{Key: resourceC.Key, New: &resourceC}}))
	cancelConnection()
	scheduler.Done(first)

	nextContext, cancelNext := context.WithTimeout(context.Background(), time.Second)
	defer cancelNext()
	second := scheduler.Next(nextContext)
	if second == nil || second.Connection != connectionC {
		t.Fatalf("push after pending cancellation = %v, want connection C", second)
	}
	scheduler.Done(second)
}

func TestPushSchedulerCloseUnblocksNext(t *testing.T) {
	scheduler := NewPushScheduler(1)
	next := make(chan *scheduledPush, 1)
	go func() { next <- scheduler.Next(context.Background()) }()
	scheduler.Close()
	select {
	case push := <-next:
		if push != nil {
			t.Fatalf("Next after Close = %#v, want nil", push)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Next")
	}
}

// A connection waiting for a push slot must keep handling Delta subscription
// changes so on-demand lookups do not deadlock behind a slow connection.
func TestStreamProcessesRequestWhilePushWaitsForPermit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldResource := addressResource(t, "cluster//Pod/demo/old", "old")
	newResource := addressResource(t, "cluster//Pod/demo/new", "new")
	scheduler := NewPushScheduler(1)
	blocker := newPushConnection(context.Background())
	scheduler.Enqueue(blocker, fullUpdate(t, "blocker"))
	held := scheduler.Next(context.Background())
	defer scheduler.Done(held)
	server := newTestServerWithScheduler(t, ztunnelScope(), []model.Resource{oldResource}, nil, scheduler)
	stream := newFakeStream(ctx, 4)
	done := server.start(stream)
	stream.send(nodeRequest(model.AddressType, oldResource.XDSName))
	stream.awaitResponses(t, model.AddressType, 1)

	if err := server.resources.apply([]model.ResourceChange{{Key: newResource.Key, New: &newResource}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	queued := false
	for time.Now().Before(deadline) {
		scheduler.mu.Lock()
		queued = len(scheduler.pending) == 1
		scheduler.mu.Unlock()
		if queued {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !queued {
		t.Fatal("push did not queue behind the occupied scheduler slot")
	}

	stream.send(request(model.AddressType, newResource.XDSName))
	deadline = time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(stream.responsesFor(model.AddressType)) >= 2 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not stop after cancellation")
	}
	t.Fatal("subscription response was blocked behind push capacity")
}

func TestSlowClientBurstConvergesFromFirstUnsentToFinalPublication(t *testing.T) {
	resource := func(payload string) model.Resource {
		result, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: "workload-a"}, "",
			testResourceContents(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{Uid: "workload-a", Name: payload}}}), nil,
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID: "workload-a",
				NodeName:    "node-a",
				Principal:   model.MustServiceAccountPrincipal("demo", "default"),
			}},
		)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	versions := []model.Resource{resource("zero"), resource("one"), resource("two"), resource("three")}
	initial, err := model.NewResourceSet(versions[:1])
	if err != nil {
		t.Fatal(err)
	}
	store := xdsstore.New(initial)
	ctx := t.Context()
	subscription := store.Subscribe(ctx, model.ClientScope{})
	subscription.Watch(model.AddressType)

	scheduler := NewPushScheduler(1)
	t.Cleanup(scheduler.Close)
	connection := newPushConnection(ctx)
	apply := func(next model.Resource) xdsstore.Update {
		t.Helper()
		if _, err := store.Apply([]model.ResourceChange{{Key: next.Key, New: &next}}); err != nil {
			t.Fatal(err)
		}
		update := <-subscription.Updates()
		changes := update.Candidates(model.AddressType)
		if len(changes) != 1 || changes[0].Key != next.Key || update.Version() != store.Snapshot().Version() {
			t.Fatalf("publication candidates = %#v", changes)
		}
		return update
	}

	firstUpdate := apply(versions[1])
	scheduler.Enqueue(connection, firstUpdate)
	first := scheduler.Next(context.Background())
	if first == nil {
		t.Fatal("first push was not scheduled")
	}

	scheduler.Enqueue(connection, apply(versions[2]))
	scheduler.Enqueue(connection, apply(versions[3]))
	scheduler.Done(first)
	final := scheduler.Next(context.Background())
	if final == nil {
		t.Fatal("coalesced final push was not scheduled")
	}
	defer scheduler.Done(final)

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"},
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     store.Snapshot(),
		Update:       final.Update,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := versions[3].Encode(model.ClientScope{Class: model.ClientSharedZTunnel}, model.AddressType)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 || delta.Resources[0].Hash != expected.Hash || len(delta.Removed) != 0 {
		t.Fatalf("coalesced delta resources=%#v removed=%v, want only final version", delta.Resources, delta.Removed)
	}
}
