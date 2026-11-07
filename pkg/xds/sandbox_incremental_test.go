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
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

func TestSandboxIncrementalPushPreservesSelection(t *testing.T) {
	a := sandboxResourceWithAttester(t, "a", "old-worker")
	nextA := sandboxResourceWithAttester(t, "a", "new-worker")
	b, c, d := sandboxResource(t, "b"), sandboxResource(t, "c"), sandboxResource(t, "d")
	other := sandboxResource(t, "other")
	before := selectionSnapshot(t, []model.Resource{a, b, c})
	after := selectionSnapshot(t, []model.Resource{nextA, c, d, other})
	update := updateBetween(before, after, before.Diff(after))
	for _, tc := range []struct {
		name     string
		wildcard bool
		names    []string
		sent     map[string]string
		want     []string
		removed  []string
	}{
		{
			name:    "named update and deletion",
			names:   []string{"a", "b", "c", "d"},
			sent:    map[string]string{"a": a.Hash, "b": b.Hash, "c": c.Hash},
			want:    []string{"a", "d"},
			removed: []string{"b"},
		},
		{
			name:  "already delivered by demand",
			names: []string{"a", "c", "d"},
			sent:  map[string]string{"a": nextA.Hash, "c": c.Hash, "d": d.Hash},
		},
		{
			name:  "unsubscribed changed names",
			names: []string{"c"},
			sent:  map[string]string{"c": c.Hash},
		},
		{
			name:     "wildcard with named interests",
			wildcard: true,
			names:    []string{"c"},
			sent:     map[string]string{"a": a.Hash, "b": b.Hash, "c": c.Hash},
			want:     []string{"a", "d", "other"},
			removed:  []string{"b"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watch := &watchState{wildcard: tc.wildcard, names: sets.New(tc.names...), sent: tc.sent}
			view := newIncrementalSubscriptionView(watch, model.SandboxType, update)
			// The generated view must not borrow the live stream's mutable state.
			watch.names.Insert("other")
			watch.sent["a"] = nextA.Hash
			delta, err := (SandboxGenerator{}).Generate(t.Context(), GenerationRequest{
				Scope:        gatewayScope(),
				TypeURL:      model.SandboxType,
				Subscription: view,
				Snapshot:     after,
				Update:       update,
			})
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, r := range delta.Resources {
				names = append(names, r.XDSName)
				if r.XDSName == "a" && r.Hash != nextA.Hash {
					t.Fatal("sent the old Sandbox binding")
				}
			}
			if !slices.Equal(names, tc.want) || !slices.Equal(delta.Removed, tc.removed) {
				t.Fatalf(
					"resources=%v removed=%v, want resources=%v removed=%v",
					names,
					delta.Removed,
					tc.want,
					tc.removed,
				)
			}
		})
	}
}

// Measure the complete incremental generation, including the subscription view.
// Only changed resources are needed in the snapshot: unrelated subscriptions
// must not be visited by this path.
func sandboxIncrementalFixture(t testing.TB, subscriptions, changed int) (*watchState, GenerationRequest) {
	t.Helper()
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	for i := range subscriptions {
		name := fmt.Sprintf("sandbox-%06d", i)
		watch.names.Insert(name)
		watch.sent[name] = "previous-version"
	}
	resources := make([]model.Resource, 0, changed)
	for i := range changed {
		name := fmt.Sprintf("sandbox-%06d", i)
		r, err := model.NewResource(model.ResourceKey{TypeURL: model.SandboxType, Name: name}, "",
			&anypb.Any{TypeUrl: model.SandboxType, Value: []byte(name)}, nil,
			model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{}})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, r)
	}
	before, err := model.NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	return watch, GenerationRequest{
		Scope:    gatewayScope(),
		TypeURL:  model.SandboxType,
		Snapshot: after,
		Update:   updateBetween(before, after, before.Diff(after)),
	}
}

func TestSandboxIncrementalPushAllocationBound(t *testing.T) {
	watch, request := sandboxIncrementalFixture(t, 100_000, 1)
	result := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			request.Subscription = newIncrementalSubscriptionView(watch, model.SandboxType, request.Update)
			delta, err := (SandboxGenerator{}).Generate(t.Context(), request)
			if err != nil || len(delta.Resources) != 1 || delta.Resources[0].XDSName != "sandbox-000000" {
				b.Fatalf("unexpected delta: %+v, %v", delta, err)
			}
		}
	})
	// A single-key update must not allocate a copy of 100k subscription names.
	// A loose byte budget avoids CPU-speed-dependent assertions.
	if bytes := result.AllocedBytesPerOp(); bytes > 64<<10 {
		t.Fatalf("single Sandbox update allocated %d bytes with 100k subscriptions; budget is 64 KiB", bytes)
	}
}

func BenchmarkSandboxIncrementalPush(b *testing.B) {
	for _, subscriptions := range []int{1_000, 50_000, 100_000} {
		for _, changed := range []int{1, 200} {
			b.Run(fmt.Sprintf("subscriptions=%d/changed=%d", subscriptions, changed), func(b *testing.B) {
				watch, request := sandboxIncrementalFixture(b, subscriptions, changed)
				b.ReportAllocs()
				for b.Loop() {
					request.Subscription = newIncrementalSubscriptionView(watch, model.SandboxType, request.Update)
					delta, err := (SandboxGenerator{}).Generate(b.Context(), request)
					if err != nil || len(delta.Resources) != changed || len(delta.Removed) != 0 {
						b.Fatalf(
							"unexpected delta: %d resources, %v removed, %v",
							len(delta.Resources),
							delta.Removed,
							err,
						)
					}
				}
			})
		}
	}
}

func BenchmarkSandboxIncrementalPushBoundary(b *testing.B) {
	for _, tc := range []struct {
		name          string
		subscriptions int
		changed       int
		wildcard      bool
	}{
		{"empty", 0, 10_000, false},
		{"few_subscribers", 10, 10_000, false},
		{"dense", 10_000, 10_000, false},
		{"dense_100k", 100_000, 100_000, false},
		{"wildcard", 100_000, 200, true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			watch, request := sandboxIncrementalFixture(b, tc.subscriptions, tc.changed)
			watch.wildcard = tc.wildcard
			want := min(tc.subscriptions, tc.changed)
			if tc.wildcard {
				want = tc.changed
			}
			b.ReportAllocs()
			for b.Loop() {
				request.Subscription = newIncrementalSubscriptionView(watch, model.SandboxType, request.Update)
				delta, err := (SandboxGenerator{}).Generate(b.Context(), request)
				if err != nil || len(delta.Resources) != want || len(delta.Removed) != 0 {
					b.Fatalf("unexpected delta: %d resources, %v removed, %v", len(delta.Resources), delta.Removed, err)
				}
			}
		})
	}
}

func BenchmarkSandboxIncrementalMigration(b *testing.B) {
	for _, changed := range []int{200, 100_000} {
		b.Run(fmt.Sprintf("subscriptions=100000/changed=%d", changed), func(b *testing.B) {
			watch, request := sandboxIncrementalFixture(b, 100_000, changed)
			resources := request.Snapshot.List(model.SandboxType)
			previous := make([]model.Resource, 0, len(resources))
			changes := make([]model.ResourceChange, 0, len(resources))
			for _, resource := range resources {
				old := resource
				old.Hash = "previous-version"
				old.Facts.Sandbox = &model.SandboxResourceFacts{AttesterWorkloadUID: "previous-worker"}
				previous = append(previous, old)
				changes = append(changes, model.ResourceChange{Key: resource.Key, Old: &old, New: &resource})
			}
			before, err := model.NewResourceSet(previous)
			if err != nil {
				b.Fatal(err)
			}
			request.Update = updateBetween(before, request.Snapshot, changes)
			b.ReportAllocs()
			for b.Loop() {
				request.Subscription = newIncrementalSubscriptionView(watch, model.SandboxType, request.Update)
				delta, err := (SandboxGenerator{}).Generate(b.Context(), request)
				if err != nil || len(delta.Resources) != changed || len(delta.Removed) != 0 {
					b.Fatalf("unexpected delta: %d resources, %v removed, %v", len(delta.Resources), delta.Removed, err)
				}
			}
		})
	}
}
