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

package store

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
)

type memoryStore struct {
	mu        sync.Mutex
	types     []Type
	resources map[Key]Resource
	snapshots map[Type]*DefaultSnapshot
	ready     bool
	err       error
	changed   chan struct{}
	calls     int
	fetches   int
	pending   *Resource
}

func memory(types ...Type) *memoryStore {
	return &memoryStore{
		types:     types,
		resources: map[Key]Resource{},
		snapshots: map[Type]*DefaultSnapshot{},
		ready:     true,
		changed:   make(chan struct{}),
	}
}

func (s *memoryStore) Types() []Type { return s.types }

func (s *memoryStore) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{Ready: s.ready, Changed: s.changed}
}

func (s *memoryStore) Read() Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := Batch{Status: Status{Ready: s.ready, Changed: s.changed}, Snapshots: map[Type]TypeSnapshot{}}
	for _, typ := range s.types {
		var resources []Resource
		if s.err == nil {
			for key, r := range s.resources {
				if key.Type == typ {
					resources = append(resources, r)
				}
			}
		}
		s.snapshots[typ] = buildDefaultSnapshot(resources, s.err, s.snapshots[typ])
		batch.Snapshots[typ] = s.snapshots[typ]
	}
	return batch
}

func (s *memoryStore) Get(key Key) (*Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	r, ok := s.resources[key]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

func (s *memoryStore) List(typ Type) ([]Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	var result []Resource
	for key, r := range s.resources {
		if key.Type == typ {
			result = append(result, r)
		}
	}
	return result, nil
}

func (s *memoryStore) Fetch(_ context.Context, key Key) (*Resource, error) {
	s.fetches++
	if s.pending != nil && s.pending.Key == key {
		s.put(*s.pending)
	}
	return s.Get(key)
}

func (s *memoryStore) put(r Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources[r.Key] = r
	close(s.changed)
	s.changed = make(chan struct{})
}

func TestAggregateQueriesPriorityAndErrors(t *testing.T) {
	first, second, unrelated := memory(Workload), memory(Workload, Type("TestPolicy")), memory("SecurityProfile")
	key := Key{Type: Workload, Name: "shared"}
	first.put(Resource{Key: key, Value: "first"})
	second.put(Resource{Key: key, Value: "second"})
	second.put(Resource{Key: Key{Type: Workload, Name: "other"}, Value: "other"})
	aggregate := NewAggregate(first, second, unrelated)
	if !slices.Equal(aggregate.Types(), []Type{Workload, Type("TestPolicy"), "SecurityProfile"}) {
		t.Fatal(aggregate.Types())
	}
	resource, err := aggregate.Get(key)
	if err != nil || resource.Value != "first" {
		t.Fatal(resource, err)
	}
	listed, err := aggregate.List(Workload)
	if err != nil || len(listed) != 2 || listed[0].Key.Name != "other" || listed[1].Value != "first" {
		t.Fatal(listed, err)
	}
	resource, err = aggregate.Get(Key{Type: Workload, Name: "other"})
	if err != nil || resource.Value != "other" {
		t.Fatal(resource, err)
	}
	if unrelated.calls != 0 {
		t.Fatal("queried unrelated source")
	}
	first.err = errors.New("source unavailable")
	close(first.changed)
	first.changed = make(chan struct{})
	aggregate.Refresh()
	before := second.calls
	if _, err := aggregate.Get(key); !errors.Is(err, first.err) || second.calls != before {
		t.Fatal("Get fell back after error", err)
	}
	if _, err := aggregate.List(Workload); !errors.Is(err, first.err) {
		t.Fatal("List hid error", err)
	}
	if _, err := aggregate.Fetch(t.Context(), key); !errors.Is(err, first.err) || second.calls != before {
		t.Fatal("Fetch fell back after error", err)
	}
}

func TestAggregateFetchAndPublication(t *testing.T) {
	workloads, policies := memory(Workload), memory(Type("TestPolicy"))
	aggregate := NewAggregate(workloads, policies)
	before := aggregate.Snapshot()
	if !before.Ready() {
		t.Fatal("not ready")
	}
	aggregate.Refresh()
	if aggregate.Snapshot() != before {
		t.Fatal("published without changes")
	}
	key := Key{Type: Type("TestPolicy"), Name: "policy"}
	policies.pending = &Resource{Key: key, Value: "fetched"}
	resource, err := aggregate.Fetch(t.Context(), key)
	if err != nil || resource.Value != "fetched" || workloads.fetches != 0 || policies.fetches != 1 {
		t.Fatal(resource, err)
	}
	if aggregate.Snapshot() == before {
		t.Fatal("fetch did not publish")
	}
	before = aggregate.Snapshot()
	workloads.put(Resource{Key: Key{Type: Workload, Name: "pod"}})
	aggregate.Refresh()
	if aggregate.Snapshot() == before {
		t.Fatal("second backend change lost")
	}
	before = aggregate.Snapshot()
	policies.setReady(false)
	aggregate.Refresh()
	if aggregate.Ready() || aggregate.Snapshot() == before {
		t.Fatal("readiness change lost")
	}
}

func TestAcquirePreservesPriorityAndExplicitFetch(t *testing.T) {
	first, second := memory(Workload), memory(Workload)
	key := Key{Type: Workload, Name: "shared"}
	second.put(Resource{Key: key, Value: "lower-priority"})
	first.pending = &Resource{Key: key, Value: map[string]string{"source": "first"}}
	aggregate := NewAggregate(first, second)
	r, release, err := aggregate.Acquire(t.Context(), key)
	if release != nil {
		defer release()
	}
	if err != nil || r == nil || !reflect.DeepEqual(r.Value, first.pending.Value) || first.fetches != 1 {
		t.Fatalf("acquire skipped higher priority source: %v %v", r, err)
	}
	first.pending = &Resource{Key: key, Value: "explicitly-refetched"}
	r, err = aggregate.Fetch(t.Context(), key)
	if err != nil || r == nil || r.Value != "explicitly-refetched" || first.fetches != 2 {
		t.Fatalf("explicit Fetch returned cached value: %v %v", r, err)
	}
}

func TestAggregateChangeNotificationAndPinnedView(t *testing.T) {
	first, second := memory(Workload), memory(Type("TestPolicy"))
	aggregate := NewAggregate(first, second)
	before := aggregate.Snapshot()
	second.put(Resource{Key: Key{Type: Type("TestPolicy"), Name: "updated"}, Value: "new"})
	aggregate.Refresh()
	select {
	case <-before.Changed():
	default:
		t.Fatal("missed publication notification")
	}
	if resource, err := before.Get(Key{Type: Type("TestPolicy"), Name: "updated"}); err != nil || resource != nil {
		t.Fatal("old view changed")
	}
	select {
	case <-aggregate.Snapshot().Changed():
		t.Fatal("current view already invalidated")
	default:
	}
}
