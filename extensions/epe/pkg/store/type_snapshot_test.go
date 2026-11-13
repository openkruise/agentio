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
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

// Uses a slice and its own selection index; no DefaultSnapshot dependency.
type selectedSnapshot struct {
	resources []Resource
	selected  map[string][]Resource
}

func selection(resources ...Resource) *selectedSnapshot {
	s := &selectedSnapshot{resources: resources, selected: map[string][]Resource{}}
	for _, r := range resources {
		s.selected[r.Value.(string)] = append(s.selected[r.Value.(string)], r)
	}
	return s
}

func (s *selectedSnapshot) Get(name string) (*Resource, error) {
	for i := range s.resources {
		if s.resources[i].Key.Name == name {
			return &s.resources[i], nil
		}
	}
	return nil, nil
}

func (s *selectedSnapshot) List() ([]Resource, error) { return s.resources, nil }

func (s *selectedSnapshot) ResourcesFor(_ Type, subject subject.Subject) ([]Resource, error) {
	return s.selected[subject.Workload.Labels["team"]], nil
}

type snapshotBackend struct {
	batch   Batch
	changed chan struct{}
}

func backend(snapshots map[Type]TypeSnapshot) *snapshotBackend {
	b := &snapshotBackend{}
	b.publish(snapshots)
	return b
}

func (b *snapshotBackend) Types() []Type {
	var types []Type
	for typ := range b.batch.Snapshots {
		types = append(types, typ)
	}
	return types
}

func (b *snapshotBackend) Status() Status { return b.batch.Status }

func (b *snapshotBackend) Read() Batch { return b.batch }

func (b *snapshotBackend) Fetch(_ context.Context, key Key) (*Resource, error) {
	return b.batch.Snapshots[key.Type].Get(key.Name)
}

func (b *snapshotBackend) publish(snapshots map[Type]TypeSnapshot) {
	if b.changed != nil {
		close(b.changed)
	}
	b.changed = make(chan struct{})
	b.batch = Batch{Status: Status{Ready: true, Changed: b.changed}, Snapshots: snapshots}
}

func TestCustomTypeSnapshotPassThrough(t *testing.T) {
	const profiles Type = "Profile"
	original := selection(Resource{Key: Key{Type: profiles, Name: "p"}, Value: "team-a"})
	a := NewAggregate(backend(map[Type]TypeSnapshot{profiles: original}))
	a.RegisterQueries([]Type{profiles}, []Type{profiles}, func(current *Snapshot, _ Query) Query {
		return current.Type(profiles).(*selectedSnapshot)
	})
	if a.Snapshot().Type(profiles) != original {
		t.Fatal("custom representation was replaced")
	}
	got, err := a.ResourcesFor(
		profiles,
		subject.Subject{Workload: subject.Workload{Labels: map[string]string{"team": "team-a"}}},
	)
	if err != nil || len(got) != 1 || got[0].Key.Name != "p" {
		t.Fatal(got, err)
	}
}

func TestCustomBuilderPrecedenceAndDependencyReuse(t *testing.T) {
	const profiles Type = "Profile"
	high := backend(
		map[Type]TypeSnapshot{profiles: selection(Resource{Key: Key{Type: profiles, Name: "shared"}, Value: "team-a"})},
	)
	lowProfiles := selection(
		Resource{Key: Key{Type: profiles, Name: "shared"}, Value: "team-b"},
		Resource{Key: Key{Type: profiles, Name: "other"}, Value: "team-b"},
	)
	workloads := NewDefaultSnapshot([]Resource{{Key: Key{Type: Workload, Name: "pod"}, Value: "old"}}, nil)
	low := backend(map[Type]TypeSnapshot{profiles: lowProfiles, Workload: workloads})
	a := NewAggregate(high, low)
	builds, queries := 0, 0
	a.RegisterTypeSnapshot(profiles, func(effective, _ TypeSnapshot) TypeSnapshot {
		builds++
		r, err := effective.Get("shared")
		if err != nil || r.Value != "team-a" {
			t.Fatal("Get did not apply precedence", r, err)
		}
		resources, err := effective.List()
		if err != nil {
			t.Fatal(err)
		}
		return selection(resources...)
	})
	a.RegisterQueries([]Type{profiles}, []Type{profiles}, func(current *Snapshot, _ Query) Query {
		queries++
		return current.Type(profiles).(*selectedSnapshot)
	})
	before := a.Snapshot()
	selected, err := before.ResourcesFor(
		profiles,
		subject.Subject{Workload: subject.Workload{Labels: map[string]string{"team": "team-b"}}},
	)
	if err != nil || len(selected) != 1 || selected[0].Key.Name != "other" {
		t.Fatal("shadowed resource entered custom index", selected, err)
	}
	oldBuilds, oldQueries := builds, queries
	low.publish(map[Type]TypeSnapshot{
		profiles: lowProfiles,
		Workload: NewDefaultSnapshot([]Resource{{Key: Key{Type: Workload, Name: "pod"}, Value: "new"}}, nil),
	})
	a.Refresh()
	if builds != oldBuilds || queries != oldQueries || before.Type(profiles) != a.Snapshot().Type(profiles) {
		t.Fatal("unrelated type rebuilt custom snapshot/query")
	}
	low.publish(map[Type]TypeSnapshot{
		profiles: selection(Resource{Key: Key{Type: profiles, Name: "other"}, Value: "team-c"}),
		Workload: low.batch.Snapshots[Workload],
	})
	a.Refresh()
	if builds != oldBuilds+1 || queries != oldQueries+1 {
		t.Fatal("dependency update did not rebuild")
	}
	selected, err = a.ResourcesFor(
		profiles,
		subject.Subject{Workload: subject.Workload{Labels: map[string]string{"team": "team-b"}}},
	)
	if err != nil || len(selected) != 0 {
		t.Fatal(selected, err)
	}
	selected, err = before.ResourcesFor(
		profiles,
		subject.Subject{Workload: subject.Workload{Labels: map[string]string{"team": "team-b"}}},
	)
	if err != nil || len(selected) != 1 {
		t.Fatal("old index was mutated", selected, err)
	}
}

func TestDefaultSnapshotReuseAndSourceError(t *testing.T) {
	high, low := memory(Workload), memory(Workload, Type("TestPolicy"))
	high.put(Resource{Key: Key{Type: Workload, Name: "pod"}, Value: "high"})
	low.put(Resource{Key: Key{Type: Workload, Name: "pod"}, Value: "low"})
	low.put(Resource{Key: Key{Type: Type("TestPolicy"), Name: "policy"}, Value: "policy"})
	a := NewAggregate(high, low)
	before := a.Snapshot()
	// The backend returns new per-type objects, but unchanged effective content
	// (including changes hidden by source priority) must preserve type identity.
	low.put(Resource{Key: Key{Type: Workload, Name: "pod"}, Value: "shadowed update"})
	a.Refresh()
	if a.Snapshot().Type(Workload) != before.Type(Workload) ||
		a.Snapshot().Type(Type("TestPolicy")) != before.Type(Type("TestPolicy")) {
		t.Fatal("unchanged effective type was rebuilt")
	}
	low.err = errors.New("unavailable")
	close(low.changed)
	low.changed = make(chan struct{})
	a.Refresh()
	r, err := a.Get(Key{Type: Workload, Name: "pod"})
	if err != nil || r.Value != "high" {
		t.Fatal("lower source error hid higher resource", r, err)
	}
	if _, err := a.Get(Key{Type: Workload, Name: "missing"}); !errors.Is(err, low.err) {
		t.Fatal("error treated as absence", err)
	}
	if _, err := a.List(Workload); !errors.Is(err, low.err) {
		t.Fatal("partial list hid source error", err)
	}
}

func TestDefaultSnapshotPassThrough(t *testing.T) {
	original := NewDefaultSnapshot([]Resource{{Key: Key{Type: Workload, Name: "pod"}, Value: "value"}}, nil)
	a := NewAggregate(backend(map[Type]TypeSnapshot{Workload: original}))
	if a.Snapshot().Type(Workload) != original {
		t.Fatal("single source default snapshot rebuilt")
	}
}

func TestDefaultSnapshotChangesKeepOldView(t *testing.T) {
	original := NewDefaultSnapshot([]Resource{
		{Key: Key{Type: Workload, Name: "b"}, Value: "unchanged"},
		{Key: Key{Type: Workload, Name: "c"}, Value: "removed"},
	}, nil)
	if original.WithChanges(nil, nil) != original {
		t.Fatal("empty update replaced snapshot")
	}
	next := original.WithChanges([]Resource{{Key: Key{Type: Workload, Name: "a"}, Value: "added"}}, []string{"c"})
	oldResource, err := original.Get("b")
	if err != nil {
		t.Fatal(err)
	}
	if r, err := next.Get("b"); err != nil || r != oldResource {
		t.Fatal("unchanged resource replaced", err)
	}
	if resources, err := next.List(); err != nil || len(resources) != 2 || resources[0].Key.Name != "a" ||
		resources[1].Key.Name != "b" {
		t.Fatal(resources, err)
	}
	if r, err := next.Get("c"); err != nil || r != nil {
		t.Fatal("deletion not applied", r, err)
	}
	if r, err := original.Get("c"); err != nil || r == nil {
		t.Fatal("old snapshot mutated", r, err)
	}
	if r, err := original.Get("a"); err != nil || r != nil {
		t.Fatal("addition leaked to old view", r, err)
	}
}

func TestDefaultSnapshotChangesPreserveSortedList(t *testing.T) {
	resource := func(name, value string) Resource { return Resource{Key: Key{Type: Workload, Name: name}, Value: value} }
	original := NewDefaultSnapshot([]Resource{
		resource("b", "old-b"),
		resource("d", "old-d"),
		resource("f", "old-f"),
	}, nil)
	next := original.WithChanges([]Resource{
		resource("a", "superseded-a"),
		resource("g", "new-g"),
		resource("d", "new-d"),
		resource("a", "new-a"),
		resource("e", "new-e"),
	}, []string{"b"})
	values, err := next.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 5 || values[0].Value != "new-a" {
		t.Fatal(values)
	}
	for i, name := range []string{"a", "d", "e", "f", "g"} {
		got, err := next.Get(name)
		if err != nil || got == nil || values[i] != *got {
			t.Fatalf("List/Get disagree for %s: %v %v", name, values, err)
		}
	}
	old, err := original.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 3 || old[0].Key.Name != "b" || old[1].Value != "old-d" {
		t.Fatalf("old list mutated: %v", old)
	}
	replacement := original.WithChanges([]Resource{resource("d", "replacement")}, nil)
	values, err = replacement.List()
	if err != nil || len(values) != 3 || values[1].Value != "replacement" {
		t.Fatal(values, err)
	}
	empty := original.WithChanges(nil, []string{"b", "d", "f"})
	values, err = empty.List()
	if err != nil || len(values) != 0 {
		t.Fatal(values, err)
	}
}
