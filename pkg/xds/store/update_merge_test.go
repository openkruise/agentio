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
	"maps"
	"reflect"
	"sync"
	"testing"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// Compare the linear merge against an independent map-union oracle, covering
// empty, disjoint and overlapping batches, both types, and nested visibility.
func TestMergeMatchesUnion(t *testing.T) {
	for oldMask := range 16 {
		for newMask := range 16 {
			older := mergeTestUpdate(oldMask, "older")
			newer := mergeTestUpdate(newMask, "newer")
			want := referenceCandidateUnion(older, newer)
			got := Merge(older, newer)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("masks %d/%d: got %#v, want %#v", oldMask, newMask, got, want)
			}
			if !reflect.DeepEqual(older, mergeTestUpdate(oldMask, "older")) ||
				!reflect.DeepEqual(newer, mergeTestUpdate(newMask, "newer")) {
				t.Fatalf("masks %d/%d: modified shared inputs", oldMask, newMask)
			}
		}
	}
}

func TestMergeConcurrentSharedVisibility(t *testing.T) {
	older, newer := mergeTestUpdate(15, "older"), mergeTestUpdate(15, "newer")
	want := referenceCandidateUnion(older, newer)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 50 {
				got := Merge(older, newer)
				// Merging an already merged notice exercises identities first
				// introduced by the newer notice, including their workload sets.
				got = Merge(got, newer)
				if !reflect.DeepEqual(got, want) {
					t.Error("concurrent merge changed identity union")
					return
				}
			}
		})
	}
	workers.Wait()
	if !reflect.DeepEqual(older, mergeTestUpdate(15, "older")) ||
		!reflect.DeepEqual(newer, mergeTestUpdate(15, "newer")) {
		t.Fatal("concurrent merge modified shared visibility")
	}
}

func TestMergeFullScopes(t *testing.T) {
	cases := []struct {
		name  string
		old   Update
		new   Update
		full  bool
		types sets.Set[string]
	}{
		{name: "incremental"},
		{name: "old global", old: Update{full: true}, full: true},
		{name: "new global", new: Update{full: true}, full: true},
		{name: "typed",
			old:   Update{full: true, fullTypes: sets.New(model.SecretType)},
			new:   Update{full: true, fullTypes: sets.New(model.ClusterType)},
			full:  true,
			types: sets.New(model.SecretType, model.ClusterType)},
		{name: "global dominates",
			old:  Update{full: true, fullTypes: sets.New(model.SecretType)},
			new:  Update{full: true},
			full: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.new.version = "new"
			got := Merge(tc.old, tc.new)
			if got.version != "new" || got.full != tc.full || !reflect.DeepEqual(got.fullTypes, tc.types) {
				t.Fatalf("unexpected full merge: %#v", got)
			}
		})
	}
}

func mergeTestUpdate(mask int, source string) Update {
	candidates := make(map[model.ResourceKey]Candidate)
	for i, name := range []string{"a", "b", "c", "d"} {
		if mask&(1<<i) == 0 {
			continue
		}
		for _, typeURL := range []string{model.AddressType, model.ClusterType} {
			key := model.ResourceKey{TypeURL: typeURL, Name: name}
			candidates[key] = Candidate{Key: key,
				Identities: []Identity{
					{Name: name, Workloads: sets.New(WorkloadIdentity{UID: source})},
					{Name: name + "-" + source, Workloads: sets.New(WorkloadIdentity{UID: source})},
				}}
		}
	}
	return indexedUpdate(source, candidates)
}

func referenceCandidateUnion(older, newer Update) Update {
	index := make(map[model.ResourceKey]Candidate)
	for _, update := range []Update{older, newer} {
		for _, batch := range update.candidates {
			for _, incoming := range batch {
				candidate := index[incoming.Key]
				candidate.Key = incoming.Key
				for _, identity := range incoming.Identities {
					identity.Workloads = maps.Clone(identity.Workloads)
					candidate.Identities = mergeIdentity(candidate.Identities, identity)
				}
				index[incoming.Key] = candidate
			}
		}
	}
	return indexedUpdate(newer.version, index)
}

func TestMergeIncrementalAndTypedFull(t *testing.T) {
	key := model.ResourceKey{TypeURL: model.AddressType, Name: "workload"}
	incremental := indexedUpdate("incremental", map[model.ResourceKey]Candidate{
		key: {Key: key, Identities: []Identity{{Name: "workload"}}},
	})
	full := Update{version: "full", full: true, fullTypes: sets.New(model.SecretType)}
	for _, tc := range []struct {
		name  string
		older Update
		newer Update
	}{
		{"incremental then full", incremental, full},
		{"full then incremental", full, incremental},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged := Merge(tc.older, tc.newer)
			if merged.Version() != tc.newer.Version() {
				t.Fatal("merge did not retain the newer notice version")
			}
			for _, typeURL := range []string{model.AddressType, model.WorkloadType} {
				if !merged.Affects(typeURL) || merged.FullFor(typeURL) ||
					!reflect.DeepEqual(merged.Candidates(typeURL), incremental.Candidates(typeURL)) {
					t.Fatalf("incremental scope or candidates changed for %s", typeURL)
				}
			}
			if !merged.Affects(model.SecretType) || !merged.FullFor(model.SecretType) ||
				merged.Affects(model.ClusterType) || merged.FullFor(model.ClusterType) {
				t.Fatal("typed-full notification widened or lost its scope")
			}
		})
	}
}

func TestMergeVisibilitySubsets(t *testing.T) {
	a, b, c := WorkloadIdentity{UID: "a"}, WorkloadIdentity{UID: "b"}, WorkloadIdentity{UID: "c"}
	for _, tc := range []struct {
		name string
		old  sets.Set[WorkloadIdentity]
		next sets.Set[WorkloadIdentity]
	}{
		{"unchanged", sets.New(a, b), sets.New(a, b)},
		{"subset", sets.New(a, b), sets.New(a)},
		{"no incoming scopes", sets.New(a), nil},
		{"first scopes", nil, sets.New(a)},
		{"additional scopes", sets.New(a, b), sets.New(b, c)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := model.ResourceKey{TypeURL: model.ClusterType, Name: "resource"}
			older := indexedUpdate("old", map[model.ResourceKey]Candidate{
				key: {Key: key, Identities: []Identity{{Name: "wire", Workloads: tc.old}}},
			})
			newer := indexedUpdate("new", map[model.ResourceKey]Candidate{
				key: {Key: key, Identities: []Identity{{Name: "wire", Workloads: tc.next}}},
			})
			oldBefore, newBefore := maps.Clone(tc.old), maps.Clone(tc.next)
			want := referenceCandidateUnion(older, newer)
			got := Merge(older, newer)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("merge lost historical visibility")
			}
			later := indexedUpdate("later", map[model.ResourceKey]Candidate{
				key: {
					Key:        key,
					Identities: []Identity{{Name: "wire", Workloads: sets.New(WorkloadIdentity{UID: "later"})}},
				},
			})
			branch := Merge(got, later)
			if !reflect.DeepEqual(branch, referenceCandidateUnion(want, later)) || !reflect.DeepEqual(got, want) ||
				!reflect.DeepEqual(tc.old, oldBefore) || !reflect.DeepEqual(tc.next, newBefore) {
				t.Fatal("later merge modified shared visibility")
			}
		})
	}
}

// A queued invalidation contains names and visibility, not rule payloads. A new
// revision with the same evidence should advance the version without allocations.
func TestMergeReusesUnchangedCandidates(t *testing.T) {
	older := mergeTestUpdate(15, "same")
	newer := mergeTestUpdate(3, "same")
	newer.version = "next"
	var merged Update
	allocations := testing.AllocsPerRun(100, func() { merged = Merge(older, newer) })
	if allocations != 0 {
		t.Fatalf("unchanged union allocated %g times", allocations)
	}
	if merged.Version() != "next" || !reflect.DeepEqual(merged, referenceCandidateUnion(older, newer)) {
		t.Fatal("reuse lost candidate evidence or the latest version")
	}
	// A later branch must not mutate the shared maps or nested identities.
	before := referenceCandidateUnion(older, newer)
	_ = Merge(merged, mergeTestUpdate(15, "new-owner"))
	if !reflect.DeepEqual(merged, before) {
		t.Fatal("later merge mutated a reused union")
	}
}

func BenchmarkMergeRepeatedInvalidations(b *testing.B) {
	older := mergeTestUpdate(15, "same")
	newer := mergeTestUpdate(3, "same")
	newer.version = "next"
	b.ReportAllocs()
	for b.Loop() {
		_ = Merge(older, newer)
	}
}
