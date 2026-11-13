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

package model

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
)

// Compare each publication with an independently rebuilt index, while keeping
// every old snapshot alive. Repeated keys exercise delete/recreate and rollback
// within one publication; aliases and policy facts share membership lists.
func TestResourceMembershipBatchMatchesRebuild(t *testing.T) {
	rng := rand.New(rand.NewPCG(17, 29))
	current := map[ResourceKey]Resource{}
	makeResource := func(id, revision int) Resource {
		name := fmt.Sprintf("w-%03d", id)
		facts := ResourceFacts{Workload: &WorkloadResourceFacts{
			WorkloadUID:       name,
			Namespace:         fmt.Sprintf("ns-%d", revision%3),
			Principal:         testPrincipal(),
			TrafficPolicyRefs: []string{fmt.Sprintf("policy-%d", revision%4)},
			GatewayReferences: []string{"gateway"},
			ServiceKeys:       []string{fmt.Sprintf("service-%d", id%3)},
		}}
		r, err := NewResource(
			ResourceKey{TypeURL: AddressType, Name: name}, name,
			Prebuilt(&anypb.Any{TypeUrl: AddressType, Value: []byte(fmt.Sprint(revision))}),
			[]string{"shared", fmt.Sprintf("alias-%d", revision%5)}, facts,
		)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	rebuild := func() ResourceSet {
		resources := make([]Resource, 0, len(current))
		for _, r := range current {
			resources = append(resources, r)
		}
		s, err := NewResourceSet(resources)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for i := range 100 {
		r := makeResource(i, 0)
		current[r.Key] = r
	}
	snapshot := rebuild()
	type retained struct {
		actual   ResourceSet
		expected ResourceSet
	}
	history := []retained{{snapshot, rebuild()}}
	for round := range 30 {
		changes := []ResourceChange{}
		for range 40 {
			id := rng.IntN(120)
			r := makeResource(id, rng.IntN(10))
			change := ResourceChange{Key: r.Key}
			if old, ok := current[r.Key]; ok {
				change.Old = &old
			}
			if rng.IntN(3) == 0 {
				delete(current, r.Key)
			} else {
				change.New = &r
				current[r.Key] = r
			}
			changes = append(changes, change)
		}
		next, _, err := snapshot.Apply(changes)
		if err != nil {
			t.Fatal(err)
		}
		snapshot = next
		history = append(history, retained{snapshot, rebuild()})
		for i, pair := range history {
			t.Run(fmt.Sprintf("round-%d/snapshot-%d", round, i), func(t *testing.T) {
				assertMembershipIndex(t, pair.actual, pair.expected)
			})
		}
	}
}

func assertMembershipIndex(t *testing.T, got, want ResourceSet) {
	t.Helper()
	if got.Len() != want.Len() {
		t.Fatalf("resource count %d != %d", got.Len(), want.Len())
	}
	for _, typ := range append(got.Types(), want.Types()...) {
		a, b := got.resources[typ], want.resources[typ]
		if a == nil || b == nil {
			t.Fatalf("missing type %q", typ)
		}
		for _, indexes := range [][2]*resourceLookupIndex{{&a.lookup, &b.lookup}, {&a.facts, &b.facts}} {
			for shard := range resourceShardCount {
				for _, m := range []map[string][]string{indexes[0].shards[shard], indexes[1].shards[shard]} {
					for key := range m {
						x, y := indexes[0].shards[shard][key], indexes[1].shards[shard][key]
						if !slices.Equal(x, y) {
							t.Fatalf("type %s posting %q: %v != %v", typ, key, x, y)
						}
					}
				}
			}
		}
	}
}
