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
	"fmt"
	"reflect"
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

func TestWorkloadAddressNoticeRetainsDependenciesAndWithdrawals(t *testing.T) {
	key := func(name string) model.ResourceKey { return model.ResourceKey{TypeURL: model.AddressType, Name: name} }
	current := model.Resource{
		Key:     key("own"),
		XDSName: "own",
		Hash:    "own",
		Value:   &anypb.Any{TypeUrl: model.AddressType},
		Facts: model.ResourceFacts{
			Workload: &model.WorkloadResourceFacts{
				WorkloadUID:       "own",
				ServiceKeys:       []string{"svc-new"},
				GatewayReferences: []string{"gw-new"},
			},
		},
	}
	snapshot, err := model.NewResourceSet([]model.Resource{current})
	if err != nil {
		t.Fatal(err)
	}
	index := map[model.ResourceKey]Candidate{}
	add := func(name string, identity Identity) {
		index[key(name)] = Candidate{Key: key(name), Identities: []Identity{identity}}
	}
	add(
		"own",
		Identity{
			Facts: model.ResourceFacts{
				Workload: &model.WorkloadResourceFacts{
					WorkloadUID:       "own",
					ServiceKeys:       []string{"svc-old"},
					GatewayReferences: []string{"gw-old"},
				},
			},
		},
	)
	add("outside", Identity{Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{WorkloadUID: "outside"}}})
	for _, name := range []string{"svc-old", "svc-new"} {
		add(name, Identity{Facts: model.ResourceFacts{Service: &model.ServiceResourceFacts{ServiceKey: name}}})
	}
	for _, name := range []string{"gw-old", "gw-new"} {
		add(name, Identity{Facts: model.ResourceFacts{GatewayOwner: name}})
	}
	add("withdrawn", Identity{Workloads: sets.New(WorkloadIdentity{UID: "own"})})
	index[key("unpublished")] = Candidate{Key: key("unpublished")}
	update := indexedUpdate("version", index)
	outsideOnly := indexedUpdate("outside", map[model.ResourceKey]Candidate{key("outside"): index[key("outside")]})
	empty := outsideOnly.ForWorkload("absent", snapshot)
	if len(empty.Candidates(model.AddressType)) != 0 || empty.addressScopes != nil {
		t.Fatal("empty scoped notice retained cluster-wide indexes")
	}
	for _, notice := range []Update{update, Merge(update, indexedUpdate("later", map[model.ResourceKey]Candidate{key("outside"): index[key("outside")]}))} {
		scoped := notice.ForWorkload("own", snapshot)
		var names []string
		for _, candidate := range scoped.Candidates(model.AddressType) {
			names = append(names, candidate.Key.Name)
		}
		want := []string{"gw-new", "gw-old", "own", "svc-new", "svc-old", "unpublished", "withdrawn"}
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("candidates=%v want=%v", names, want)
		}
		if len(notice.Candidates(model.AddressType)) != 8 {
			t.Fatal("modified shared publication")
		}
		if len(scoped.indexAddressScopes().addressesByWorkload["outside"]) != 0 {
			t.Fatal("scoped notice retained unrelated workload index")
		}
		// A second queued publication must preserve old dependencies and withdrawals.
		merged := Merge(scoped, indexedUpdate("next", map[model.ResourceKey]Candidate{
			key("own"): index[key("own")],
		}).ForWorkload("own", snapshot)).ForWorkload("own", snapshot)
		if !reflect.DeepEqual(merged.Candidates(model.AddressType), scoped.Candidates(model.AddressType)) {
			t.Fatal("scoped merge lost dependency or withdrawal evidence")
		}
	}
}

func TestEmptyWorkloadAddressNoticePreservesOtherUpdates(t *testing.T) {
	address := model.ResourceKey{TypeURL: model.AddressType, Name: "other"}
	for _, extraType := range []string{"", model.SecretType, model.SandboxType} {
		for _, fullSecret := range []bool{false, true} {
			candidates := map[model.ResourceKey]Candidate{address: {
				Key: address,
				Identities: []Identity{{
					Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{WorkloadUID: "other"}},
				}},
			}}
			extra := model.ResourceKey{TypeURL: extraType, Name: "extra"}
			if extraType != "" {
				candidates[extra] = Candidate{Key: extra}
			}
			original := indexedUpdate("version", candidates)
			if fullSecret {
				original = Merge(original, Update{
					version:   "version",
					full:      true,
					fullTypes: sets.New(model.SecretType),
				})
			}
			scoped := original.ForWorkload("own", model.ResourceSet{})
			if scoped.Version() != original.Version() || scoped.addressScopes != nil ||
				scoped.Affects(model.AddressType) || scoped.Affects(model.WorkloadType) ||
				len(scoped.Candidates(model.AddressType)) != 0 {
				t.Fatalf("empty Address scope retained unrelated work or lost its version: %+v", scoped)
			}
			if scoped.FullFor(model.SecretType) != fullSecret ||
				scoped.FullFor(model.SandboxType) != (extraType == model.SandboxType) {
				t.Fatal("changed another type's refresh scope")
			}
			if extraType == model.SecretType {
				if got := scoped.Candidates(extraType); len(got) != 1 || got[0].Key != extra {
					t.Fatal("lost the mixed Secret candidate")
				}
			}
			if len(original.Candidates(model.AddressType)) != 1 || !original.Affects(model.AddressType) ||
				original.FullFor(model.SandboxType) || extraType != "" && len(original.Candidates(extraType)) != 1 {
				t.Fatal("modified the shared notice")
			}
		}
	}
}

func TestWorkloadAddressIndexIsLazyAndShared(t *testing.T) {
	candidates := map[model.ResourceKey]Candidate{}
	for i := range 16 {
		uid := fmt.Sprint(i)
		key := model.ResourceKey{TypeURL: model.AddressType, Name: uid}
		candidates[key] = Candidate{
			Key: key,
			Identities: []Identity{
				{Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{WorkloadUID: uid}}},
			},
		}
	}
	update := indexedUpdate("initial", candidates)
	if update.addressScopes.addressesByWorkload != nil {
		t.Fatal("ordinary publication eagerly indexed workloads")
	}
	copy := update
	var clients sync.WaitGroup
	for i := range 16 {
		clients.Go(func() {
			uid := fmt.Sprint(i)
			scoped := copy.ForWorkload(uid, model.ResourceSet{})
			if got := scoped.Candidates(model.AddressType); len(got) != 1 || got[0].Key.Name != uid {
				t.Errorf("workload %s received %v", uid, got)
			}
			if scoped.addressScopes == update.addressScopes {
				t.Error("scoped notice retained the global index")
			}
		})
	}
	clients.Wait()
	if copy.addressScopes != update.addressScopes || len(update.addressScopes.addressesByWorkload) != 16 {
		t.Fatal("publication copies did not share their workload index")
	}
	key := model.ResourceKey{TypeURL: model.AddressType, Name: "16"}
	merged := Merge(update, indexedUpdate("next", map[model.ResourceKey]Candidate{key: {Key: key}}))
	if merged.addressScopes == update.addressScopes || merged.addressScopes.addressesByWorkload != nil {
		t.Fatal("changed publication reused a stale index or built one eagerly")
	}
}

func BenchmarkWorkloadQueuedAddressMerge(b *testing.B) {
	batches := [2]map[model.ResourceKey]Candidate{{}, {}}
	for i := range 10000 {
		uid := fmt.Sprintf("workload-%05d", i)
		key := model.ResourceKey{TypeURL: model.AddressType, Name: uid}
		batches[i/5000][key] = Candidate{
			Key: key,
			Identities: []Identity{{
				Name:  uid,
				Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{WorkloadUID: uid}},
			}},
		}
	}
	older, newer := indexedUpdate("older", batches[0]), indexedUpdate("newer", batches[1])
	for _, scoped := range []bool{false, true} {
		b.Run(fmt.Sprintf("scope-before-merge=%t", scoped), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				a, z := older, newer
				if scoped {
					a = a.ForWorkload("workload-00000", model.ResourceSet{})
					z = z.ForWorkload("workload-00000", model.ResourceSet{})
				}
				merged := Merge(a, z)
				if got := len(merged.Candidates(model.AddressType)); scoped && got != 1 || !scoped && got != 10000 {
					b.Fatalf("candidate count = %d", got)
				}
			}
		})
	}
}
