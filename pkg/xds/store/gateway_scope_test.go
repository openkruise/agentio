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
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

func gatewayScopeFixture(t testing.TB, n int) (Update, Update, model.ResourceSet) {
	t.Helper()
	key := model.ResourceKey{TypeURL: model.AddressType, Name: "gateway"}
	batch := func(offset int) Update {
		owners := sets.New[WorkloadIdentity]()
		for i := range n {
			owners.Insert(WorkloadIdentity{UID: fmt.Sprint(i + offset)})
		}
		return indexedUpdate("v", map[model.ResourceKey]Candidate{key: {
			Key: key,
			Identities: []Identity{{
				Name: "gateway",
				Facts: model.ResourceFacts{
					GatewayOwner: "ns/gw",
					Workload:     &model.WorkloadResourceFacts{WorkloadUID: "gateway-pod"},
				},
				Workloads: owners,
			}},
		}})
	}
	resources := make([]model.Resource, 0, n)
	for i := range n {
		uid := fmt.Sprint(i)
		resources = append(resources, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.AddressType, Name: uid},
			XDSName: uid,
			Hash:    uid,
			Value:   &anypb.Any{TypeUrl: model.AddressType},
			Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID:       uid,
				GatewayReferences: []string{"ns/gw"},
			}},
		})
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	return batch(0), batch(n), snapshot
}

func TestScopedGatewayRetainsOnlyOwningWorkloadEvidence(t *testing.T) {
	old, next, snapshot := gatewayScopeFixture(t, 1000)
	scoped := Merge(old.ForWorkload("0", snapshot), next.ForWorkload("0", snapshot))
	candidates := scoped.Candidates(model.AddressType)
	if len(candidates) != 1 || len(candidates[0].Identities[0].Workloads) != 1 ||
		!candidates[0].Identities[0].Workloads.Contains(WorkloadIdentity{UID: "0"}) {
		t.Fatalf("lost owning workload evidence: %+v", candidates)
	}
	if len(old.Candidates(model.AddressType)[0].Identities[0].Workloads) != 1000 ||
		len(next.Candidates(model.AddressType)[0].Identities[0].Workloads) != 1000 {
		t.Fatal("modified shared publication")
	}
	retired := old.ForWorkload("0", model.ResourceSet{}).Candidates(model.AddressType)
	if len(retired) != 1 || len(retired[0].Identities[0].Workloads) != 1 {
		t.Fatal("lost dependency withdrawal after workload deletion")
	}
	other := old.ForWorkload("1", snapshot).Candidates(model.AddressType)
	if len(other) != 1 || !other[0].Identities[0].Workloads.Contains(WorkloadIdentity{UID: "1"}) {
		t.Fatal("scoping one client changed another client")
	}
	for _, candidate := range scoped.Candidates(model.AddressType) {
		for _, identity := range candidate.Identities {
			for owner := range identity.Workloads {
				if owner.UID != "0" {
					t.Fatalf(
						"scoped gateway retained %d workload identities, including %s",
						len(identity.Workloads),
						owner.UID,
					)
				}
			}
		}
	}
}

func TestUnchangedDependencyOnlyNotifiesItsWorkload(t *testing.T) {
	_, _, snapshot := gatewayScopeFixture(t, 2)
	key := model.ResourceKey{TypeURL: model.AddressType, Name: "gateway"}
	gateway := model.Resource{Key: key, XDSName: "gateway", Facts: model.ResourceFacts{GatewayOwner: "ns/gw"}}
	index := map[model.ResourceKey]Candidate{}
	addCandidate(index, gateway, &model.WorkloadResourceFacts{WorkloadUID: "0"})
	dependency := indexedUpdate("dependency", index)
	if len(dependency.ForWorkload("0", snapshot).Candidates(model.AddressType)) != 1 {
		t.Fatal("lost the changed workload's dependency")
	}
	peer := dependency.ForWorkload("1", snapshot)
	if peer.Affects(model.AddressType) || peer.Affects(model.WorkloadType) ||
		len(peer.Candidates(model.AddressType)) != 0 {
		t.Fatal("unchanged gateway dependency reached an unrelated workload")
	}
	addCandidate(index, gateway, nil)
	direct := indexedUpdate("direct", index)
	for _, update := range []Update{direct, Merge(dependency, direct), Merge(direct, dependency)} {
		if len(update.ForWorkload("1", snapshot).Candidates(model.AddressType)) != 1 {
			t.Fatal("direct gateway changes must reach all dependent workloads")
		}
	}
	if !dependency.Candidates(model.AddressType)[0].DependencyOnly {
		t.Fatal("modified the shared dependency notice")
	}
}

func BenchmarkSharedGatewayQueuedScope(b *testing.B) {
	old, next, snapshot := gatewayScopeFixture(b, 1000)
	b.ReportAllocs()
	for b.Loop() {
		for i := range 100 {
			uid := fmt.Sprint(i)
			merged := Merge(old.ForWorkload(uid, snapshot), next.ForWorkload(uid, snapshot))
			if len(merged.Candidates(model.AddressType)) != 1 {
				b.Fatal("lost gateway dependency")
			}
		}
	}
}

func TestWorkloadSandboxNoticesReselectWithoutQueuedCandidates(t *testing.T) {
	key := model.ResourceKey{TypeURL: model.SandboxType, Name: "retired"}
	secret := model.ResourceKey{TypeURL: model.SecretType, Name: "secret"}
	for _, mixed := range []bool{false, true} {
		candidates := map[model.ResourceKey]Candidate{key: {Key: key}}
		if mixed {
			candidates[secret] = Candidate{Key: secret}
		}
		notice := indexedUpdate("version", candidates)
		for _, refresh := range []Update{{}, {full: true, fullTypes: sets.New(model.SecretType)}, {full: true}} {
			original := Merge(notice, refresh)
			original.version = notice.version
			scoped := original.ForWorkload("own", model.ResourceSet{})
			queued := Merge(scoped, scoped.ForWorkload("own", model.ResourceSet{}))
			if !queued.FullFor(model.SandboxType) || len(queued.Candidates(model.SandboxType)) != 0 ||
				queued.Version() != notice.Version() {
				t.Fatalf("Sandbox reselect retained candidates or lost pending-name refresh: %+v", queued)
			}
			if queued.FullFor(model.AddressType) != original.FullFor(model.AddressType) ||
				queued.FullFor(model.SecretType) != original.FullFor(model.SecretType) {
				t.Fatal("changed other resource refresh scopes")
			}
			if len(original.Candidates(model.SandboxType)) != 1 ||
				original.FullFor(model.SandboxType) != refresh.FullFor(model.SandboxType) {
				t.Fatal("modified shared Sandbox publication")
			}
			if mixed {
				for _, update := range []Update{original, scoped, queued} {
					if got := update.Candidates(model.SecretType); len(got) != 1 || got[0].Key != secret {
						t.Fatal("lost the mixed Secret candidate")
					}
				}
			}
		}
	}
}
