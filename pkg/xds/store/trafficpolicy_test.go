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
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

func trafficPolicyResource(t testing.TB, typ, name, value string, refs ...string) model.Resource {
	t.Helper()
	facts := model.ResourceFacts{}
	if typ == model.AddressType {
		facts.Workload = &model.WorkloadResourceFacts{WorkloadUID: name, TrafficPolicyRefs: refs}
	} else if typ == model.SandboxType {
		facts.Sandbox = &model.SandboxResourceFacts{AttesterWorkloadUID: "w"}
	}
	r, err := model.NewResource(model.ResourceKey{TypeURL: typ, Name: name}, name,
		model.Prebuilt(&anypb.Any{TypeUrl: typ, Value: []byte(value)}), nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func withReferences(t testing.TB, r model.Resource, keys ...model.ResourceKey) model.Resource {
	t.Helper()
	facts := r.Facts
	facts.References = &model.ResourceReferences{Keys: keys}
	result, err := model.NewResource(r.Key, r.XDSName, model.Prebuilt(r.Value), r.Aliases, facts)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDeletionRetainsReferencedResourceTypes(t *testing.T) {
	for _, typ := range []string{model.TrafficPolicyType, model.SecurityProfileType, model.SniTrafficPolicyType} {
		t.Run(typ, func(t *testing.T) {
			body := trafficPolicyResource(t, typ, "policy", "body")
			w := withReferences(t, trafficPolicyResource(t, model.AddressType, "w", "bound"), body.Key)
			sandbox := withReferences(t, trafficPolicyResource(t, model.SandboxType, "sandbox", "bound"), body.Key)
			initial, err := model.NewResourceSet([]model.Resource{body, w, sandbox})
			if err != nil {
				t.Fatal(err)
			}
			s := New(initial)
			apply := func(changes ...model.ResourceChange) Publication {
				t.Helper()
				p, err := s.Apply(changes)
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			if apply(model.ResourceChange{Key: body.Key, Old: &body}).Changed {
				t.Fatal("referenced body was withdrawn")
			}
			sub := s.Subscribe(t.Context(), model.ClientScope{})
			sub.Watch(typ)
			unbound := withReferences(t, w)
			apply(model.ResourceChange{Key: w.Key, New: &unbound})
			if _, ok := s.Snapshot().Get(body.Key); !ok {
				t.Fatal("remaining Sandbox reference was ignored")
			}
			select {
			case <-sub.Updates():
			default:
				t.Fatal("reference withdrawal did not invalidate the target type")
			}
			p := apply(model.ResourceChange{Key: sandbox.Key, Old: &sandbox})
			if _, ok := p.Snapshot.Get(body.Key); ok || len(s.pendingRemovals) != 0 {
				t.Fatal("last reference did not release body")
			}
		})
	}
}

func TestDeletionReleasesDependencyChain(t *testing.T) {
	leaf := trafficPolicyResource(t, model.SniTrafficPolicyType, "same", "leaf")
	parent := withReferences(t, trafficPolicyResource(t, model.SecurityProfileType, "same", "parent"), leaf.Key)
	root := withReferences(t, trafficPolicyResource(t, model.AddressType, "w", "root"), parent.Key)
	initial, err := model.NewResourceSet([]model.Resource{root, parent, leaf})
	if err != nil {
		t.Fatal(err)
	}
	s := New(initial)
	if _, err := s.Apply(
		[]model.ResourceChange{{Key: leaf.Key, Old: &leaf}, {Key: parent.Key, Old: &parent}},
	); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().Len() != 3 || len(s.pendingRemovals) != 2 {
		t.Fatal("dependency chain was not retained atomically")
	}
	unbound := withReferences(t, root)
	p, err := s.Apply([]model.ResourceChange{{Key: root.Key, New: &unbound}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Snapshot.Len() != 1 || len(s.pendingRemovals) != 0 {
		t.Fatal("unreferenced dependency chain was not reclaimed")
	}
}

func TestTrafficPolicyDeletionWaitsForBindings(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "Apply", true: "Replace"}[replace], func(t *testing.T) {
			policy := trafficPolicyResource(t, model.TrafficPolicyType, "p", "allow")
			first := trafficPolicyResource(t, model.AddressType, "first", "bound", "p")
			second := trafficPolicyResource(t, model.AddressType, "second", "bound", "p")
			initial, err := model.NewResourceSet([]model.Resource{policy, first, second})
			if err != nil {
				t.Fatal(err)
			}
			s := New(initial)
			sub := s.Subscribe(t.Context(), model.ClientScope{})
			sub.Watch(model.TrafficPolicyType)
			publish := func(changes ...model.ResourceChange) Publication {
				t.Helper()
				if replace {
					raw, _, err := s.Snapshot().Apply(changes)
					if err != nil {
						t.Fatal(err)
					}
					// The compiler's full snapshot never contains the retained body.
					raw, _, err = raw.Apply([]model.ResourceChange{{Key: policy.Key}})
					if err != nil {
						t.Fatal(err)
					}
					return s.Replace(raw)
				}
				p, err := s.Apply(changes)
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			p := publish(model.ResourceChange{Key: policy.Key, Old: &policy})
			if p.Changed || p.Snapshot.Version() != initial.Version() {
				t.Fatal("deferred deletion changed publication")
			}
			select {
			case <-sub.Updates():
				t.Fatal("retained policy was withdrawn")
			default:
			}
			unbound := trafficPolicyResource(t, model.AddressType, first.Key.Name, "unbound")
			publish(model.ResourceChange{Key: first.Key, New: &unbound})
			if _, ok := s.Snapshot().Get(policy.Key); !ok {
				t.Fatal("body removed with a remaining reference")
			}
			p = publish(model.ResourceChange{Key: second.Key, Old: &second})
			if _, ok := p.Snapshot.Get(policy.Key); ok || len(s.pendingRemovals) != 0 {
				t.Fatal("last reference did not release body")
			}
			select {
			case <-sub.Updates():
			default:
				t.Fatal("final policy deletion was not notified")
			}
			if _, ok := initial.Get(policy.Key); !ok {
				t.Fatal("old immutable snapshot was mutated")
			}
		})
	}
}

func TestTrafficPolicyRecreationCancelsDeletion(t *testing.T) {
	for _, sameBody := range []bool{false, true} {
		for _, replace := range []bool{false, true} {
			policy := trafficPolicyResource(t, model.TrafficPolicyType, "p", "allow")
			w := trafficPolicyResource(t, model.AddressType, "w", "bound", "p")
			initial, err := model.NewResourceSet([]model.Resource{policy, w})
			if err != nil {
				t.Fatal(err)
			}
			s := New(initial)
			if _, err := s.Apply([]model.ResourceChange{{Key: policy.Key, Old: &policy}}); err != nil {
				t.Fatal(err)
			}
			recreated := policy
			if !sameBody {
				recreated = trafficPolicyResource(t, model.TrafficPolicyType, "p", "deny")
			}
			if replace {
				next, err := model.NewResourceSet([]model.Resource{recreated})
				if err != nil {
					t.Fatal(err)
				}
				s.Replace(next)
			} else {
				// Recreation and the last reference withdrawal may share a batch.
				if _, err := s.Apply(
					[]model.ResourceChange{{Key: w.Key, Old: &w}, {Key: recreated.Key, New: &recreated}},
				); err != nil {
					t.Fatal(err)
				}
			}
			got, ok := s.Snapshot().Get(policy.Key)
			if !ok || got.Hash != recreated.Hash || len(s.pendingRemovals) != 0 {
				t.Fatalf("recreated body removed: same=%v replace=%v", sameBody, replace)
			}
		}
	}
}
