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

package trafficpolicy

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	xdsstore "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

type benchSource struct {
	mu       sync.Mutex
	changed  chan struct{}
	snapshot xdsclient.Snapshot
}

func (s *benchSource) Snapshot() xdsclient.Snapshot {
	return s.SnapshotFor(nil)
}

func (s *benchSource) SnapshotFor(names map[string][]string) xdsclient.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := xdsclient.Snapshot{
		Changed:   s.snapshot.Changed,
		Synced:    s.snapshot.Synced,
		Resources: map[string]map[string]*xdsclient.Resource{},
	}
	for typ, resources := range s.snapshot.Resources {
		if names == nil {
			result.Resources[typ] = maps.Clone(resources)
			continue
		}
		selected := map[string]*xdsclient.Resource{}
		for _, name := range names[typ] {
			if resource := resources[name]; resource != nil {
				selected[name] = resource
			}
		}
		result.Resources[typ] = selected
	}
	return result
}

func (s *benchSource) Demand(context.Context, string, string) (*xdsclient.Resource, error) {
	return nil, xdsclient.ErrNotFound
}

func (s *benchSource) Observe(_ ...string) (<-chan struct{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot.Changed, true
}

func benchFixture(count int) (*benchSource, *store.Aggregate, *resourceResolver, subject.Subject) {
	pack := func(m proto.Message) *anypb.Any {
		a, err := anypb.New(m)
		if err != nil {
			panic(err)
		}
		return a
	}
	source := &benchSource{
		changed: make(chan struct{}),
		snapshot: xdsclient.Snapshot{
			Synced:    map[string]bool{model.WorkloadType: true, model.TrafficPolicyType: true},
			Resources: map[string]map[string]*xdsclient.Resource{model.WorkloadType: {}, model.TrafficPolicyType: {}},
		},
	}
	source.snapshot.Changed = source.changed
	ref := pack(
		&ext.PolicyReference{
			TypeUrl:   model.TrafficPolicyType,
			Resources: []*ext.PolicyResourceReference{{Name: "policy"}},
		},
	)
	profile := pack(&ext.PolicyReference{TypeUrl: model.SecurityProfileType})
	for i := range count {
		name := fmt.Sprintf("pod-%d", i)
		source.snapshot.Resources[model.WorkloadType][name] = &xdsclient.Resource{Value: &workload.Workload{
			Uid:       name,
			Name:      name,
			Namespace: "ns",
			Addresses: [][]byte{{192, 0, 2, 1}},
			Extensions: []*workload.Extension{
				{Name: "traffic-policy-reference", Config: ref},
				{Name: "security-profile-reference", Config: profile},
			},
		},
		}
	}
	source.snapshot.Resources[model.TrafficPolicyType]["policy"] = &xdsclient.Resource{Value: &sec.TrafficPolicy{
		Egress: &sec.TrafficPolicy_RuleSet{
			Rules: []*sec.TrafficPolicy_Rule{
				{
					Match: &sec.TrafficPolicy_Match{
						DestinationIps: []*sec.TrafficPolicy_Address{address("203.0.113.0/24")},
					},
				},
			},
		},
	},
	}
	aggregate := store.NewAggregate(xdsstore.New(source))
	RegisterQueries(aggregate, "Kubernetes")
	r := &resourceResolver{source: aggregate}
	return source, aggregate, r, subject.Subject{
		Workload: subject.Workload{Namespace: "ns", Name: "pod-0", IP: "192.0.2.1"},
	}
}

func BenchmarkResourceQueries(b *testing.B) {
	for _, count := range []int{100, 1000, 10000, 50000} {
		b.Run(fmt.Sprintf("N%d", count), func(b *testing.B) {
			source, aggregate, r, pod := benchFixture(count)
			ctx := context.Background()
			if _, err := r.config(ctx, pod); err != nil {
				b.Fatal(err)
			}
			b.Run("GetParallel", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if _, err := aggregate.Get(store.Key{Type: store.TrafficPolicy, Name: "policy"}); err != nil {
							b.Error(err)
						}
					}
				})
			})
			b.Run("ResourcesForParallel", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if _, err := lookup(ctx, aggregate, pod); err != nil {
							b.Error(err)
						}
					}
				})
			})
			b.Run("AuthorizationParallel", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if _, err := r.config(ctx, pod); err != nil {
							b.Error(err)
						}
					}
				})
			})
			b.Run("UnrelatedUpdate", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					source.mu.Lock()
					old := source.snapshot.Resources[model.WorkloadType]["pod-1"]
					w := proto.Clone(old.Value.(*workload.Workload)).(*workload.Workload)
					w.ClusterId = fmt.Sprint(i)
					source.snapshot.Resources[model.WorkloadType]["pod-1"] = &xdsclient.Resource{Value: w}
					close(source.changed)
					source.changed = make(chan struct{})
					source.snapshot.Changed = source.changed
					source.mu.Unlock()
					aggregate.Refresh()
					if _, err := r.config(ctx, pod); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func TestXDSUpdatePreservesUnrelatedCompiledEntry(t *testing.T) {
	source, aggregate, _, _ := benchFixture(2)
	before := aggregate.Snapshot()
	previous := before.Query(store.TrafficPolicy).(*queryIndex)
	value := proto.Clone(source.snapshot.Resources[model.WorkloadType]["pod-1"].Value.(*workload.Workload)).(*workload.Workload)
	value.ClusterId = "updated"
	source.snapshot.Resources[model.WorkloadType]["pod-1"] = &xdsclient.Resource{Value: value}
	close(source.changed)
	source.changed = make(chan struct{})
	source.snapshot.Changed = source.changed
	aggregate.Refresh()
	current := aggregate.Snapshot().Query(store.TrafficPolicy).(*queryIndex)
	if current.workloads[subjectKey{"ns", "pod-0"}] != previous.workloads[subjectKey{"ns", "pod-0"}] {
		t.Fatal("unchanged workload recompiled after single-source passthrough")
	}
	if current.workloads[subjectKey{"ns", "pod-1"}] == previous.workloads[subjectKey{"ns", "pod-1"}] {
		t.Fatal("changed workload entry not replaced")
	}
	if previous.workloads[subjectKey{"ns", "pod-1"}].workload.Value.(*workload.Workload).ClusterId != "" {
		t.Fatal("old entry mutated")
	}
}
