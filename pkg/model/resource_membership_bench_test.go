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
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
)

// Shared policy and gateway postings must not be copied once per changed
// workload. Keep single-key and payload-only controls alongside lifecycle churn.
func BenchmarkResourceMembershipBatch(b *testing.B) {
	benchmarkResourceMembershipBatch(b, true, 1000, 1)
}

func BenchmarkResourceMembershipBatchWithoutGlobalReferences(b *testing.B) {
	benchmarkResourceMembershipBatch(b, false, 1000, 1)
}

func BenchmarkResourceMembershipBatchUniqueFacts(b *testing.B) {
	benchmarkResourceMembershipBatch(b, false, 1, 1)
}

// Change one member per two-member namespace/node group. Each shared posting
// receives only one change, exposing batching overhead without coalescing gains.
func BenchmarkResourceMembershipBatchDispersedSmallGroups(b *testing.B) {
	benchmarkResourceMembershipBatch(b, false, 2, 2)
}

func benchmarkResourceMembershipBatch(b *testing.B, shared bool, namespaceSize, stride int) {
	for _, size := range []int{50000, 100000} {
		b.Run(fmt.Sprintf("inventory=%d", size), func(b *testing.B) {
			resources := make([]Resource, size)
			for i := range resources {
				name := fmt.Sprintf("w-%06d", i)
				resources[i] = Resource{
					Key:     ResourceKey{TypeURL: AddressType, Name: name},
					XDSName: name,
					Hash:    name,
					Value:   &anypb.Any{TypeUrl: AddressType, Value: []byte("old")},
					Facts: ResourceFacts{Workload: &WorkloadResourceFacts{
						WorkloadUID:       name,
						Namespace:         fmt.Sprintf("ns-%03d", i/namespaceSize),
						NodeName:          fmt.Sprintf("node-%04d", i/min(namespaceSize, 100)),
						Principal:         testPrincipal(),
						TrafficPolicyRefs: []string{"global/policy"},
						GatewayReferences: []string{"gateway"},
					}},
				}
				if !shared {
					resources[i].Facts.Workload.Principal = Principal{}
					resources[i].Facts.Workload.TrafficPolicyRefs = nil
					resources[i].Facts.Workload.GatewayReferences = nil
				}
			}
			initial, err := NewResourceSet(resources)
			if err != nil {
				b.Fatal(err)
			}
			for _, count := range []int{1, 100, 1000} {
				b.Run(fmt.Sprintf("batch=%d", count), func(b *testing.B) {
					deletes := make([]ResourceChange, count)
					adds := make([]ResourceChange, count)
					updates := make([]ResourceChange, count)
					for i := range count {
						old := resources[size-stride*count+stride*i]
						next := old
						next.Hash += "-updated"
						next.Value = &anypb.Any{TypeUrl: AddressType, Value: []byte("new")}
						deletes[i] = ResourceChange{Key: old.Key, Old: &old}
						adds[i] = ResourceChange{Key: old.Key, New: &old}
						updates[i] = ResourceChange{Key: old.Key, Old: &old, New: &next}
					}
					absent, _, err := initial.Apply(deletes)
					if err != nil {
						b.Fatal(err)
					}
					for _, tc := range []struct {
						name    string
						set     ResourceSet
						changes []ResourceChange
						want    int
					}{{"delete", initial, deletes, size - count}, {"add", absent, adds, size}, {"payload", initial, updates, size}} {
						b.Run(tc.name, func(b *testing.B) {
							b.ReportAllocs()
							for b.Loop() {
								next, changed, err := tc.set.Apply(tc.changes)
								if err != nil || !changed || next.Len() != tc.want {
									b.Fatalf("changed=%t len=%d err=%v", changed, next.Len(), err)
								}
							}
						})
					}
				})
			}
		})
	}
}
