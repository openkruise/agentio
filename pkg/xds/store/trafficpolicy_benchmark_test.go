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

	"github.com/openkruise/agentio/pkg/model"
)

func BenchmarkTrafficPolicyRetention(b *testing.B) {
	refs := []string{"p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"}
	for _, size := range []int{10_000, 100_000} {
		b.Run(fmt.Sprintf("workloads=%d", size), func(b *testing.B) {
			resources := make([]model.Resource, 0, size+len(refs))
			for i := range size {
				name := fmt.Sprintf("w%d", i)
				resources = append(resources, model.Resource{
					Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
					XDSName: name,
					Hash:    name,
					Value:   &anypb.Any{TypeUrl: model.AddressType, Value: []byte(name)},
					Facts: model.ResourceFacts{
						Workload: &model.WorkloadResourceFacts{WorkloadUID: name, TrafficPolicyRefs: refs},
					},
				})
			}
			var deletions []model.ResourceChange
			for _, name := range refs {
				p := model.Resource{Key: model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: name},
					XDSName: name,
					Hash:    name,
					Value:   &anypb.Any{TypeUrl: model.TrafficPolicyType, Value: []byte(name)}}
				resources = append(resources, p)
				deletions = append(deletions, model.ResourceChange{Key: p.Key, Old: &p})
			}
			initial, err := model.NewResourceSet(resources)
			if err != nil {
				b.Fatal(err)
			}
			for _, pending := range []bool{false, true} {
				for _, rebind := range []bool{false, true} {
					b.Run(fmt.Sprintf("pending=%v/rebind=%v", pending, rebind), func(b *testing.B) {
						s := New(initial)
						if pending {
							if _, err := s.Apply(deletions); err != nil {
								b.Fatal(err)
							}
						}
						variants := [2]model.Resource{resources[0], resources[0]}
						variants[1].Hash += "-new"
						if rebind {
							facts := *variants[1].Facts.Workload
							facts.TrafficPolicyRefs = refs[1:]
							variants[1].Facts.Workload = &facts
						}
						b.ReportAllocs()
						b.ResetTimer()
						for i := range b.N {
							r := variants[(i+1)%2]
							if _, err := s.Apply([]model.ResourceChange{{Key: r.Key, New: &r}}); err != nil {
								b.Fatal(err)
							}
						}
					})
				}
			}
		})
	}
}
