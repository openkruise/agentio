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

func BenchmarkWorkloadQuery(b *testing.B) {
	principal := testPrincipal()
	resources := make([]Resource, 10000)
	for index := range resources {
		uid := fmt.Sprintf("uid-%05d", index)
		resources[index] = Resource{Key: ResourceKey{TypeURL: AddressType, Name: uid},
			Value: &anypb.Any{TypeUrl: AddressType, Value: []byte(uid)},
			Facts: ResourceFacts{
				Workload: &WorkloadResourceFacts{
					Namespace:         "demo",
					WorkloadUID:       uid,
					Source:            SourceRef{Registry: "kubernetes/test", Key: uid},
					NodeName:          fmt.Sprintf("node-%03d", index/100),
					Principal:         principal,
					AuthorizationRefs: []string{fmt.Sprintf("demo/policy-%05d", index)},
				},
			},
		}
	}
	const longUID = "Kubernetes//Pod/production/workload-00001"
	const longPolicy = "production/workload-traffic-policy-00001"
	resources = append(resources, Resource{Key: ResourceKey{TypeURL: AddressType, Name: longUID},
		Value: &anypb.Any{TypeUrl: AddressType, Value: []byte("long-names")},
		Facts: ResourceFacts{
			Workload: &WorkloadResourceFacts{
				Namespace:         "demo",
				WorkloadUID:       longUID,
				Source:            SourceRef{Registry: "kubernetes/test", Key: "source-long"},
				NodeName:          "node-long",
				Principal:         principal,
				AuthorizationRefs: []string{longPolicy},
			},
		},
	})
	snapshot, err := NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		query WorkloadQuery
		want  bool
	}{
		{"dedicated-match", WorkloadQuery{WorkloadUID: "uid-00001", Source: SourceRef{Registry: "kubernetes/test", Key: "uid-00001"}, Principal: &principal, AuthorizationRefsOnly: true, AuthorizationReference: "demo/policy-00001"}, true},
		{"dedicated-unrelated", WorkloadQuery{WorkloadUID: "uid-00001", Source: SourceRef{Registry: "kubernetes/test", Key: "uid-00001"}, Principal: &principal, AuthorizationRefsOnly: true, AuthorizationReference: "demo/policy-00002"}, false},
		{"shared-match", WorkloadQuery{NodeName: "node-000", AuthorizationRefsOnly: true, AuthorizationReference: "demo/policy-00001"}, true},
		{"shared-unrelated", WorkloadQuery{NodeName: "node-001", AuthorizationRefsOnly: true, AuthorizationReference: "demo/policy-00001"}, false},
		{"dedicated-long-names", WorkloadQuery{WorkloadUID: longUID, Source: SourceRef{Registry: "kubernetes/test", Key: "source-long"}, Principal: &principal, AuthorizationRefsOnly: true, AuthorizationReference: longPolicy}, true},
		{"shared-long-names", WorkloadQuery{NodeName: "node-long", AuthorizationRefsOnly: true, AuthorizationReference: longPolicy}, true},
		{"principal", WorkloadQuery{Principal: &principal}, true},
		{"global", WorkloadQuery{AuthorizationRefsOnly: true}, true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if snapshot.HasWorkload(AddressType, tc.query) != tc.want {
					b.Fatal("incorrect query result")
				}
			}
		})
	}
}
