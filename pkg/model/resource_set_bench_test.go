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

func BenchmarkResourceSetSingleKeyUpdate(b *testing.B) {
	b.Run("resources=100000", benchmarkResourceSetSingleKeyUpdate)
}

func benchmarkResourceSetSingleKeyUpdate(b *testing.B) {
	const resourcesCount = 100_000
	resources := make([]Resource, 0, resourcesCount)
	for i := range resourcesCount {
		name := fmt.Sprintf("cluster//Pod/default/pod-%06d", i)
		resources = append(resources, Resource{
			Key:     ResourceKey{TypeURL: AddressType, Name: name},
			XDSName: name,
			Value:   &anypb.Any{TypeUrl: AddressType, Value: []byte("address")},
			Hash:    name,
			Facts: ResourceFacts{Workload: &WorkloadResourceFacts{Namespace: "demo",
				WorkloadUID: name,
				Principal:   testPrincipal(),
			}},
		})
	}
	initial, err := NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	key := resources[len(resources)/2].Key
	variants := [2]Resource{resources[len(resources)/2], resources[len(resources)/2]}
	variants[0].Hash += "-a"
	variants[1].Hash += "-b"

	b.Run("incremental-sharded", func(b *testing.B) {
		set := initial
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resource := variants[i%2]
			var changed bool
			set, changed, err = set.Apply([]ResourceChange{{Key: key, New: &resource}})
			if err != nil || !changed {
				b.Fatalf("Apply() changed=%t err=%v", changed, err)
			}
		}
	})

	b.Run("full-rebuild", func(b *testing.B) {
		copyOfResources := append([]Resource(nil), resources...)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			copyOfResources[len(copyOfResources)/2] = variants[i%2]
			if _, err := NewResourceSet(copyOfResources); err != nil {
				b.Fatal(err)
			}
		}
	})
}
