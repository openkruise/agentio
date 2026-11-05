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

package xds

import (
	"fmt"
	"maps"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func BenchmarkDedicatedSandboxBulkPolicy(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			scope := model.ClientScope{
				Class:       model.ClientDedicatedZTunnel,
				WorkloadUID: "worker-0",
				Source:      model.SourceRef{Registry: "test", Key: "worker-0"},
				Principal:   model.MustServiceAccountPrincipal("workers", "default"),
			}
			worker := model.Resource{
				Key:     model.ResourceKey{TypeURL: model.AddressType, Name: "worker-0"},
				XDSName: "worker-0",
				Hash:    "worker-0",
				Value:   &anypb.Any{TypeUrl: model.AddressType},
				Facts: model.ResourceFacts{
					Workload: &model.WorkloadResourceFacts{
						WorkloadUID: scope.WorkloadUID,
						Source:      scope.Source,
						Principal:   scope.Principal,
					},
				},
			}
			resources := []model.Resource{worker}
			changes := make([]model.ResourceChange, 0, size)
			for i := range size {
				r := sandboxResourceWithAttester(b, fmt.Sprintf("sandbox-%d", i), fmt.Sprintf("worker-%d", i))
				resources = append(resources, r)
				r.Hash += "-changed"
				changes = append(changes, model.ResourceChange{Key: r.Key, New: &r})
			}
			before, err := model.NewResourceSet(resources)
			if err != nil {
				b.Fatal(err)
			}
			store := xdsstore.New(before)
			sub := store.Subscribe(b.Context(), scope)
			sub.Watch(model.SandboxType)
			if _, err := store.Apply(changes); err != nil {
				b.Fatal(err)
			}
			update := <-sub.Updates()
			generator := SandboxGenerator{}
			initial := initializedSubscription(
				b,
				generator,
				scope,
				model.SandboxType,
				before,
				SubscriptionView{wildcard: true},
			)
			server := &Server{resources: store, generators: map[string]ResourceGenerator{model.SandboxType: generator}}
			stream := newFakeStream(b.Context(), 0)
			watch := &watchState{wildcard: true, names: sets.New[string](), started: true}
			watches := map[string]*watchState{model.SandboxType: watch}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				watch.sent = maps.Clone(initial.sent)
				stream.responses = nil
				err := server.pushUpdate(stream, scope, log, watches, update)
				if err != nil || len(stream.responses) != 1 || len(stream.responses[0].Resources) != 1 {
					b.Fatalf("responses=%v err=%v", stream.responses, err)
				}
			}
		})
	}
}
