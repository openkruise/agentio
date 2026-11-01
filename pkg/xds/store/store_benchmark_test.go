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

func BenchmarkStorePublish(b *testing.B) {
	resources, variants := storeBenchmarkResources(b)
	initial, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("resources=10000/subscribers=%d", clientCount), func(b *testing.B) {
			ctx := b.Context()
			store := New(initial)
			subscriptions := make([]Subscription, clientCount)
			for client := range subscriptions {
				subscriptions[client] = store.Subscribe(ctx, model.ClientScope{})
				subscriptions[client].Watch(model.AddressType)
			}
			next := 1
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "subscribers/op")
			b.ResetTimer()
			for range b.N {
				resource := variants[next]
				if _, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}}); err != nil {
					b.Fatal(err)
				}
				for _, subscription := range subscriptions {
					<-subscription.Updates()
				}
				next ^= 1
			}
		})
	}
}

func storeBenchmarkResources(t testing.TB) ([]model.Resource, [2]model.Resource) {
	t.Helper()
	const resourceCount = 10_000
	const targetIndex = 5_050
	resources := make([]model.Resource, 0, resourceCount)
	var variants [2]model.Resource
	for index := range resourceCount {
		name := fmt.Sprintf("workload-%06d", index)
		facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
			WorkloadUID: name,
			Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
			NodeName:    fmt.Sprintf("node-%03d", index%100),
			Principal:   mustTestPrincipal("cluster.local", "ns/"+("demo")+"/sa/"+("default")),
		}}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name},
			"",
			&anypb.Any{TypeUrl: model.AddressType, Value: []byte("old")},
			nil,
			facts,
		)
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
		if index == targetIndex {
			variants[0] = resource
			variants[1], err = model.NewResource(
				resource.Key,
				"",
				&anypb.Any{TypeUrl: model.AddressType, Value: []byte("new")},
				nil,
				facts,
			)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return resources, variants
}

// Batch publication must not expand the same namespace policies for every workload.
func BenchmarkAuthorizationDependencyExpansion(b *testing.B) {
	for _, workloadCount := range []int{100, 1000} {
		for _, policyCount := range []int{100, 1000} {
			b.Run(fmt.Sprintf("workloads=%d/policies=%d", workloadCount, policyCount), func(b *testing.B) {
				resources := make([]model.Resource, 0, workloadCount+policyCount)
				changes := make([]model.ResourceChange, 0, workloadCount)
				for i := range policyCount {
					name := fmt.Sprintf("demo/p%d", i)
					resource, err := model.NewResource(
						model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name}, "",
						&anypb.Any{TypeUrl: model.WorkloadAuthorizationType, Value: []byte("policy")}, nil,
						model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{
							Scope:     model.AuthorizationScopeNamespace,
							Namespace: "demo",
						}})
					if err != nil {
						b.Fatal(err)
					}
					resources = append(resources, resource)
				}
				before, err := model.NewResourceSet(resources)
				if err != nil {
					b.Fatal(err)
				}
				for i := range workloadCount {
					name := fmt.Sprintf("w%d", i)
					resource, err := model.NewResource(
						model.ResourceKey{TypeURL: model.AddressType, Name: name}, "",
						&anypb.Any{TypeUrl: model.AddressType, Value: []byte("workload")}, nil,
						model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
							WorkloadUID: name,
							Namespace:   "demo",
							NodeName:    "node",
							Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
						}})
					if err != nil {
						b.Fatal(err)
					}
					resources = append(resources, resource)
					changes = append(changes, model.ResourceChange{Key: resource.Key, New: &resource})
				}
				after, err := model.NewResourceSet(resources)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					updateBetween(before, after, changes)
				}
			})
		}
	}
}

// Two global gateway publications arrive while the same clients are behind.
// Each gateway has legacy and native resources with the same wire name.
func BenchmarkStoreGatewayBacklog(b *testing.B) {
	for _, gateways := range []int{100, 1000} {
		resources := make([]model.Resource, 0, gateways*2)
		forward := make([]model.ResourceChange, 0, gateways*2)
		reverse := make([]model.ResourceChange, 0, gateways*2)
		for gateway := range gateways {
			owner := fmt.Sprintf("demo/gateway-%04d", gateway)
			for _, native := range []bool{false, true} {
				key := model.ResourceKey{
					TypeURL: model.ClusterType,
					Name:    fmt.Sprintf("%s|native=%t|sandbox-ext-proc", owner, native),
				}
				facts := model.ResourceFacts{GatewayOwner: owner, AgentioEgress: native}
				old, err := model.NewResource(
					key,
					"sandbox-ext-proc",
					&anypb.Any{TypeUrl: model.ClusterType, Value: []byte("old")},
					nil,
					facts,
				)
				if err != nil {
					b.Fatal(err)
				}
				next, err := model.NewResource(
					key,
					"sandbox-ext-proc",
					&anypb.Any{TypeUrl: model.ClusterType, Value: []byte("new")},
					nil,
					facts,
				)
				if err != nil {
					b.Fatal(err)
				}
				resources = append(resources, old)
				forward = append(forward, model.ResourceChange{Key: key, Old: &old, New: &next})
				reverse = append(reverse, model.ResourceChange{Key: key, Old: &next, New: &old})
			}
		}
		initial, err := model.NewResourceSet(resources)
		if err != nil {
			b.Fatal(err)
		}
		for _, clients := range []int{100, 1000} {
			b.Run(fmt.Sprintf("gateways=%d/subscribers=%d", gateways, clients), func(b *testing.B) {
				store := New(initial)
				subscriptions := make([]Subscription, clients)
				for i := range subscriptions {
					subscriptions[i] = store.Subscribe(b.Context(), model.ClientScope{})
					subscriptions[i].Watch(model.ClusterType)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					for _, changes := range [][]model.ResourceChange{forward, reverse} {
						if _, err := store.Apply(changes); err != nil {
							b.Fatal(err)
						}
					}
					for _, subscription := range subscriptions {
						if update := <-subscription.Updates(); len(
							update.Candidates(model.ClusterType),
						) != len(
							resources,
						) {
							b.Fatalf(
								"candidates=%d, want %d",
								len(update.Candidates(model.ClusterType)),
								len(resources),
							)
						}
					}
				}
			})
		}
	}
}
