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
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

// Cold selection must scale with the selected gateway, not unrelated inventory.
func BenchmarkGatewayColdSelection(b *testing.B) {
	for _, gateways := range []int{1, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("gateways=%d", gateways), func(b *testing.B) {
			resources := make([]model.Resource, 0, gateways*20)
			for g := range gateways {
				for v := range 2 {
					for r := range 10 {
						owner := fmt.Sprintf("demo/gateway-%05d", g)
						name := fmt.Sprintf("cluster-%02d", r)
						resource, err := model.NewResource(
							model.ResourceKey{
								TypeURL: model.ClusterType,
								Name:    fmt.Sprintf("%s|%d|%s", owner, v, name),
							},
							name,
							&anypb.Any{TypeUrl: model.ClusterType, Value: []byte("payload")},
							nil,
							model.ResourceFacts{GatewayOwner: owner, AgentioEgress: v == 1},
						)
						if err != nil {
							b.Fatal(err)
						}
						resources = append(resources, resource)
					}
				}
			}
			snapshot, err := model.NewResourceSet(resources)
			if err != nil {
				b.Fatal(err)
			}
			scope := gatewayScope()
			scope.GatewayKey = "demo/gateway-00000"
			request := GenerationRequest{
				Scope:        scope,
				Snapshot:     snapshot,
				TypeURL:      model.ClusterType,
				Subscription: SubscriptionView{wildcard: true},
				Full:         true,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				delta, err := (SnapshotGenerator{}).Generate(b.Context(), request)
				if err != nil || len(delta.Resources) != 10 {
					b.Fatalf("%d %v", len(delta.Resources), err)
				}
			}
		})
	}
}

// Updating another gateway with the same wire name must not trigger a global lookup.
func BenchmarkGatewayUnrelatedIncremental(b *testing.B) {
	for _, gateways := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("gateways=%d", gateways), func(b *testing.B) {
			resources := make([]model.Resource, 0, gateways*2)
			for g := range gateways {
				for v := range 2 {
					owner := fmt.Sprintf("demo/gateway-%05d", g)
					resource, err := model.NewResource(
						model.ResourceKey{
							TypeURL: model.ClusterType,
							Name:    fmt.Sprintf("%s|%d|http_dynamic_forward_proxy", owner, v),
						},
						"http_dynamic_forward_proxy",
						&anypb.Any{TypeUrl: model.ClusterType, Value: []byte("payload")},
						nil,
						model.ResourceFacts{GatewayOwner: owner, AgentioEgress: v == 1},
					)
					if err != nil {
						b.Fatal(err)
					}
					resources = append(resources, resource)
				}
			}
			before, err := model.NewResourceSet(resources)
			if err != nil {
				b.Fatal(err)
			}
			old := resources[2]
			next, err := model.NewResource(
				old.Key,
				old.XDSName,
				&anypb.Any{TypeUrl: model.ClusterType, Value: []byte("changed")},
				nil,
				old.Facts,
			)
			if err != nil {
				b.Fatal(err)
			}
			changes := []model.ResourceChange{{Key: old.Key, Old: &old, New: &next}}
			after, _, err := before.Apply(changes)
			if err != nil {
				b.Fatal(err)
			}
			scope := gatewayScope()
			scope.GatewayKey = "demo/gateway-00000"
			request := GenerationRequest{
				Scope:    scope,
				Snapshot: after,
				TypeURL:  model.ClusterType,
				Subscription: SubscriptionView{
					wildcard: true,
					sent:     map[string]string{resources[0].XDSName: resources[0].Hash},
				},
				Update: updateBetween(before, after, changes),
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				delta, err := (SnapshotGenerator{}).Generate(b.Context(), request)
				if err != nil || len(delta.Resources) != 0 || len(delta.Removed) != 0 {
					b.Fatalf("%+v %v", delta, err)
				}
			}
		})
	}
}

func BenchmarkGatewayNACKUnrelatedUpdate(b *testing.B) {
	for _, count := range []int{10, 1000} {
		b.Run(fmt.Sprintf("resources=%d", count), func(b *testing.B) {
			resources := make([]model.Resource, 0, count+1)
			watch := &watchState{
				wildcard:    true,
				recovering:  true,
				sent:        make(map[string]string, count),
				pendingAcks: map[string]string{"a-0": "rejected"},
			}
			for i := range count {
				r := gatewayResourceOfType(b, model.RouteType, "demo/egress", fmt.Sprintf("a-%d", i), "payload")
				resources = append(resources, r)
				watch.sent[r.XDSName] = r.Hash
			}
			other := gatewayResourceOfType(b, model.RouteType, "demo/other", "a-0", "before")
			resources = append(resources, other)
			server := newTestServer(b, gatewayScope(), resources, nil)
			before := server.resources.Snapshot()
			next := gatewayResourceOfType(b, model.RouteType, "demo/other", "a-0", "after")
			changes := []model.ResourceChange{{Key: other.Key, Old: &other, New: &next}}
			after, _, err := before.Apply(changes)
			if err != nil {
				b.Fatal(err)
			}
			server.resources.publish(after)
			update := updateBetween(before, after, changes)
			stream := &countingDeltaStream{ctx: b.Context()}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := server.server.sendIncremental(
					stream,
					server.scope,
					log,
					model.RouteType,
					watch,
					update,
				); err != nil {
					b.Fatal(err)
				}
			}
			if stream.responses != 0 {
				b.Fatal("unrelated update retried rejected configuration")
			}
		})
	}
}
