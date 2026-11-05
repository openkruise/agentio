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
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

func BenchmarkWorkloadGeneratorGatewayUpdate(b *testing.B) {
	b.Run("unrelated-resources=5000", func(b *testing.B) {
		const unrelatedCount = 5_000
		value := func(payload string) *anypb.Any {
			return &anypb.Any{TypeUrl: model.AddressType, Value: []byte(payload)}
		}
		resource := func(name, payload string, facts model.ResourceFacts) model.Resource {
			result, err := model.NewResource(
				model.ResourceKey{TypeURL: model.AddressType, Name: name}, "", value(payload), nil, facts)
			if err != nil {
				b.Fatal(err)
			}
			return result
		}
		resources := make([]model.Resource, 0, unrelatedCount+3)
		for index := range unrelatedCount {
			name := fmt.Sprintf("other-%05d", index)
			resources = append(resources, resource(fmt.Sprintf("unrelated-%05d", index), "unrelated",
				model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
					WorkloadUID: name,
					Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
					Principal:   model.MustServiceAccountPrincipal("other", "default"),
				}}))
		}
		resources = append(resources, resource("uid-a", "workload",
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID:       "uid-a",
				Source:            model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
				Principal:         model.MustServiceAccountPrincipal("demo", "default"),
				GatewayReferences: []string{"agentio-system/egress-a"},
			}}))
		oldGateway := resource("gateway-a", "old",
			model.ResourceFacts{
				Workload: &model.WorkloadResourceFacts{
					WorkloadUID: "gateway-a",
					Principal:   model.MustServiceAccountPrincipal("agentio-system", "gateway"),
				},
				GatewayOwner: "agentio-system/egress-a",
			})
		newGateway := resource("gateway-a", "new",
			model.ResourceFacts{
				Workload: &model.WorkloadResourceFacts{
					WorkloadUID: "gateway-a",
					Principal:   model.MustServiceAccountPrincipal("agentio-system", "gateway"),
				},
				GatewayOwner: "agentio-system/egress-a",
			})
		oldResources := append(append([]model.Resource(nil), resources...), oldGateway)
		newResources := append(append([]model.Resource(nil), resources...), newGateway)
		oldSnapshot, err := model.NewResourceSet(oldResources)
		if err != nil {
			b.Fatal(err)
		}
		newSnapshot, err := model.NewResourceSet(newResources)
		if err != nil {
			b.Fatal(err)
		}
		request := GenerationRequest{
			Scope: model.ClientScope{
				Class:       model.ClientDedicatedZTunnel,
				Principal:   model.MustServiceAccountPrincipal("demo", "default"),
				WorkloadUID: "uid-a",
				Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
			},
			TypeURL:      model.AddressType,
			Subscription: SubscriptionView{wildcard: true},
			Snapshot:     newSnapshot,
			Update: updateBetween(oldSnapshot, newSnapshot, []model.ResourceChange{{
				Key: newGateway.Key,
				Old: &oldGateway,
				New: &newGateway,
			}}),
		}
		if got := generateWDSIncremental(
			request,
			false,
		); len(got.Resources) != 1 ||
			got.Resources[0].XDSName != "gateway-a" {
			b.Fatalf("representative delta = %+v", got)
		}

		b.ReportAllocs()

		for b.Loop() {
			_ = generateWDSIncremental(request, false)
		}
	})
}

func BenchmarkWorkloadGeneratorIncremental(b *testing.B) {
	_, after, update, target := scaleWorkloadTransition(b, 10_000)
	for _, benchmark := range []struct {
		name  string
		scope model.ClientScope
	}{
		{
			name: "client=dedicated",
			scope: model.ClientScope{
				Class:       model.ClientDedicatedZTunnel,
				WorkloadUID: target.Facts.Workload.WorkloadUID,
				Source:      target.Facts.Workload.Source,
				Principal:   target.Facts.Workload.Principal,
			},
		},
		{
			name: "client=shared/local-workloads=100",
			scope: model.ClientScope{
				Class:    model.ClientSharedZTunnel,
				NodeName: "node-050",
			},
		},
	} {
		b.Run("resources=10000/"+benchmark.name, func(b *testing.B) {
			request := GenerationRequest{
				Scope:        benchmark.scope,
				TypeURL:      model.AddressType,
				Subscription: SubscriptionView{wildcard: true},
				Snapshot:     after,
				Update:       update,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				delta, err := (WorkloadGenerator{}).Generate(context.Background(), request)
				if err != nil || len(delta.Resources) != 1 {
					b.Fatalf("Generate() resources=%d err=%v", len(delta.Resources), err)
				}
			}
		})
	}
}

func BenchmarkWorkloadGeneratorFull(b *testing.B) {
	b.Run("resources=10000", func(b *testing.B) {
		const resourceCount = 10_000
		resources := make([]model.Resource, 0, resourceCount)
		for index := range resourceCount {
			name := fmt.Sprintf("cluster//Pod/demo/pod-%05d", index)
			resources = append(resources, addressResource(b, name, name))
		}
		snapshot, err := model.NewResourceSet(resources)
		if err != nil {
			b.Fatal(err)
		}
		request := GenerationRequest{
			Scope:        ztunnelScope(),
			Snapshot:     snapshot,
			TypeURL:      model.AddressType,
			Subscription: SubscriptionView{wildcard: true, sent: map[string]string{}},
			Full:         true,
		}

		b.ReportAllocs()
		b.ReportMetric(resourceCount, "resources/msg")
		b.ResetTimer()
		for b.Loop() {
			delta, err := (WorkloadGenerator{}).Generate(context.Background(), request)
			if err != nil || len(delta.Resources) != resourceCount {
				b.Fatalf("Generate() resources=%d err=%v", len(delta.Resources), err)
			}
		}
	})
}
