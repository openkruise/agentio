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

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func BenchmarkDirectWorkloadSNIPolicy(b *testing.B) {
	for _, rules := range []int{0, 40, 160, 640} {
		policy := &extensionsv1.SniTrafficPolicy{}
		for index := range rules {
			policy.Rules = append(policy.Rules, &extensionsv1.SniRule{
				Match: &extensionsv1.SniMatch{
					Sni:   []string{fmt.Sprintf("api-%03d.example.com", index)},
					Ports: []uint32{443},
				},
				Action: extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH,
			})
		}
		extensions := []*workloadv1.Extension{{Name: "security-profile-reference",
			Config: mustAny(&extensionsv1.PolicyReference{
				TypeUrl: model.SecurityProfileType,
				Resources: []*extensionsv1.PolicyResourceReference{
					{Name: "namespaced/demo/profile", Uid: "profile-uid"},
				},
			})}}
		if rules > 0 {
			extensions = append(extensions, &workloadv1.Extension{Name: "sni-traffic-policy", Config: mustAny(policy)})
		}
		resources := make([]model.Resource, 0, 100)
		for index := range 100 {
			base := addressResource(b, fmt.Sprintf("uid-%03d", index), "pod")
			address := &workloadv1.Address{}
			if err := testResourceValue(base).UnmarshalTo(address); err != nil {
				b.Fatal(err)
			}
			address.GetWorkload().Extensions = extensions
			resource, err := model.NewResource(
				base.Key,
				base.XDSName,
				testResourceContents(mustAny(address)),
				base.Aliases,
				base.Facts,
			)
			if err != nil {
				b.Fatal(err)
			}
			resources = append(resources, resource)
		}
		before, err := model.NewResourceSet(resources)
		if err != nil {
			b.Fatal(err)
		}
		address := &workloadv1.Address{}
		if err := testResourceValue(resources[0]).UnmarshalTo(address); err != nil {
			b.Fatal(err)
		}
		if rules > 0 {
			policy.Rules[0].Action = extensionsv1.SniAction_SNI_ACTION_DENY
			address.GetWorkload().Extensions[1].Config = mustAny(policy)
		} else {
			address.GetWorkload().Node = "node-b"
		}
		resources[0], err = model.NewResource(
			resources[0].Key,
			resources[0].XDSName,
			testResourceContents(mustAny(address)),
			resources[0].Aliases,
			resources[0].Facts,
		)
		if err != nil {
			b.Fatal(err)
		}
		after, err := model.NewResourceSet(resources)
		if err != nil {
			b.Fatal(err)
		}
		for _, class := range []model.ClientClass{model.ClientEgressGateway, model.ClientAgentioEgress} {
			for _, mode := range []string{"cold", "update"} {
				b.Run(fmt.Sprintf("rules=%d/client=%s/%s", rules, class, mode), func(b *testing.B) {
					scope := gatewayScope()
					scope.Class = class
					request := GenerationRequest{
						Scope:        scope,
						TypeURL:      model.WorkloadType,
						Snapshot:     after,
						Subscription: SubscriptionView{wildcard: true},
						Full:         mode == "cold",
						Update:       updateBetween(before, after, before.Diff(after)),
					}
					if mode == "update" {
						initial, err := (WorkloadGenerator{}).Generate(b.Context(), GenerationRequest{
							Scope:        scope,
							TypeURL:      model.WorkloadType,
							Snapshot:     before,
							Subscription: SubscriptionView{wildcard: true},
							Full:         true,
						})
						if err != nil {
							b.Fatal(err)
						}
						request.Subscription.sent = make(map[string]string, len(initial.Resources))
						for _, resource := range initial.Resources {
							request.Subscription.sent[resource.XDSName] = resource.Hash
						}
					}
					b.ReportAllocs()
					var delta GeneratedDelta
					for b.Loop() {
						var err error
						delta, err = (WorkloadGenerator{}).Generate(b.Context(), request)
						if err != nil {
							b.Fatal(err)
						}
					}
					payloadBytes := 0
					for _, resource := range delta.Resources {
						payloadBytes += proto.Size(resource.Value)
					}
					b.ReportMetric(float64(payloadBytes), "payload-B/msg")
					b.ReportMetric(float64(len(delta.Resources)), "resources/msg")
				})
			}
		}
	}
}

func BenchmarkWorkloadGeneratorGatewayUpdate(b *testing.B) {
	b.Run("unrelated-resources=5000", func(b *testing.B) {
		const unrelatedCount = 5_000
		value := func(payload string) *anypb.Any {
			return mustAny(
				&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{Name: payload}}},
			)
		}
		resource := func(name, payload string, facts model.ResourceFacts) model.Resource {
			result, err := model.NewResource(
				model.ResourceKey{
					TypeURL: model.AddressType,
					Name:    name,
				},
				"",
				testResourceContents(value(payload)),
				nil,
				facts,
			)
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

		// Measure cached pushes separately from first materialization.
		if _, err := (WorkloadGenerator{}).Generate(context.Background(), request); err != nil {
			b.Fatal(err)
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

// Includes publication and the first consumer, then sharing across additional clients.
func BenchmarkWorkloadProjectionLifecycle(b *testing.B) {
	for _, rules := range []int{0, 40, 160, 640} {
		base := addressResource(b, "uid", "pod")
		address := &workloadv1.Address{}
		if err := testResourceValue(base).UnmarshalTo(address); err != nil {
			b.Fatal(err)
		}
		policy := &extensionsv1.SniTrafficPolicy{}
		for index := range rules {
			policy.Rules = append(policy.Rules, &extensionsv1.SniRule{
				Match:  &extensionsv1.SniMatch{Sni: []string{fmt.Sprintf("api-%03d.example.com", index)}},
				Action: extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH,
			})
		}
		if rules > 0 {
			address.GetWorkload().Extensions = []*workloadv1.Extension{
				{Name: "sni-traffic-policy", Config: mustAny(policy)},
			}
		}
		value := mustAny(address)
		for _, clients := range []int{1, 10, 100} {
			b.Run(fmt.Sprintf("rules=%d/clients=%d", rules, clients), func(b *testing.B) {
				scope := gatewayScope()
				scope.Class = model.ClientAgentioEgress
				b.ReportAllocs()
				for b.Loop() {
					resource, err := model.NewResource(
						base.Key,
						base.XDSName,
						testResourceContents(value),
						base.Aliases,
						base.Facts,
					)
					if err != nil {
						b.Fatal(err)
					}
					for client := range clients {
						scope.WorkloadUID = fmt.Sprintf("client-%d", client)
						if _, err := (WorkloadGenerator{}).projectResources(
							scope,
							[]model.Resource{resource},
							model.WorkloadType,
						); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}
