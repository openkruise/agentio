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
	"io"
	"log/slog"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// Keep inventories at production scale even when the response selects one name.
// These benchmarks isolate generation cost; TLS, flow control and concurrent
// WDS delivery are covered by bench/porter's controlplane suite.
func BenchmarkControlPlaneScale(b *testing.B) {
	for _, size := range []int{50000, 100000} {
		b.Run(fmt.Sprintf("inventory=%d", size), func(b *testing.B) {
			resources := make([]model.Resource, 0, size+1)
			names := make([]string, size/4)
			for i := range size {
				name := fmt.Sprintf("workload-%06d", i)
				alias := fmt.Sprintf("instance-%06d", i)
				resource := addressResource(b, name, name, alias, fmt.Sprintf("shared-%06d", i/2))
				if i < 500 {
					resource.Facts.Workload.ServiceKeys = []string{"demo/service"}
				}
				resources = append(resources, resource)
				if i < len(names) {
					names[i] = alias
				}
			}
			service, err := model.NewResource(
				model.ResourceKey{TypeURL: model.AddressType, Name: "demo/service"},
				"",
				mustAny(
					&workloadv1.Address{
						Type: &workloadv1.Address_Service{Service: &workloadv1.Service{Name: "service"}},
					},
				),
				[]string{
					"service-alias",
				},
				model.ResourceFacts{Service: &model.ServiceResourceFacts{ServiceKey: "demo/service"}},
			)
			if err != nil {
				b.Fatal(err)
			}
			resources = append(resources, service)
			snapshot, err := model.NewResourceSet(resources)
			if err != nil {
				b.Fatal(err)
			}
			for _, scenario := range []struct {
				name   string
				names  []string
				count  int
				direct bool
			}{
				{"ordinary-wds", nil, size + 1, false},
				{"initial-demand", names, len(names), true},
				{"unique-alias", names[:1], 1, true},
				{"shared-alias", []string{"shared-000000"}, 2, true},
				{"service-expansion", []string{"service-alias"}, 500, true},
			} {
				b.Run(scenario.name, func(b *testing.B) {
					typ := model.AddressType
					scope := ztunnelScope()
					view := SubscriptionView{wildcard: true}
					if scenario.direct {
						typ = model.WorkloadType
						scope = gatewayScope()
						view = SubscriptionView{names: scenario.names}
					}
					request := GenerationRequest{
						Scope:           scope,
						Snapshot:        snapshot,
						TypeURL:         typ,
						Subscription:    view,
						SubscribedNames: scenario.names,
						Full:            true,
					}
					b.ReportAllocs()
					for b.Loop() {
						delta, err := (WorkloadGenerator{}).Generate(b.Context(), request)
						if err != nil || len(delta.Resources) != scenario.count {
							b.Fatalf("resources=%d want=%d err=%v", len(delta.Resources), scenario.count, err)
						}
					}
				})
			}
		})
	}
}

func BenchmarkControlPlaneDemandChurn(b *testing.B) {
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	b.Cleanup(func() { slog.SetDefault(previous) })
	for _, size := range []int{50000, 100000} {
		b.Run(fmt.Sprintf("inventory=%d/subscriptions=10000", size), func(b *testing.B) {
			resources := make([]model.Resource, 0, size)
			names := make([]string, 10000)
			for i := range size {
				name := fmt.Sprintf("workload-%06d", i)
				alias := fmt.Sprintf("instance-%06d", i)
				resources = append(resources, addressResource(b, name, name, alias))
				if i < len(names) {
					names[i] = alias
				}
			}
			server := newTestServer(b, gatewayScope(), resources, nil)
			stream := discardDeltaStream{ctx: b.Context()}
			subscription := server.resources.Subscribe(b.Context())
			watches := map[string]*watchState{}
			if err := server.server.handleRequest(
				stream,
				server.scope,
				log,
				watches,
				subscription,
				nodeRequest(model.WorkloadType, names...),
			); err != nil {
				b.Fatal(err)
			}
			watch := watches[model.WorkloadType]
			oldName, newName := "instance-009999", "instance-010000"
			b.ReportAllocs()
			for b.Loop() {
				request := &discoveryv3.DeltaDiscoveryRequest{
					TypeUrl:                  model.WorkloadType,
					ResponseNonce:            watch.nonceSent,
					ResourceNamesSubscribe:   []string{newName},
					ResourceNamesUnsubscribe: []string{oldName},
				}
				if err := server.server.handleRequest(
					stream,
					server.scope,
					log,
					watches,
					subscription,
					request,
				); err != nil {
					b.Fatal(err)
				}
				oldName, newName = newName, oldName
			}
			if len(watch.names) != 10000 || len(watch.sent) != 10000 {
				b.Fatalf("subscription state drifted: names=%d sent=%d", len(watch.names), len(watch.sent))
			}
		})
	}
}
