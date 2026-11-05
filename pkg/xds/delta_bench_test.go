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
	"io"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func BenchmarkDeltaPushScan(b *testing.B) {
	const resourceCount = 100_000
	value := &anypb.Any{TypeUrl: model.AddressType, Value: []byte("address")}
	resources := make([]model.Resource, 0, resourceCount)
	for i := range resourceCount {
		name := fmt.Sprintf("cluster//Pod/default/pod-%06d", i)
		resources = append(resources, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
			XDSName: name,
			Value:   value,
			Hash:    name,
			Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID: name,
				Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
				NodeName:    "node-a",
				Principal:   model.MustServiceAccountPrincipal("default", "default"),
			}},
		})
	}
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: model.MustServiceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	testServer := newTestServer(b, scope, resources, nil)
	stream := discardDeltaStream{ctx: context.Background()}

	b.Run("resources=100000/mode=incremental", func(b *testing.B) {
		key := resources[resourceCount/2].Key
		variants := [2]model.Resource{resources[resourceCount/2], resources[resourceCount/2]}
		variants[0].Hash += "-a"
		variants[1].Hash += "-b"
		base, err := model.NewResourceSet(resources)
		if err != nil {
			b.Fatal(err)
		}
		var snapshots [2]model.ResourceSet
		for variant := range variants {
			snapshot, changed, err := base.Apply([]model.ResourceChange{{Key: key, New: &variants[variant]}})
			if err != nil || !changed {
				b.Fatalf("build variant %d: changed=%v err=%v", variant, changed, err)
			}
			snapshots[variant] = snapshot
		}
		updates := [2]xdsstore.Update{
			updateBetween(snapshots[1], snapshots[0], []model.ResourceChange{{
				Key: key,
				Old: &variants[1],
				New: &variants[0],
			}}),
			updateBetween(snapshots[0], snapshots[1], []model.ResourceChange{{
				Key: key,
				Old: &variants[0],
				New: &variants[1],
			}}),
		}
		sent := make(map[string]string, len(resources))
		for _, resource := range resources {
			sent[resource.XDSName] = resource.Hash
		}
		watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: sent}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			update := updates[i%2]
			testServer.resources.snapshot = snapshots[i%2]
			if err := testServer.server.sendIncremental(
				stream,
				testServer.scope,
				log,
				model.AddressType,
				watch,
				update,
			); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("resources=100000/mode=full", func(b *testing.B) {
		sent := make(map[string]string, len(resources))
		for _, resource := range resources {
			sent[resource.XDSName] = resource.Hash
		}
		watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: sent}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := testServer.server.sendDiff(
				stream,
				testServer.scope,
				log,
				model.AddressType,
				watch,
				false,
			); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDeltaPushInitialState(b *testing.B) {
	b.Run("resources=5000", func(b *testing.B) {
		const resourceCount = 5_000
		resources := make([]model.Resource, 0, resourceCount)
		for index := range resourceCount {
			name := fmt.Sprintf("cluster//Pod/default/pod-%05d", index)
			resources = append(resources, addressResource(b, name, name))
		}
		scope := ztunnelScope()
		server := newTestServer(b, scope, resources, nil)
		stream := discardDeltaStream{ctx: context.Background()}

		b.ReportAllocs()
		for b.Loop() {
			watch := &watchState{
				wildcard: true,
				started:  true,
				names:    sets.New[string](),
				sent:     map[string]string{},
			}
			if err := server.server.sendDiff(stream, scope, log, model.AddressType, watch, true); err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(len(watch.sent)), "sent-hashes")
		}
	})
}

func BenchmarkDeltaPushIncrementalAllClients(b *testing.B) {
	b.Run("resources=100/clients=25/changed=100", func(b *testing.B) {
		const keyCount, clientCount = 100, 25
		value := &anypb.Any{TypeUrl: model.AddressType, Value: []byte("address")}
		variants := [2][]model.Resource{
			make([]model.Resource, 0, keyCount),
			make([]model.Resource, 0, keyCount),
		}
		changes := [2][]model.ResourceChange{
			make([]model.ResourceChange, 0, keyCount),
			make([]model.ResourceChange, 0, keyCount),
		}
		for index := range keyCount {
			name := fmt.Sprintf("cluster//Pod/default/pod-%03d", index)
			for variant := range variants {
				variants[variant] = append(variants[variant], model.Resource{
					Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
					XDSName: name,
					Value:   value,
					Hash:    fmt.Sprintf("%s-%d", name, variant),
					Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
						WorkloadUID: name,
						Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
						NodeName:    "node-a",
						Principal:   model.MustServiceAccountPrincipal("default", "default"),
					}},
				})
			}
			changes[0] = append(changes[0], model.ResourceChange{
				Key: variants[0][index].Key,
				Old: &variants[1][index],
				New: &variants[0][index],
			})
			changes[1] = append(changes[1], model.ResourceChange{
				Key: variants[0][index].Key,
				Old: &variants[0][index],
				New: &variants[1][index],
			})
		}
		var snapshots [2]model.ResourceSet
		for variant := range variants {
			var err error
			snapshots[variant], err = model.NewResourceSet(variants[variant])
			if err != nil {
				b.Fatal(err)
			}
		}
		updates := [2]xdsstore.Update{
			updateBetween(snapshots[1], snapshots[0], changes[0]),
			updateBetween(snapshots[0], snapshots[1], changes[1]),
		}
		scope := model.ClientScope{
			Class:     model.ClientSharedZTunnel,
			Principal: model.MustServiceAccountPrincipal("demo", "ztunnel"),
			NodeName:  "node-a",
		}
		testServer := newTestServer(b, scope, variants[0], nil)
		stream := discardDeltaStream{ctx: context.Background()}
		watches := make([]*watchState, clientCount)
		for client := range watches {
			sent := make(map[string]string, keyCount)
			for _, resource := range variants[0] {
				sent[resource.XDSName] = resource.Hash
			}
			watches[client] = &watchState{wildcard: true, started: true, names: sets.New[string](), sent: sent}
		}

		b.ReportAllocs()

		for iteration := 0; b.Loop(); iteration++ {
			update := updates[(iteration+1)%2]
			testServer.resources.snapshot = snapshots[(iteration+1)%2]
			for _, watch := range watches {
				if err := testServer.server.sendIncremental(
					stream,
					scope,
					log,
					model.AddressType,
					watch,
					update,
				); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

func BenchmarkDeltaPushPublicationFanout(b *testing.B) {
	resources, variants := fanoutBenchmarkResources(b)
	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("resources=10000/client=dedicated/affected=one/clients=%d", clientCount), func(b *testing.B) {
			scopes := make([]model.ClientScope, clientCount)
			for client := range scopes {
				index := fanoutTargetIndex
				if client > 0 {
					index = client - 1
					if index >= fanoutTargetIndex {
						index++
					}
				}
				scopes[client] = model.ClientScope{
					Class:       model.ClientDedicatedZTunnel,
					WorkloadUID: fmt.Sprintf("workload-%06d", index),
					Source:      model.SourceRef{Registry: "kubernetes/test", Key: fmt.Sprintf("workload-%06d", index)},
					Principal:   model.MustServiceAccountPrincipal("demo", "default"),
				}
			}
			benchmarkIncrementalClientFanout(b, resources, variants, scopes)
		})
		b.Run(fmt.Sprintf("resources=10000/client=shared/affected=all/clients=%d", clientCount), func(b *testing.B) {
			scopes := make([]model.ClientScope, clientCount)
			for client := range scopes {
				scopes[client] = model.ClientScope{
					Class:    model.ClientSharedZTunnel,
					NodeName: "node-050",
				}
			}
			benchmarkIncrementalClientFanout(b, resources, variants, scopes)
		})
	}
}

func BenchmarkDeltaPushGatewayUpdate(b *testing.B) {
	resources, updates, snapshots := relationshipFanoutScenario(b)
	server := newTestServer(b, ztunnelScope(), resources, nil)
	stream := &countingDeltaStream{ctx: context.Background()}
	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("workloads=10000/gateways=100/client=shared/affected=one-node/clients=%d", clientCount), func(b *testing.B) {
			scopes, watches := distributedSharedClients(clientCount)
			expected := clientsOnNode(scopes, "node-050")
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				server.resources.snapshot = snapshots[iteration&1]
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendIncremental(stream, scope, log, model.AddressType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
		b.Run(fmt.Sprintf("workloads=10000/gateways=100/client=dedicated/clients=%d", clientCount), func(b *testing.B) {
			scopes := distributedDedicatedClients(clientCount)
			watches := wildcardWatches(clientCount)
			expected := 0
			for client := range scopes {
				if client%scenarioNodeCount == 50 {
					expected++
				}
			}
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				server.resources.snapshot = snapshots[iteration&1]
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendIncremental(stream, scope, log, model.AddressType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
	}
}

func BenchmarkDeltaPushAuthorizationUpdate(b *testing.B) {
	resources, updates, snapshots := authorizationFanoutScenario(b)
	server := newTestServer(b, ztunnelScope(), resources, nil)
	stream := &countingDeltaStream{ctx: context.Background()}
	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("workloads=10000/policies=10000/client=shared/affected=one-node/clients=%d", clientCount), func(b *testing.B) {
			scopes, watches := distributedSharedClients(clientCount)
			expected := clientsOnNode(scopes, "node-050")
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				server.resources.snapshot = snapshots[iteration&1]
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendIncremental(stream, scope, log, model.WorkloadAuthorizationType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
		b.Run(fmt.Sprintf("workloads=10000/policies=10000/client=dedicated/affected=one/clients=%d", clientCount), func(b *testing.B) {
			scopes := distributedDedicatedClients(clientCount)
			watches := wildcardWatches(clientCount)
			expected := 0
			if clientCount > 50 {
				expected = 1
			}
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				server.resources.snapshot = snapshots[iteration&1]
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendIncremental(stream, scope, log, model.WorkloadAuthorizationType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
	}
}

func BenchmarkDeltaPushMixedClients(b *testing.B) {
	resources, variants := fanoutBenchmarkResources(b)
	initial, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	updated, changed, err := initial.Apply([]model.ResourceChange{{Key: variants[1].Key, New: &variants[1]}})
	if err != nil || !changed {
		b.Fatalf("build mixed-client transition: changed=%v err=%v", changed, err)
	}
	snapshots := [2]model.ResourceSet{initial, updated}
	updates := [2]xdsstore.Update{
		updateBetween(updated, initial, []model.ResourceChange{{Key: variants[0].Key, Old: &variants[1], New: &variants[0]}}),
		updateBetween(initial, updated, []model.ResourceChange{{Key: variants[1].Key, Old: &variants[0], New: &variants[1]}}),
	}
	server := newTestServer(b, ztunnelScope(), resources, nil)
	stream := &countingDeltaStream{ctx: context.Background()}
	for _, clientCount := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("resources=10000/changed=1/clients=%d", clientCount), func(b *testing.B) {
			scopes := mixedClientScopes(clientCount)
			watches := wildcardWatches(clientCount)
			expected := affectedMixedClients(scopes, variants[0])
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "clients/op")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				server.resources.snapshot = snapshots[iteration&1]
				stream.responses = 0
				stream.resources = 0
				for client, scope := range scopes {
					if err := server.server.sendIncremental(stream, scope, log, model.AddressType, watches[client], updates[iteration&1]); err != nil {
						b.Fatal(err)
					}
				}
				if stream.responses != expected || stream.resources != expected {
					b.Fatalf("responses=%d resources=%d, want %d affected clients", stream.responses, stream.resources, expected)
				}
			}
		})
	}
}

func BenchmarkDeltaPushIncrementalBatch(b *testing.B) {
	resources, before, _, changes := incrementalBatchScenario(b, 1_000)
	server := newTestServer(b, ztunnelScope(), resources, nil)
	stream := &countingDeltaStream{ctx: context.Background()}
	for _, changedCount := range []int{1, 100, 1_000} {
		for _, clientCount := range []int{1_000, 10_000} {
			if changedCount == 1_000 && clientCount == 10_000 {
				continue
			}
			b.Run(fmt.Sprintf("resources=10000/changed=%d/clients=%d", changedCount, clientCount), func(b *testing.B) {
				scopes, watches := distributedSharedClients(clientCount)
				after, _, err := before.Apply(changes[:changedCount])
				if err != nil {
					b.Fatal(err)
				}
				forward := updateBetween(before, after, changes[:changedCount])
				reverseChanges := make([]model.ResourceChange, changedCount)
				for index, change := range changes[:changedCount] {
					reverseChanges[index] = model.ResourceChange{Key: change.Key, Old: change.New, New: change.Old}
				}
				reverse := updateBetween(after, before, reverseChanges)
				updates := [2]xdsstore.Update{forward, reverse}
				snapshots := [2]model.ResourceSet{after, before}
				expected := changedCount * clientCount / scenarioNodeCount
				b.ReportAllocs()
				b.ReportMetric(float64(clientCount), "clients/op")
				b.ReportMetric(float64(changedCount), "changed-keys/op")
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					server.resources.snapshot = snapshots[iteration&1]
					stream.responses = 0
					stream.resources = 0
					for client, scope := range scopes {
						if err := server.server.sendIncremental(stream, scope, log, model.AddressType, watches[client], updates[iteration&1]); err != nil {
							b.Fatal(err)
						}
					}
					if stream.resources != expected {
						b.Fatalf("resources=%d, want %d", stream.resources, expected)
					}
				}
			})
		}
	}
}

type discardDeltaStream struct{ ctx context.Context }

func (d discardDeltaStream) Send(*discoveryv3.DeltaDiscoveryResponse) error { return nil }
func (d discardDeltaStream) Recv() (*discoveryv3.DeltaDiscoveryRequest, error) {
	return nil, io.EOF
}
func (d discardDeltaStream) Context() context.Context   { return d.ctx }
func (discardDeltaStream) SetHeader(metadata.MD) error  { return nil }
func (discardDeltaStream) SendHeader(metadata.MD) error { return nil }
func (discardDeltaStream) SetTrailer(metadata.MD)       {}
func (discardDeltaStream) SendMsg(any) error            { return nil }
func (discardDeltaStream) RecvMsg(any) error            { return io.EOF }

const (
	scenarioResourceCount = 10_000
	scenarioNodeCount     = 100
)

type countingDeltaStream struct {
	ctx       context.Context
	responses int
	resources int
}

func (s *countingDeltaStream) Send(response *discoveryv3.DeltaDiscoveryResponse) error {
	s.responses++
	s.resources += len(response.GetResources()) + len(response.GetRemovedResources())
	return nil
}

func (*countingDeltaStream) Recv() (*discoveryv3.DeltaDiscoveryRequest, error) {
	return nil, io.EOF
}

func (s *countingDeltaStream) Context() context.Context   { return s.ctx }
func (*countingDeltaStream) SetHeader(metadata.MD) error  { return nil }
func (*countingDeltaStream) SendHeader(metadata.MD) error { return nil }
func (*countingDeltaStream) SetTrailer(metadata.MD)       {}
func (*countingDeltaStream) SendMsg(any) error            { return nil }
func (*countingDeltaStream) RecvMsg(any) error            { return io.EOF }

const fanoutResourceCount = 10_000
const fanoutTargetIndex = 5_050

func benchmarkIncrementalClientFanout(
	b *testing.B,
	resources []model.Resource,
	variants [2]model.Resource,
	scopes []model.ClientScope,
) {
	b.Helper()
	initial, err := model.NewResourceSet(resources)
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := xdsstore.New(initial)
	subscription := store.Subscribe(ctx, model.ClientScope{})
	subscription.Watch(model.AddressType)
	updates := subscription.Updates()
	testServer := newTestServer(b, ztunnelScope(), resources, nil)
	testServer.server.resources = store
	stream := discardDeltaStream{ctx: context.Background()}
	watches := make([]*watchState, len(scopes))
	for client := range watches {
		watches[client] = &watchState{
			wildcard: true,
			started:  true,
			names:    sets.New[string](),
			sent:     make(map[string]string),
		}
	}

	next := 1
	b.ReportAllocs()
	b.ReportMetric(float64(len(scopes)), "clients/op")
	b.ResetTimer()
	for range b.N {
		resource := variants[next]
		if _, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}}); err != nil {
			b.Fatal(err)
		}
		update := <-updates
		for client, scope := range scopes {
			if err := testServer.server.sendIncremental(stream, scope, log, model.AddressType, watches[client], update); err != nil {
				b.Fatal(err)
			}
		}
		next ^= 1
	}
}

func fanoutBenchmarkResources(t testing.TB) ([]model.Resource, [2]model.Resource) {
	t.Helper()
	resources := make([]model.Resource, 0, fanoutResourceCount)
	var variants [2]model.Resource
	for index := range fanoutResourceCount {
		name := fmt.Sprintf("workload-%06d", index)
		facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
			WorkloadUID: name,
			Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
			NodeName:    fmt.Sprintf("node-%03d", index%100),
			Principal:   model.MustServiceAccountPrincipal("demo", "default"),
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
		if index == fanoutTargetIndex {
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

func relationshipFanoutScenario(t testing.TB) ([]model.Resource, [2]xdsstore.Update, [2]model.ResourceSet) {
	t.Helper()
	resources := make([]model.Resource, 0, scenarioResourceCount+scenarioNodeCount)
	value := &anypb.Any{TypeUrl: model.AddressType, Value: []byte("address")}
	for index := range scenarioResourceCount {
		node := fmt.Sprintf("node-%03d", index%scenarioNodeCount)
		name := fmt.Sprintf("workload-%06d", index)
		resources = append(resources, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
			XDSName: name,
			Value:   value,
			Hash:    name,
			Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID: name,
				Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
				NodeName:    node,
				Principal:   model.MustServiceAccountPrincipal("demo", "default"),
				GatewayReferences: []string{
					"gateway/" + node,
				},
			}},
		})
	}
	var variants [2]model.Resource
	for index := range scenarioNodeCount {
		node := fmt.Sprintf("node-%03d", index)
		name := "gateway-" + node
		resource := model.Resource{
			Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
			XDSName: name,
			Value:   value,
			Hash:    name,
			Facts: model.ResourceFacts{
				Workload: &model.WorkloadResourceFacts{
					WorkloadUID: name,
					Source:      model.SourceRef{Registry: "kubernetes/test", Key: name},
					Principal:   model.MustServiceAccountPrincipal("agentio-system", "gateway"),
				},
				GatewayOwner: "gateway/" + node,
			},
		}
		resources = append(resources, resource)
		if index == 50 {
			variants[0] = resource
			variants[1] = resource
			variants[0].Hash += "-old"
			variants[1].Hash += "-new"
			resources[len(resources)-1] = variants[0]
		}
	}
	before, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	after, changed, err := before.Apply([]model.ResourceChange{{Key: variants[1].Key, New: &variants[1]}})
	if err != nil || !changed {
		t.Fatalf("build relationship transition: changed=%v err=%v", changed, err)
	}
	return resources, [2]xdsstore.Update{
		updateBetween(
			before,
			after,
			[]model.ResourceChange{{Key: variants[0].Key, Old: &variants[0], New: &variants[1]}},
		),
		updateBetween(
			after,
			before,
			[]model.ResourceChange{{Key: variants[0].Key, Old: &variants[1], New: &variants[0]}},
		),
	}, [2]model.ResourceSet{after, before}
}

func authorizationFanoutScenario(t testing.TB) ([]model.Resource, [2]xdsstore.Update, [2]model.ResourceSet) {
	t.Helper()
	const targetPolicy = "demo/policy-target"
	resources := make([]model.Resource, 0, scenarioResourceCount*2)
	for index := range scenarioResourceCount {
		node := fmt.Sprintf("node-%03d", index%scenarioNodeCount)
		name := fmt.Sprintf("workload-%06d", index)
		policies := []string(nil)
		if index == 50 {
			policies = []string{targetPolicy}
		}
		facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
			WorkloadUID:       name,
			Source:            model.SourceRef{Registry: "kubernetes/test", Key: name},
			NodeName:          node,
			Principal:         model.MustServiceAccountPrincipal("demo", "default"),
			AuthorizationRefs: policies,
		}}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name}, "",
			mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
				Uid:                   name,
				Namespace:             "demo",
				Node:                  node,
				AuthorizationPolicies: policies,
			}}}), nil,
			facts,
		)
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
	}
	value := &anypb.Any{TypeUrl: model.WorkloadAuthorizationType, Value: []byte("authorization")}
	var variants [2]model.Resource
	for index := range scenarioResourceCount {
		name := fmt.Sprintf("demo/policy-%06d", index)
		if index == 5_000 {
			name = targetPolicy
		}
		resource := model.Resource{
			Key:     model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name},
			XDSName: name,
			Value:   value,
			Hash:    name + "-old",
			Facts: model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{
				Scope: model.AuthorizationScopeWorkload,
			}},
		}
		resources = append(resources, resource)
		if name == targetPolicy {
			variants[0] = resource
			variants[1] = resource
			variants[1].Hash = name + "-new"
		}
	}
	before, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	after, changed, err := before.Apply([]model.ResourceChange{{Key: variants[1].Key, New: &variants[1]}})
	if err != nil || !changed {
		t.Fatalf("build Authorization transition: changed=%v err=%v", changed, err)
	}
	return resources, [2]xdsstore.Update{
		updateBetween(
			before,
			after,
			[]model.ResourceChange{{Key: variants[0].Key, Old: &variants[0], New: &variants[1]}},
		),
		updateBetween(
			after,
			before,
			[]model.ResourceChange{{Key: variants[0].Key, Old: &variants[1], New: &variants[0]}},
		),
	}, [2]model.ResourceSet{after, before}
}

func incrementalBatchScenario(t testing.TB, changedCount int) (
	[]model.Resource, model.ResourceSet, model.ResourceSet, []model.ResourceChange,
) {
	t.Helper()
	resources, _ := fanoutBenchmarkResources(t)
	before, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	changes := make([]model.ResourceChange, 0, changedCount)
	for index := range changedCount {
		old := resources[index]
		updated := old
		updated.Hash += "-new"
		changes = append(changes, model.ResourceChange{Key: old.Key, Old: &old, New: &updated})
	}
	after, changed, err := before.Apply(changes)
	if err != nil || !changed {
		t.Fatalf("build incremental batch: changed=%v err=%v", changed, err)
	}
	return resources, before, after, changes
}

func distributedSharedClients(clientCount int) ([]model.ClientScope, []*watchState) {
	scopes := make([]model.ClientScope, clientCount)
	for client := range scopes {
		scopes[client] = model.ClientScope{
			Class:    model.ClientSharedZTunnel,
			NodeName: fmt.Sprintf("node-%03d", client%scenarioNodeCount),
		}
	}
	return scopes, wildcardWatches(clientCount)
}

func distributedDedicatedClients(clientCount int) []model.ClientScope {
	scopes := make([]model.ClientScope, clientCount)
	for client := range scopes {
		scopes[client] = model.ClientScope{
			Class:       model.ClientDedicatedZTunnel,
			Principal:   model.MustServiceAccountPrincipal("demo", "default"),
			WorkloadUID: fmt.Sprintf("workload-%06d", client),
			Source:      model.SourceRef{Registry: "kubernetes/test", Key: fmt.Sprintf("workload-%06d", client)},
		}
	}
	return scopes
}

func mixedClientScopes(clientCount int) []model.ClientScope {
	scopes := make([]model.ClientScope, clientCount)
	for client := range scopes {
		if client%2 == 0 {
			scopes[client] = model.ClientScope{
				Class:    model.ClientSharedZTunnel,
				NodeName: fmt.Sprintf("node-%03d", (client/2)%scenarioNodeCount),
			}
			continue
		}
		index := client / 2
		if client == 1 {
			index = fanoutTargetIndex
		} else if index == fanoutTargetIndex {
			index++
		}
		scopes[client] = model.ClientScope{
			Class:       model.ClientDedicatedZTunnel,
			Principal:   model.MustServiceAccountPrincipal("demo", "default"),
			WorkloadUID: fmt.Sprintf("workload-%06d", index),
			Source:      model.SourceRef{Registry: "kubernetes/test", Key: fmt.Sprintf("workload-%06d", index)},
		}
	}
	return scopes
}

func wildcardWatches(clientCount int) []*watchState {
	watches := make([]*watchState, clientCount)
	for client := range watches {
		watches[client] = &watchState{
			wildcard: true,
			started:  true,
			names:    sets.New[string](),
			sent:     make(map[string]string),
		}
	}
	return watches
}

func clientsOnNode(scopes []model.ClientScope, node string) int {
	result := 0
	for _, scope := range scopes {
		if scope.Class == model.ClientSharedZTunnel && scope.NodeName == node {
			result++
		}
	}
	return result
}

func affectedMixedClients(scopes []model.ClientScope, resource model.Resource) int {
	result := 0
	for _, scope := range scopes {
		if workloadMatchesScope(scope, resource) {
			result++
		}
	}
	return result
}
