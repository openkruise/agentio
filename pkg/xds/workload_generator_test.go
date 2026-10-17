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
	"runtime"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/util/sets"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestWildcardFullAddressGenerationCollapsesWireNamesDeterministically(t *testing.T) {
	resources := []model.Resource{
		addressResourceWithWireName(t, "canonical-a", "shared-wire-name"),
		addressResourceWithWireName(t, "canonical-b", "shared-wire-name"),
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        ztunnelScope(),
		Snapshot:     snapshot,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true, sent: map[string]string{}},
		Full:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 || delta.Resources[0].Key.Name != "canonical-b" ||
		delta.Resources[0].XDSName != "shared-wire-name" {
		t.Fatalf("generated resources = %#v, want canonical-b under the shared wire name", delta.Resources)
	}
}

func TestWildcardFullAddressGenerationHonorsInitialVersions(t *testing.T) {
	resource := addressResource(t, "cluster//Pod/demo/pod-a", "pod-a")
	snapshot, err := model.NewResourceSet([]model.Resource{resource})
	if err != nil {
		t.Fatal(err)
	}

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:    ztunnelScope(),
		Snapshot: snapshot,
		TypeURL:  model.AddressType,
		Subscription: SubscriptionView{
			wildcard: true,
			sent:     map[string]string{resource.XDSName: resource.Hash},
		},
		Full: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("generated delta = resources:%v removed:%v, want no change", delta.Resources, delta.Removed)
	}
}

func TestWildcardFullAddressGenerationAllocationBudget(t *testing.T) {
	const resourceCount = 1_000
	resources := make([]model.Resource, 0, resourceCount)
	for index := range resourceCount {
		name := fmt.Sprintf("cluster//Pod/demo/pod-%04d", index)
		resources = append(resources, addressResource(t, name, name))
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	request := GenerationRequest{
		Scope:        ztunnelScope(),
		Snapshot:     snapshot,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true, sent: map[string]string{}},
		Full:         true,
	}

	var delta GeneratedDelta
	var generationErr error
	allocations := testing.AllocsPerRun(3, func() {
		delta, generationErr = (WorkloadGenerator{}).Generate(context.Background(), request)
	})
	if generationErr != nil {
		t.Fatal(generationErr)
	}
	if len(delta.Resources) != resourceCount {
		t.Fatalf("generated resources = %d, want %d", len(delta.Resources), resourceCount)
	}
	if allocations > 200 {
		t.Fatalf("allocations per full generation = %.0f, want at most 200", allocations)
	}

	const runs = 10
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		delta, generationErr = (WorkloadGenerator{}).Generate(context.Background(), request)
		if generationErr != nil {
			t.Fatal(generationErr)
		}
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if bytesPerRun := (after.TotalAlloc - before.TotalAlloc) / runs; bytesPerRun > 600<<10 {
		t.Fatalf("full generation allocated %d bytes/run, want at most %d", bytesPerRun, 600<<10)
	}
}

func addressResourceWithWireName(t testing.TB, keyName, wireName string) model.Resource {
	t.Helper()
	base := addressResource(t, keyName, keyName)
	resource, err := model.NewResource(base.Key, wireName, base.Value, base.Aliases, base.Facts)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func TestWorkloadGeneratorProjectsDirectResourceFromCanonicalAddress(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal model.Principal
		policy    string
	}{
		{name: "authenticated workload", principal: serviceAccountPrincipal("demo", "default"), policy: "demo/auth"},
		{name: "discovery-only workload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address := selectionWorkload(t, "uid-a", "demo", "node-a", "", tc.policy)
			facts := address.Facts
			workloadFacts := *facts.Workload
			workloadFacts.Principal = tc.principal
			facts.Workload = &workloadFacts
			var err error
			address, err = model.NewResource(address.Key, address.XDSName, address.Value, address.Aliases, facts)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := selectionSnapshot(t, []model.Resource{address})
			if got := len(snapshot.List(model.WorkloadType)); got != 0 {
				t.Fatalf("retained Workload resources = %d, want 0", got)
			}
			originalValue := proto.Clone(address.Value)
			expected := &workloadv1.Address{}
			if err := address.Value.UnmarshalTo(expected); err != nil {
				t.Fatal(err)
			}
			delta, err := (WorkloadGenerator{}).Generate(t.Context(), GenerationRequest{
				Scope:        gatewayScope(),
				TypeURL:      model.WorkloadType,
				Subscription: SubscriptionView{wildcard: true},
				Snapshot:     snapshot,
				Full:         true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(delta.Resources) != 1 || delta.Resources[0].Key.TypeURL != model.WorkloadType || delta.Resources[0].XDSName != "uid-a" {
				t.Fatalf("projected resources = %+v", delta.Resources)
			}
			workload := &workloadv1.Workload{}
			if err := delta.Resources[0].Value.UnmarshalTo(workload); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(workload, expected.GetWorkload()) {
				t.Fatalf("projected Workload = %v, want %v", workload, expected.GetWorkload())
			}
			if !proto.Equal(address.Value, originalValue) {
				t.Fatal("projection mutated the canonical Address")
			}
		})
	}
}

func TestWildcardDirectWorkloadFullRegenerationOmitsUnchangedResources(t *testing.T) {
	facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
		WorkloadUID: "uid-a",
		NodeName:    "node-a",
		Principal:   serviceAccountPrincipal("demo", "default"),
	}}
	// Two map entries exercise deterministic marshaling of the projected value.
	address, err := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: "uid-a"}, "",
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
			Uid:       "uid-a",
			Namespace: "demo",
			Node:      "node-a",
			Services: map[string]*workloadv1.PortList{
				"demo/svc-a": {Ports: []*workloadv1.Port{{ServicePort: 80, TargetPort: 8080}}},
				"demo/svc-b": {Ports: []*workloadv1.Port{{ServicePort: 81, TargetPort: 8081}}},
			},
		}}}), nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := selectionSnapshot(t, []model.Resource{address})
	request := GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientEgressGateway},
		TypeURL:      model.WorkloadType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     snapshot,
		Full:         true,
	}

	first, err := (WorkloadGenerator{}).Generate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Resources) != 1 {
		t.Fatalf("initial full push resources = %v, want one", selectedNames(first.Resources))
	}
	if first.elideSentState {
		t.Fatal("full push for direct Workloads dropped sent state")
	}

	sent := make(map[string]string, len(first.Resources))
	for _, resource := range first.Resources {
		sent[resource.XDSName] = resource.Hash
	}
	request.Subscription = SubscriptionView{wildcard: true, sent: sent}
	// Map-field marshaling order is randomized per attempt; repeat to catch a
	// nondeterministic projection hash.
	for attempt := 0; attempt < 20; attempt++ {
		second, err := (WorkloadGenerator{}).Generate(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if len(second.Resources) != 0 || len(second.Removed) != 0 {
			t.Fatalf("unchanged full regeneration resent resources=%v removed=%v",
				selectedNames(second.Resources), second.Removed)
		}
	}
}

func TestWildcardDirectWorkloadIncrementalPushKeepsSentState(t *testing.T) {
	before := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	after := selectionWorkload(t, "uid-a", "demo", "node-b", "", "")
	oldSnapshot := selectionSnapshot(t, []model.Resource{before})
	newSnapshot := selectionSnapshot(t, []model.Resource{after})
	update := updateBetween(oldSnapshot, newSnapshot, oldSnapshot.Diff(newSnapshot))

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientEgressGateway},
		TypeURL:      model.WorkloadType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     newSnapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 {
		t.Fatalf("incremental push resources = %v, want the changed workload", selectedNames(delta.Resources))
	}
	if delta.elideSentState {
		t.Fatal("incremental push for direct Workloads dropped sent state")
	}
}

func TestWildcardDirectWorkloadIgnoresAddressServiceRemoval(t *testing.T) {
	workload := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	service := selectionService(t, "demo/svc-a")
	oldSnapshot := selectionSnapshot(t, []model.Resource{workload, service})
	newSnapshot := selectionSnapshot(t, []model.Resource{workload})
	update := updateBetween(oldSnapshot, newSnapshot, oldSnapshot.Diff(newSnapshot))

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:   gatewayScope(),
		TypeURL: model.WorkloadType,
		Subscription: initializedSubscription(
			t,
			WorkloadGenerator{},
			gatewayScope(),
			model.WorkloadType,
			oldSnapshot,
			SubscriptionView{wildcard: true},
		),
		Snapshot: newSnapshot,
		Update:   update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("service-only Address change produced direct Workload delta: resources=%v removed=%v",
			selectedNames(delta.Resources), delta.Removed)
	}
}

func TestDedicatedZTunnelReceivesOnlyWorkloadScope(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "demo/selector-a"),
		selectionWorkload(t, "uid-b", "other", "node-b", "svc-b", "other/selector-b"),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
		selectionService(t, "other/svc-b", "/10.96.0.2"),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   serviceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, nil)
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a"}) {
		t.Fatalf("selected resources = %v, want own workload and service", names)
	}
}

func TestWorkloadReferencedGatewaySelection(t *testing.T) {
	own := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""), "agentio-system/egress-a")
	other := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-b", "other", "node-b", "svc-b", ""), "other/egress-b")
	gatewayAWorkload := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""), "agentio-system/egress-a")
	gatewayAService := selectionOwnedByGateway(t,
		selectionService(t, "agentio-system/egress-a.agentio-system.svc.cluster.local"), "agentio-system/egress-a")
	gatewayBWorkload := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-b", "other", "gateway-node", "", ""), "other/egress-b")
	gatewayBService := selectionOwnedByGateway(t,
		selectionService(t, "other/egress-b.other.svc.cluster.local"), "other/egress-b")
	snapshot := selectionSnapshot(t, []model.Resource{
		own, other, selectionService(t, "demo/svc-a"), selectionService(t, "other/svc-b"),
		gatewayAWorkload, gatewayAService, gatewayBWorkload, gatewayBService,
		selectionWorkload(t, "unrelated", "unrelated", "node-z", "", ""),
	})
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   serviceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, nil)
	want := []string{"agentio-system/egress-a.agentio-system.svc.cluster.local", "demo/svc-a", "gateway-a", "uid-a"}
	if names := selectedNames(got); !slices.Equal(names, want) {
		t.Fatalf("wildcard selected resources = %v, want %v", names, want)
	}

	got = selectWorkloadResources(scope, snapshot, model.AddressType, []string{"uid-a"})
	want = []string{"agentio-system/egress-a.agentio-system.svc.cluster.local", "gateway-a", "uid-a"}
	if names := selectedNames(got); !slices.Equal(names, want) {
		t.Fatalf("named selected resources = %v, want %v", names, want)
	}
}

func TestNodeReferencedGatewaySelection(t *testing.T) {
	localA := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "", ""), "agentio-system/egress-a")
	localB := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-b", "demo", "node-a", "", ""), "agentio-system/egress-b")
	remote := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-c", "other", "node-b", "", ""), "other/egress-c")
	resources := []model.Resource{localA, localB, remote}
	for _, gateway := range []struct{ uid, key string }{
		{uid: "gateway-a", key: "agentio-system/egress-a"},
		{uid: "gateway-b", key: "agentio-system/egress-b"},
		{uid: "gateway-c", key: "other/egress-c"},
	} {
		resources = append(resources, selectionOwnedByGateway(t,
			selectionWorkload(t, gateway.uid, "agentio-system", "gateway-node", "", ""), gateway.key))
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"}
	if names := selectedNames(selectWorkloadResources(scope, snapshot, model.AddressType, nil)); !slices.Equal(names, []string{"gateway-a", "gateway-b", "uid-a", "uid-b"}) {
		t.Fatalf("node selected resources = %v", names)
	}
}

func TestNamedWorkloadAlwaysIncludesReferencedGateways(t *testing.T) {
	own := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "", ""), "agentio-system/egress-a")
	gateway := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""), "agentio-system/egress-a")
	snapshot := selectionSnapshot(t, []model.Resource{own, gateway})
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   serviceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}
	if names := selectedNames(
		selectWorkloadResources(scope, snapshot, model.AddressType, []string{"uid-a"}),
	); !slices.Equal(
		names,
		[]string{"gateway-a", "uid-a"},
	) {
		t.Fatalf("named selection = %v", names)
	}
}

func TestNamedReferencedGatewayIncremental(t *testing.T) {
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   serviceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}
	plain := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	own := selectionWithGatewayReference(t, plain, "agentio-system/egress-a")
	oldGateway := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""), "agentio-system/egress-a")
	newGateway, err := model.NewResource(oldGateway.Key, oldGateway.XDSName, oldGateway.Value,
		[]string{"revision/two"}, oldGateway.Facts)
	if err != nil {
		t.Fatal(err)
	}
	oldSnapshot := selectionSnapshot(t, []model.Resource{own, oldGateway})
	newSnapshot := selectionSnapshot(t, []model.Resource{own, newGateway})
	watch := &watchState{
		names:   sets.New("uid-a"),
		started: true,
		sent:    map[string]string{"uid-a": own.Hash, "gateway-a": oldGateway.Hash},
	}
	update := updateBetween(oldSnapshot, newSnapshot, oldSnapshot.Diff(newSnapshot))
	view := newIncrementalSubscriptionView(watch, model.AddressType, update)
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.AddressType,
		Subscription: view,
		Snapshot:     newSnapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"gateway-a"}) || len(delta.Removed) != 0 {
		t.Fatalf("gateway payload delta resources=%v removed=%v", names, delta.Removed)
	}

	withoutReference := selectionSnapshot(t, []model.Resource{plain, newGateway})
	watch.sent = map[string]string{"uid-a": own.Hash, "gateway-a": newGateway.Hash}
	update = updateBetween(newSnapshot, withoutReference, newSnapshot.Diff(withoutReference))
	view = newIncrementalSubscriptionView(watch, model.AddressType, update)
	delta, err = (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.AddressType,
		Subscription: view,
		Snapshot:     withoutReference,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"uid-a"}) ||
		!slices.Equal(delta.Removed, []string{"gateway-a"}) {
		t.Fatalf("reference removal delta resources=%v removed=%v", names, delta.Removed)
	}
}

func TestSharedZTunnelReceivesNodeWorkloads(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "other", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-c", "other", "node-b", "svc-b", ""),
		selectionService(t, "demo/svc-a"),
		selectionService(t, "other/svc-b"),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("agentio-system", "ztunnel"),
		NodeName:  "node-a",
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, nil)
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a", "uid-b"}) {
		t.Fatalf("selected resources = %v, want node-local workloads and their service", names)
	}
}

func TestNodeNamedSubscriptionAddsLocalAndExplicitRemoteWorkloads(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-a", "svc-b", ""),
		selectionWorkload(t, "uid-c", "demo", "node-b", "svc-a", ""),
		selectionWorkload(t, "uid-d", "demo", "node-b", "svc-c", ""),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
		selectionService(t, "demo/svc-b", "/10.96.0.2"),
		selectionService(t, "demo/svc-c", "/10.96.0.3"),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("agentio-system", "ztunnel"),
		NodeName:  "node-a",
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, []string{"uid-a"})
	if names := selectedNames(got); !slices.Equal(names, []string{"uid-a", "uid-b"}) {
		t.Fatalf("selected named Address resources = %v, want all node-local workloads only", names)
	}

	got = selectWorkloadResources(scope, snapshot, model.AddressType, []string{"uid-c"})
	if names := selectedNames(got); !slices.Equal(names, []string{"uid-a", "uid-b", "uid-c"}) {
		t.Fatalf("selected remote Address resource = %v, want explicit remote workload plus node-local workloads", names)
	}

	got = selectWorkloadResources(scope, snapshot, model.AddressType, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a", "uid-b", "uid-c"}) {
		t.Fatalf("selected VIP Address resources = %v, want subscribed service, every endpoint, and node-local workloads", names)
	}

	got = selectWorkloadResources(scope, snapshot, model.AddressType, []string{"/10.96.0.3"})
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-c", "uid-a", "uid-b", "uid-d"}) {
		t.Fatalf("selected remote-only Service resources = %v, want its remote endpoint and node-local workloads", names)
	}
}

func TestWorkloadTypeNamedServiceResolvesAddressAlias(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-b", "svc-b", ""),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
	}
	snapshot := selectionSnapshot(t, resources)

	got := projectedWorkloads(t, gatewayScope(), snapshot, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"uid-a"}) {
		t.Fatalf("selected Workload resources = %v, want service endpoint resolved through Address alias", names)
	}
}

func TestNamedServiceSubscriptionExpandsSelectedEndpointWorkloads(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-b", "svc-a", ""),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   serviceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}

	got := selectWorkloadResources(scope, snapshot, model.AddressType, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a"}) {
		t.Fatalf("selected resources = %v, want service and selected endpoint workload", names)
	}
}

func TestGatewayNamedServiceSubscriptionExpandsAllEndpoints(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-b", "svc-a", ""),
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
	}
	snapshot := selectionSnapshot(t, resources)

	got := selectWorkloadResources(gatewayScope(), snapshot, model.AddressType, []string{"/10.96.0.1"})
	if names := selectedNames(got); !slices.Equal(names, []string{"demo/svc-a", "uid-a", "uid-b"}) {
		t.Fatalf("selected resources = %v, want service and all endpoints", names)
	}
}

func TestGatewayNamedWorkloadSelectionDoesNotAllocateSnapshotScale(t *testing.T) {
	const resourceCount = 10_000
	value := mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{}}})
	resources := make([]model.Resource, 0, resourceCount+3)
	for i := range resourceCount {
		name := fmt.Sprintf("unrelated-%06d", i)
		resources = append(resources, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.AddressType, Name: name},
			XDSName: name,
			Value:   value,
			Hash:    name,
			Facts: model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID: name,
				NodeName:    "node-a",
				Principal:   serviceAccountPrincipal("demo", "default"),
			}},
		})
	}
	resources = append(resources,
		selectionService(t, "demo/svc-a", "/10.96.0.1"),
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		selectionWorkload(t, "uid-b", "demo", "node-b", "svc-a", ""),
	)
	snapshot := selectionSnapshot(t, resources)

	const runs = 10
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var selected []model.Resource
	allocations := testing.AllocsPerRun(runs, func() {
		selected = selectWorkloadResources(gatewayScope(), snapshot, model.AddressType, []string{"/10.96.0.1"})
	})
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if names := selectedNames(selected); !slices.Equal(names, []string{"demo/svc-a", "uid-a", "uid-b"}) {
		t.Fatalf("selected resources = %v, want target service and endpoints", names)
	}
	if allocations > 64 {
		t.Fatalf("named gateway selection allocations = %.1f/run, want <= 64", allocations)
	}
	if bytesPerRun := (after.TotalAlloc - before.TotalAlloc) / runs; bytesPerRun > 256<<10 {
		t.Fatalf("named gateway selection allocated %d bytes/run, want <= %d", bytesPerRun, 256<<10)
	}

}

func TestUnrelatedGatewayNamedServiceAddressChangeDoesNotReconcile(t *testing.T) {
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	endpoint := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	oldUnrelated := selectionWorkload(t, "uid-b", "demo", "node-b", "svc-b", "")
	newUnrelated, err := model.NewResource(
		oldUnrelated.Key, oldUnrelated.XDSName, oldUnrelated.Value,
		[]string{"uid-b-alias"}, oldUnrelated.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	before := selectionSnapshot(t, []model.Resource{service, endpoint, oldUnrelated})
	after := selectionSnapshot(t, []model.Resource{service, endpoint, newUnrelated})
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: oldUnrelated.Key,
		Old: &oldUnrelated,
		New: &newUnrelated,
	}})
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        gatewayScope(),
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{names: []string{"/10.96.0.1"}},
		Snapshot:     after,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("unrelated change produced resources=%v removed=%v", selectedNames(delta.Resources), delta.Removed)
	}
}

func TestNodeNamedServiceRemotePayloadUpdateUsesChangedKey(t *testing.T) {
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	local := selectionWorkload(t, "uid-local", "demo", "node-a", "svc-a", "")
	oldRemote := selectionWorkload(t, "uid-remote", "demo", "node-b", "svc-a", "")
	newRemote, err := model.NewResource(
		oldRemote.Key, oldRemote.XDSName,
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
			Uid:       "uid-remote",
			Namespace: "demo",
			Node:      "node-b",
			Name:      "updated",
		}}}),
		oldRemote.Aliases, oldRemote.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := selectionSnapshot(t, []model.Resource{service, local, newRemote})
	update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
		Key: oldRemote.Key,
		Old: &oldRemote,
		New: &newRemote,
	}})
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	sent := make(map[string]string, 10_002)
	for i := range 10_000 {
		sent[fmt.Sprintf("unrelated-%05d", i)] = "v1"
	}
	sent[service.XDSName] = service.Hash
	sent[local.XDSName] = local.Hash
	sent[oldRemote.XDSName] = oldRemote.Hash
	watch := &watchState{
		started: true,
		names:   sets.New(service.Aliases[0]),
		sent:    sent,
	}

	view := newIncrementalSubscriptionView(watch, model.AddressType, update)
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.AddressType,
		Subscription: view,
		Snapshot:     snapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"uid-remote"}) {
		t.Fatalf("remote payload-only delta resources = %v, want uid-remote", names)
	}
	if len(delta.Removed) != 0 {
		t.Fatalf("remote payload-only removals = %v, want empty", delta.Removed)
	}
}

func TestNodeNamedServiceRemoteToLocalMoveUpdatesWorkload(t *testing.T) {
	service := selectionService(t, "demo/svc-a", "/10.96.0.1")
	local := selectionWorkload(t, "uid-local", "demo", "node-a", "svc-a", "")
	oldRemote := selectionWorkload(t, "uid-remote", "demo", "node-b", "svc-a", "")
	newLocal := selectionWorkload(t, "uid-remote", "demo", "node-a", "svc-a", "")
	snapshot := selectionSnapshot(t, []model.Resource{service, local, newLocal})
	update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
		Key: oldRemote.Key,
		Old: &oldRemote,
		New: &newLocal,
	}})
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("demo", "ztunnel"),
		NodeName:  "node-a",
	}
	watch := &watchState{
		started: true,
		names:   sets.New(service.Aliases[0]),
		sent: map[string]string{
			service.XDSName: service.Hash, local.XDSName: local.Hash, oldRemote.XDSName: oldRemote.Hash,
		},
	}

	view := newIncrementalSubscriptionView(watch, model.AddressType, update)
	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.AddressType,
		Subscription: view,
		Snapshot:     snapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"uid-remote"}) {
		t.Fatalf("remote-to-local delta resources = %v, want uid-remote", names)
	}
	if len(delta.Removed) != 0 {
		t.Fatalf("remote-to-local removals = %v, want none", delta.Removed)
	}
}

func TestDedicatedWorkloadNamedServiceMembershipLossReconcilesRemovals(t *testing.T) {
	for _, client := range []struct {
		name  string
		class model.ClientClass
	}{
		{name: "sandbox", class: model.ClientDedicatedZTunnel},
	} {
		for _, transition := range []string{"local-to-remote", "delete", "detach-service"} {
			t.Run(client.name+"/"+transition, func(t *testing.T) {
				service := selectionService(t, "demo/svc-a", "/10.96.0.1")
				oldWorkload := selectionWorkload(t, "uid-local", "demo", "node-a", "svc-a", "")
				var newWorkload *model.Resource
				switch transition {
				case "local-to-remote":
					facts := oldWorkload.Facts
					workloadFacts := *facts.Workload
					workloadFacts.Source.Key = "replacement-pod"
					facts.Workload = &workloadFacts
					updated, err := model.NewResource(
						oldWorkload.Key, oldWorkload.XDSName, oldWorkload.Value,
						oldWorkload.Aliases, facts,
					)
					if err != nil {
						t.Fatal(err)
					}
					newWorkload = &updated
				case "delete":
				case "detach-service":
					updated := selectionWorkload(t, "uid-local", "demo", "node-a", "", "")
					newWorkload = &updated
				default:
					t.Fatalf("unknown transition %q", transition)
				}

				resources := []model.Resource{service}
				if newWorkload != nil {
					resources = append(resources, *newWorkload)
				}
				snapshot := selectionSnapshot(t, resources)
				update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
					Key: oldWorkload.Key,
					Old: &oldWorkload,
					New: newWorkload,
				}})
				scope := model.ClientScope{
					Class:       client.class,
					Principal:   serviceAccountPrincipal("demo", "default"),
					WorkloadUID: "uid-local",
					Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-local"},
				}
				watch := &watchState{
					started: true,
					names:   sets.New(service.Aliases[0]),
					sent: map[string]string{
						service.XDSName:     service.Hash,
						oldWorkload.XDSName: oldWorkload.Hash,
					},
				}

				view := newIncrementalSubscriptionView(watch, model.AddressType, update)
				delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
					Scope:        scope,
					TypeURL:      model.AddressType,
					Subscription: view,
					Snapshot:     snapshot,
					Update:       update,
				})
				if err != nil {
					t.Fatal(err)
				}
				wantRemoved := []string{service.XDSName, oldWorkload.XDSName}
				if !slices.Equal(delta.Removed, wantRemoved) {
					t.Fatalf("membership loss removals = %v, want %v", delta.Removed, wantRemoved)
				}
				if len(delta.Resources) != 0 {
					t.Fatalf("membership loss resources = %v, want none", selectedNames(delta.Resources))
				}
			})
		}
	}
}

func TestGatewayWorkloadIncrementalUsesResourceFamily(t *testing.T) {
	oldResource := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	newResource, err := model.NewResource(
		oldResource.Key, "",
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
			Uid:       "uid-a",
			Namespace: "demo",
			Node:      "node-a",
			Name:      "updated",
		}}}), nil, oldResource.Facts)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := selectionWorkload(t, "uid-b", "demo", "node-b", "", "")
	snapshot := selectionSnapshot(t, []model.Resource{newResource, unrelated, selectionWorkload(t, "ordinary", "demo", "node-a", "", "demo/selector-a")})
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent:     map[string]string{oldResource.XDSName: oldResource.Hash, unrelated.XDSName: unrelated.Hash},
	}
	update := updateReversedFrom(t, snapshot, []model.ResourceChange{{
		Key: oldResource.Key,
		Old: &oldResource,
		New: &newResource,
	}})
	view := newIncrementalSubscriptionView(watch, model.AddressType, update)
	if names := view.SentNames(); !slices.Equal(names, []string{oldResource.XDSName}) {
		t.Fatalf("gateway incremental sent-state = %v, want only changed workload", names)
	}

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        gatewayScope(),
		TypeURL:      model.AddressType,
		Subscription: view,
		Snapshot:     snapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"uid-a"}) {
		t.Fatalf("incremental gateway resources = %v, want updated workload", names)
	}
}

func TestIncrementalPublicationTransitionAtTenThousandResources(t *testing.T) {
	_, after, update, target := scaleWorkloadTransition(t, 10_000)
	for _, test := range []struct {
		name  string
		scope model.ClientScope
	}{
		{
			name: "dedicated",
			scope: model.ClientScope{
				Class:       model.ClientDedicatedZTunnel,
				WorkloadUID: target.Facts.Workload.WorkloadUID,
				Source:      target.Facts.Workload.Source,
				Principal:   target.Facts.Workload.Principal,
			},
		},
		{
			name: "node",
			scope: model.ClientScope{
				Class:    model.ClientSharedZTunnel,
				NodeName: "node-050",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
				Scope:        test.scope,
				TypeURL:      model.AddressType,
				Subscription: SubscriptionView{wildcard: true},
				Snapshot:     after,
				Update:       update,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := selectedNames(delta.Resources); len(got) != 1 || got[0] != target.XDSName {
				t.Fatalf("changed resources = %v, want only %q", got, target.XDSName)
			}
			if len(delta.Removed) != 0 {
				t.Fatalf("incremental removals = %v, want none", delta.Removed)
			}
		})
	}
}

// Expanding one Service must resolve the subscription once, rather than allocate
// a Service lookup for every endpoint in the full selection.
func TestNamedServiceSelectionAllocationBudget(t *testing.T) {
	const endpoints = 1_000
	resources := make([]model.Resource, 0, endpoints+1)
	resources = append(resources, selectionService(t, "demo/svc-a", "/10.96.0.1"))
	for i := range endpoints {
		resources = append(resources, selectionWorkload(t, fmt.Sprintf("uid-%04d", i), "demo", "node-a", "svc-a", ""))
	}
	snapshot := selectionSnapshot(t, resources)
	var selected []model.Resource
	allocations := testing.AllocsPerRun(3, func() {
		selected = selectWorkloadResources(gatewayScope(), snapshot, model.AddressType, []string{"/10.96.0.1"})
	})
	if len(selected) != endpoints+1 {
		t.Fatalf("selected resources = %d, want %d", len(selected), endpoints+1)
	}
	if allocations > 200 {
		t.Fatalf("allocations per named Service selection = %.0f, want at most 200", allocations)
	}
}

func TestWorkloadInstanceDemandDoesNotFollowNameReuse(t *testing.T) {
	oldSource := model.SourceRef{Registry: "substrate/runtime-a", Key: "instance-old"}
	old := addressResource(t, "runtime/workload", "actor", oldSource.WorkloadAlias())
	snapshot, err := model.NewResourceSet([]model.Resource{old})
	if err != nil {
		t.Fatal(err)
	}
	subscription := SubscriptionView{names: []string{oldSource.WorkloadAlias()}, sent: map[string]string{}}
	request := GenerationRequest{
		Scope:        gatewayScope(),
		Snapshot:     snapshot,
		TypeURL:      model.WorkloadType,
		Subscription: subscription,
		Full:         true,
	}
	delta, err := (WorkloadGenerator{}).Generate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 || !slices.Contains(delta.Resources[0].Aliases, oldSource.WorkloadAlias()) {
		t.Fatalf("instance demand=%v", delta)
	}
	subscription.sent[old.XDSName] = delta.Resources[0].Hash
	replacement := addressResource(
		t,
		old.Key.Name,
		"actor",
		(model.SourceRef{Registry: oldSource.Registry, Key: "instance-new"}).WorkloadAlias(),
	)
	change := model.ResourceChange{Key: old.Key, Old: &old, New: &replacement}
	after, _, err := snapshot.Apply([]model.ResourceChange{change})
	if err != nil {
		t.Fatal(err)
	}
	request.Full = false
	request.Snapshot = after
	request.Subscription = subscription
	request.Update = updateBetween(snapshot, after, []model.ResourceChange{change})
	delta, err = (WorkloadGenerator{}).Generate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || !slices.Contains(delta.Removed, old.XDSName) {
		t.Fatalf("old identity followed name reuse: %v", delta)
	}
}
