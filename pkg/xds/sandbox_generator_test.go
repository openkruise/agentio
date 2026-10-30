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
	"reflect"
	"slices"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func sandboxResource(t *testing.T, uid string, policies ...*securityv1.TrafficPolicy) model.Resource {
	return sandboxResourceWithAttester(t, uid, "", policies...)
}

func sandboxResourceWithAttester(
	t *testing.T,
	uid, workloadUID string,
	policies ...*securityv1.TrafficPolicy,
) model.Resource {
	t.Helper()
	var trafficPolicy *securityv1.TrafficPolicy
	if len(policies) > 1 {
		t.Fatal("expected one effective TrafficPolicy")
	}
	if len(policies) == 1 {
		trafficPolicy = policies[0]
	}
	value, err := anypb.New(
		&sandboxv1.Sandbox{
			Uid:           uid,
			Attester:      &sandboxv1.Sandbox_Attester{WorkloadUid: workloadUID},
			TrafficPolicy: trafficPolicy,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	r, err := model.NewResource(
		model.ResourceKey{TypeURL: model.SandboxType, Name: uid},
		"",
		value,
		nil,
		model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{AttesterWorkloadUID: workloadUID}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func workerResource(t *testing.T, source string) model.Resource {
	t.Helper()
	r := selectionWorkload(t, "worker", "workers", "node-a", "", "")
	facts := *r.Facts.Workload
	facts.WorkloadUID = "worker"
	facts.Source = model.SourceRef{Registry: "kubernetes/test", Key: source}
	r, err := model.NewResource(r.Key, r.XDSName, r.Value, r.Aliases, model.ResourceFacts{Workload: &facts})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func workerScope(r model.Resource) model.ClientScope {
	return model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   r.Facts.Workload.Principal,
		WorkloadUID: "worker",
		Source:      r.Facts.Workload.Source,
	}
}

func TestSandboxNamedDeltaResubscribeAndDeletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := gatewayScope()
	a, b := sandboxResource(t, "a"), sandboxResource(t, "b")
	server := newTestServer(t, scope, []model.Resource{a, b}, nil)
	stream := newFakeStream(ctx, 8)
	done := server.start(stream)
	request := nodeRequest(model.SandboxType)
	request.ResourceNamesSubscribe = []string{"a", "missing"}
	stream.send(request)
	responses := stream.awaitResponses(t, model.SandboxType, 1)
	first := responses[0]
	if len(first.Resources) != 1 || first.Resources[0].Name != "a" ||
		!reflect.DeepEqual(first.RemovedResources, []string{"missing"}) {
		t.Fatalf("unexpected initial response %v", first)
	}
	stream.send(
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                model.SandboxType,
			ResponseNonce:          first.Nonce,
			ResourceNamesSubscribe: []string{"a"},
		},
	)
	responses = stream.awaitResponses(t, model.SandboxType, 2)
	if len(responses[1].Resources) != 1 {
		t.Fatal("repeated subscribe must resend cached resource")
	}
	server.resources.publish(selectionSnapshot(t, []model.Resource{b}))
	responses = stream.awaitResponses(t, model.SandboxType, 3)
	if !reflect.DeepEqual(responses[2].RemovedResources, []string{"a"}) {
		t.Fatalf("deletion %v", responses[2])
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatal(err)
	}
}

func TestSandboxDynamicWorkerScopeAndPodReplacement(t *testing.T) {
	a, b := sandboxResource(t, "a"), sandboxResource(t, "b")
	empty := workerResource(t, "pod-1")
	boundA, boundB := sandboxResourceWithAttester(t, "a", "worker"), sandboxResourceWithAttester(t, "b", "worker")
	replacement := workerResource(t, "pod-2")
	scope := workerScope(empty)
	snapshots := []model.ResourceSet{
		selectionSnapshot(t, []model.Resource{empty, a, b}),
		selectionSnapshot(t, []model.Resource{empty, boundA, boundB}),
		selectionSnapshot(t, []model.Resource{replacement, boundA, boundB}),
	}
	sub := SubscriptionView{names: []string{"a", "b", "other"}, sent: map[string]string{}}
	gen := SandboxGenerator{}
	full, err := gen.Generate(
		t.Context(),
		GenerationRequest{
			Scope:        scope,
			TypeURL:      model.SandboxType,
			Subscription: sub,
			Snapshot:     snapshots[0],
			Full:         true,
		},
	)
	if err != nil || len(full.Resources) != 0 {
		t.Fatalf("empty worker: %+v %v", full, err)
	}
	for i := 1; i < len(snapshots); i++ {
		before, after := snapshots[i-1], snapshots[i]
		update := updateBetween(before, after, before.Diff(after))
		if !update.Affects(model.SandboxType) {
			t.Fatal("binding/source update did not wake Sandbox watch")
		}
		delta, err := gen.Generate(
			t.Context(),
			GenerationRequest{
				Scope:        scope,
				TypeURL:      model.SandboxType,
				Subscription: sub,
				Snapshot:     after,
				Update:       update,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && len(delta.Resources) != 2 {
			t.Fatalf("dynamic binding: %+v", delta)
		}
		if i == 2 && !reflect.DeepEqual(delta.Removed, []string{"a", "b"}) {
			t.Fatalf("old Pod retained visibility: %+v", delta)
		}
		for _, resource := range delta.Resources {
			sub.sent[resource.XDSName] = resource.Hash
		}
		for _, name := range delta.Removed {
			delete(sub.sent, name)
		}
	}
}

func TestSandboxMembershipDoesNotChangeWorkload(t *testing.T) {
	worker := workerResource(t, "pod-1")
	a := sandboxResourceWithAttester(t, "a", "worker")
	b := sandboxResourceWithAttester(t, "b", "worker")
	before := selectionSnapshot(t, []model.Resource{worker, a})
	after := selectionSnapshot(t, []model.Resource{worker, a, b})
	update := updateBetween(before, after, before.Diff(after))
	if update.Affects(model.AddressType) || update.Affects(model.WorkloadType) {
		t.Fatal("Sandbox membership change woke Workload watches")
	}
}

func TestSandboxWatchStartsEmptyAndUnsubscribeStopsDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := gatewayScope()
	a := sandboxResource(t, "a")
	server := newTestServer(t, scope, []model.Resource{a}, nil)
	stream := newFakeStream(ctx, 8)
	done := server.start(stream)
	request := nodeRequest(model.SandboxType, "*")
	request.ResourceNamesUnsubscribe = []string{"*"}
	stream.send(request)
	first := stream.awaitResponses(t, model.SandboxType, 1)[0]
	if len(first.Resources) != 0 {
		t.Fatal("simultaneous wildcard subscribe/unsubscribe must start an empty watch")
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.SandboxType, ResourceNamesSubscribe: []string{"a"}})
	stream.awaitResponses(t, model.SandboxType, 2)
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.SandboxType, ResourceNamesUnsubscribe: []string{"a"}})
	stream.awaitResponses(t, model.SandboxType, 3)
	// A subsequent explicit request is a barrier proving the earlier update was processed.
	changed := sandboxResource(t, "a", &securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{}})
	server.resources.publish(selectionSnapshot(t, []model.Resource{changed}))
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.SandboxType})
	responses := stream.awaitResponses(t, model.SandboxType, 4)
	for _, response := range responses[2:] {
		if len(response.Resources) > 0 {
			t.Fatal("unsubscribed resource delivered")
		}
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatal(err)
	}
}

func TestSandboxImplicitWildcardDelivery(t *testing.T) {
	for _, mode := range []string{"existing", "warm pool", "reconnect"} {
		t.Run(mode, func(t *testing.T) {
			worker := workerResource(t, "pod-1")
			a := sandboxResourceWithAttester(t, "a", "worker")
			outside := sandboxResourceWithAttester(t, "outside", "another-worker")
			resources := []model.Resource{worker, outside}
			if mode != "warm pool" {
				resources = append(resources, a)
			}
			server := newTestServer(t, workerScope(worker), resources, nil)
			stream := newFakeStream(t.Context(), 8)
			done := server.start(stream)
			request := nodeRequest(model.SandboxType)
			if mode == "reconnect" {
				request.InitialResourceVersions = map[string]string{"a": a.Hash, "gone": "old-version"}
			}
			stream.send(request)
			first := stream.awaitResponses(t, model.SandboxType, 1)[0]
			var wantResources, wantRemoved []string
			if mode == "existing" {
				wantResources = []string{"a"}
			}
			if mode == "reconnect" {
				wantRemoved = []string{"gone"}
			}
			if !slices.Equal(resourceNames(first), wantResources) ||
				!slices.Equal(first.RemovedResources, wantRemoved) {
				t.Fatalf("initial response = %v, want resources %v, removed %v", first, wantResources, wantRemoved)
			}
			stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.SandboxType, ResponseNonce: first.Nonce})

			// New bindings and policy updates must arrive without another subscription,
			// including when the first response was empty or came from a reconnect.
			changed := sandboxResourceWithAttester(
				t,
				"a",
				"worker",
				&securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{}},
			)
			b := sandboxResourceWithAttester(t, "b", "worker")
			server.resources.publish(selectionSnapshot(t, []model.Resource{worker, changed, b, outside}))
			updated := stream.awaitResponses(t, model.SandboxType, 2)[1]
			if !slices.Equal(resourceNames(updated), []string{"a", "b"}) || len(updated.RemovedResources) != 0 {
				t.Fatalf("incremental response = %v, want only a and b", updated)
			}
			if updated.Resources[0].Version == a.Hash {
				t.Fatal("policy update delivered the old Sandbox version")
			}
			stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.SandboxType, ResponseNonce: updated.Nonce})
			server.resources.publish(selectionSnapshot(t, []model.Resource{worker, b, outside}))
			removed := stream.awaitResponses(t, model.SandboxType, 3)[2]
			if len(removed.Resources) != 0 || !slices.Equal(removed.RemovedResources, []string{"a"}) {
				t.Fatalf("deletion response = %v, want only a removed", removed)
			}
			if err := server.finish(t, stream, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSandboxInlinePolicyChangeIsDeliveredWithoutPolicySubscriptions(t *testing.T) {
	worker := workerResource(t, "pod-1")
	policy := &securityv1.TrafficPolicy{
		Egress: &securityv1.TrafficPolicy_RuleSet{
			Rules: []*securityv1.TrafficPolicy_Rule{
				{Action: securityv1.TrafficPolicy_DENY, Match: &securityv1.TrafficPolicy_Match{}},
			},
		},
	}
	before := selectionSnapshot(t, []model.Resource{worker, sandboxResourceWithAttester(t, "a", "worker")})
	after := selectionSnapshot(t, []model.Resource{worker, sandboxResourceWithAttester(t, "a", "worker", policy)})
	update := updateBetween(before, after, before.Diff(after))
	if update.Affects(model.WorkloadAuthorizationType) || update.Affects(model.SniTrafficPolicyType) {
		t.Fatal("inline policy change must not wake independent policy watches")
	}
	delta, err := (SandboxGenerator{}).Generate(t.Context(), GenerationRequest{
		Scope:        workerScope(worker),
		TypeURL:      model.SandboxType,
		Subscription: SubscriptionView{names: []string{"a"}},
		Snapshot:     after,
		Update:       update,
	})
	if err != nil || len(delta.Resources) != 1 {
		t.Fatalf("inline update: %+v %v", delta, err)
	}
	manifest := new(sandboxv1.Sandbox)
	if err := delta.Resources[0].Value.UnmarshalTo(manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.TrafficPolicy == nil || manifest.TrafficPolicy.Egress.Rules[0].Action != securityv1.TrafficPolicy_DENY {
		t.Fatal("Sandbox update lost the complete deny policy")
	}
}

func TestSandboxAttesterMigrationUpdatesVisibilityWithoutWorkloadChanges(t *testing.T) {
	a := selectionWorkload(t, "worker-a", "workers", "node-a", "", "")
	b := selectionWorkload(t, "worker-b", "workers", "node-b", "", "")
	beforeSandbox := sandboxResourceWithAttester(t, "actor", "worker-a")
	afterSandbox := sandboxResourceWithAttester(t, "actor", "worker-b")
	before := selectionSnapshot(t, []model.Resource{a, b, beforeSandbox})
	after := selectionSnapshot(t, []model.Resource{a, b, afterSandbox})
	update := updateBetween(before, after, before.Diff(after))
	if update.Affects(model.AddressType) || update.Affects(model.WorkloadType) {
		t.Fatal("attester migration changed Workload resources")
	}
	if len(before.ListSandboxesByAttester("worker-a")) != 1 || len(before.ListSandboxesByAttester("worker-b")) != 0 ||
		len(after.ListSandboxesByAttester("worker-a")) != 0 || len(after.ListSandboxesByAttester("worker-b")) != 1 {
		t.Fatal("attester index did not preserve before/after snapshots")
	}
	for _, wildcard := range []bool{false, true} {
		for _, worker := range []model.Resource{a, b} {
			scope := model.ClientScope{
				Class:       model.ClientDedicatedZTunnel,
				Principal:   worker.Facts.Workload.Principal,
				WorkloadUID: worker.Facts.Workload.WorkloadUID,
				Source:      worker.Facts.Workload.Source,
			}
			initial := initializedSubscription(t, SandboxGenerator{}, scope, model.SandboxType,
				before, SubscriptionView{names: []string{"actor"}, wildcard: wildcard})
			watch := &watchState{wildcard: wildcard, names: sets.New("actor"), sent: initial.sent}
			delta, err := (SandboxGenerator{}).Generate(t.Context(), GenerationRequest{
				Scope:        scope,
				TypeURL:      model.SandboxType,
				Subscription: newIncrementalSubscriptionView(watch, model.SandboxType, update),
				Snapshot:     after,
				Update:       update,
			})
			if err != nil {
				t.Fatal(err)
			}
			if worker.Key.Name == "worker-a" {
				if len(delta.Resources) != 0 || !reflect.DeepEqual(delta.Removed, []string{"actor"}) {
					t.Fatalf("old attester retained visibility: %+v", delta)
				}
			} else if len(delta.Resources) != 1 || len(delta.Removed) != 0 {
				t.Fatalf("new attester did not gain visibility: %+v", delta)
			}
		}
	}
}

// Exercise the real Store subscription index together with the generator: a
// binding move and a replacement Pod must withdraw the old stream's Sandbox.
func TestScopedStoreSandboxLifecycle(t *testing.T) {
	worker := workerResource(t, "pod-1")
	sandbox := sandboxResourceWithAttester(t, "sandbox", "worker")
	server := newTestServer(t, workerScope(worker), []model.Resource{worker, sandbox}, nil)
	resources := xdsstore.New(selectionSnapshot(t, []model.Resource{worker, sandbox}))
	server.server.resources = resources
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream := newFakeStream(ctx, 16)
	done := server.start(stream)
	stream.send(nodeRequest(model.SandboxType, "*"))
	response := stream.awaitResponses(t, model.SandboxType, 1)[0]
	if len(response.Resources) != 1 {
		t.Fatal("initial Sandbox missing")
	}
	steps := []struct {
		resource model.Resource
		removed  bool
	}{
		{sandboxResourceWithAttester(t, "sandbox", "other"), true},
		{sandbox, false},
		{workerResource(t, "pod-2"), true},
	}
	for i, step := range steps {
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.SandboxType, ResponseNonce: response.Nonce})
		if _, err := resources.Apply(
			[]model.ResourceChange{{Key: step.resource.Key, New: &step.resource}},
		); err != nil {
			t.Fatal(err)
		}
		response = stream.awaitResponses(t, model.SandboxType, i+2)[i+1]
		if step.removed {
			if !reflect.DeepEqual(response.RemovedResources, []string{"sandbox"}) || len(response.Resources) != 0 {
				t.Fatalf("withdrawal: %v", response)
			}
		} else if len(response.Resources) != 1 || response.Resources[0].Name != "sandbox" {
			t.Fatalf("rebind: %v", response)
		}
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatal(err)
	}
}
