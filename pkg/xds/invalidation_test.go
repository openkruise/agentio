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
	"slices"
	"testing"

	"istio.io/istio/pkg/util/sets"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// Demand may read a publication before either merging boundary processes it.
// Exercise the stream entry points, including a late, older push after rollback.
func TestDemandObservesIntermediatePublication(t *testing.T) {
	for _, typeURL := range []string{model.AddressType, model.WorkloadType, model.TrafficPolicyType, model.SandboxType, model.ClusterType} {
		for _, transient := range []bool{false, true} {
			t.Run(typeURL+map[bool]string{false: "/rollback", true: "/create-delete"}[transient], func(t *testing.T) {
				old := addressResource(t, "a", "old")
				middle := addressResource(t, "a", "middle")
				var dependencies []model.Resource
				switch typeURL {
				case model.TrafficPolicyType:
					dependencies = []model.Resource{
						workloadWithTrafficRefs(t, addressResource(t, "worker", "worker"), "a"),
					}
					old = sharedTrafficResource(t, "a", securityv1.TrafficPolicy_ALLOW)
					middle = sharedTrafficResource(t, "a", securityv1.TrafficPolicy_DENY)
				case model.SandboxType:
					old = sandboxResource(t, "a")
					middle = sandboxResourceWithAttester(t, "a", "worker")
				case model.ClusterType:
					old = gatewayResource(t, "demo/egress", "a", "old")
					middle = gatewayResource(t, "demo/egress", "a", "middle")
				}
				initial := append(slices.Clone(dependencies), old)
				if transient {
					initial = dependencies
				}
				server := newTestServer(t, gatewayScope(), initial, nil)
				stream := newFakeStream(t.Context(), 1)
				subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
				watches := map[string]*watchState{}
				name := "a"
				if typeURL == model.AddressType {
					name = "*"
				}
				request := func() {
					t.Helper()
					if err := server.server.handleRequest(
						stream,
						server.scope,
						log,
						watches,
						subscription,
						nodeRequest(typeURL, name),
					); err != nil {
						t.Fatal(err)
					}
				}
				request()
				original := map[string]string{}
				for _, resource := range stream.sent()[0].Resources {
					original[resource.Name] = resource.Version
				}
				before := server.resources.Snapshot()
				during := selectionSnapshot(t, append(slices.Clone(dependencies), middle))
				server.resources.publish(during)
				request()
				responses := stream.sent()
				if len(responses[len(responses)-1].Resources) != 1 {
					t.Fatal("intermediate publication was not delivered")
				}
				server.resources.publish(before)
				forward := updateBetween(before, during, before.Diff(during))
				rollback := updateBetween(during, before, during.Diff(before))
				for _, update := range []xdsstore.Update{xdsstore.Merge(forward, rollback), forward} {
					if err := server.server.pushUpdate(stream, server.scope, log, watches, update); err != nil {
						t.Fatal(err)
					}
					actual := map[string]string{}
					for _, response := range stream.sent() {
						for _, resource := range response.Resources {
							actual[resource.Name] = resource.Version
						}
						for _, removed := range response.RemovedResources {
							delete(actual, removed)
						}
					}
					if len(actual) != len(original) || actual["a"] != original["a"] {
						t.Fatalf("client remains on intermediate state: got %v, want %v", actual, original)
					}
				}
			})
		}
	}
}

func TestMergedUpdateWithdrawsIntermediateDependencies(t *testing.T) {
	own := selectionWorkload(t, "own", "demo", "node-a", "", "")
	policy := sharedTrafficResource(t, "p", securityv1.TrafficPolicy_ALLOW)
	authorization := selectionAuthorization(t, "auth", model.AuthorizationScopeWorkload, "")
	service := selectionService(t, "demo/svc")
	gateway := selectionOwnedByGateway(
		t,
		selectionWorkload(t, "gateway", "demo", "gateway-node", "", ""),
		"demo/gateway",
	)
	bound := selectionWithGatewayReference(t,
		workloadWithTrafficRefs(t, selectionWorkload(t, "own", "demo", "node-a", "svc", "auth"), "p"), "demo/gateway")
	base := selectionSnapshot(t, []model.Resource{own, policy, authorization, service, gateway})
	middle := selectionSnapshot(t, []model.Resource{bound, policy, authorization, service, gateway})
	update := xdsstore.Merge(
		updateBetween(base, middle, base.Diff(middle)),
		updateBetween(middle, base, middle.Diff(base)),
	)
	scope := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"}
	for _, tc := range []struct {
		typeURL   string
		generator ResourceGenerator
		removed   []string
	}{
		{model.AddressType, WorkloadGenerator{}, []string{"demo/svc", "gateway"}},
		{model.WorkloadType, WorkloadGenerator{}, []string{"gateway"}},
		{model.TrafficPolicyType, TrafficPolicyGenerator{}, []string{"p"}},
		{model.WorkloadAuthorizationType, AuthorizationGenerator{}, []string{"auth"}},
	} {
		t.Run(tc.typeURL, func(t *testing.T) {
			subscription := initializedSubscription(
				t,
				tc.generator,
				scope,
				tc.typeURL,
				middle,
				SubscriptionView{wildcard: true},
			)
			delta, err := tc.generator.Generate(
				t.Context(),
				GenerationRequest{
					Scope:        scope,
					TypeURL:      tc.typeURL,
					Snapshot:     base,
					Subscription: subscription,
					Update:       update,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(delta.Removed, tc.removed) {
				t.Fatalf("removals = %v, want %v", delta.Removed, tc.removed)
			}
			for _, resource := range delta.Resources {
				if slices.Contains(tc.removed, resource.XDSName) {
					t.Fatalf("revoked dependency %s was resent", resource.XDSName)
				}
			}
		})
	}
}

func TestMergedUpdateWithdrawsIntermediateServiceAlias(t *testing.T) {
	endpoint := selectionWorkload(t, "endpoint", "demo", "remote-node", "svc", "")
	service := selectionService(t, "demo/svc")
	aliased := selectionService(t, "demo/svc", "vip")
	before := selectionSnapshot(t, []model.Resource{endpoint, service})
	middle := selectionSnapshot(t, []model.Resource{endpoint, aliased})
	update := xdsstore.Merge(
		updateBetween(before, middle, before.Diff(middle)),
		updateBetween(middle, before, middle.Diff(before)),
	)
	subscription := initializedSubscription(
		t,
		WorkloadGenerator{},
		gatewayScope(),
		model.AddressType,
		middle,
		SubscriptionView{names: []string{"vip"}},
	)
	if len(subscription.sent) != 2 {
		t.Fatalf("alias did not expand: %v", subscription.sent)
	}
	delta, err := (WorkloadGenerator{}).Generate(
		t.Context(),
		GenerationRequest{
			Scope:        gatewayScope(),
			TypeURL:      model.AddressType,
			Snapshot:     before,
			Subscription: subscription,
			Update:       update,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(delta.Removed, []string{"demo/svc", "endpoint"}) || len(delta.Resources) != 0 {
		t.Fatalf("alias rollback: %+v", delta)
	}
}

func TestWildcardRemovalSurvivesResourceThenReferenceDeletion(t *testing.T) {
	plain := selectionWorkload(t, "own", "demo", "node-a", "", "")
	own := selectionWithGatewayReference(t, selectionWorkload(t, "own", "demo", "node-a", "svc", ""), "demo/gateway")
	service := selectionService(t, "demo/svc")
	gateway := selectionOwnedByGateway(
		t,
		selectionWorkload(t, "gateway", "demo", "gateway-node", "", ""),
		"demo/gateway",
	)
	before := selectionSnapshot(t, []model.Resource{own, service, gateway})
	middle := selectionSnapshot(t, []model.Resource{own})
	after := selectionSnapshot(t, []model.Resource{plain})
	update := xdsstore.Merge(
		updateBetween(before, middle, before.Diff(middle)),
		updateBetween(middle, after, middle.Diff(after)),
	)
	for _, node := range []string{"node-a", "unrelated-node"} {
		delta, err := (WorkloadGenerator{}).Generate(t.Context(), GenerationRequest{
			Scope:        model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: node},
			TypeURL:      model.AddressType,
			Snapshot:     after,
			Update:       update,
			Subscription: SubscriptionView{wildcard: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{"demo/svc", "gateway"}
		if node == "unrelated-node" {
			expected = nil
		}
		if !slices.Equal(delta.Removed, expected) {
			t.Fatalf("scope %s: removed %v, want %v", node, delta.Removed, expected)
		}
		if !delta.elideSentState {
			t.Fatal("wildcard Address unexpectedly retains sent state")
		}
	}
}

func TestMergedUpdateWithdrawsIntermediateSandboxScope(t *testing.T) {
	old := workerResource(t, "old-pod")
	middleWorker := workerResource(t, "middle-pod")
	sandbox := sandboxResourceWithAttester(t, "actor", "worker")
	before := selectionSnapshot(t, []model.Resource{old, sandbox})
	middle := selectionSnapshot(t, []model.Resource{middleWorker, sandbox})
	update := xdsstore.Merge(
		updateBetween(before, middle, before.Diff(middle)),
		updateBetween(middle, before, middle.Diff(before)),
	)
	scope := workerScope(middleWorker)
	subscription := initializedSubscription(
		t,
		SandboxGenerator{},
		scope,
		model.SandboxType,
		middle,
		SubscriptionView{names: []string{"actor"}},
	)
	delta, err := (SandboxGenerator{}).Generate(
		t.Context(),
		GenerationRequest{
			Scope:        scope,
			TypeURL:      model.SandboxType,
			Snapshot:     before,
			Subscription: subscription,
			Update:       update,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(delta.Removed, []string{"actor"}) {
		t.Fatalf("sandbox scope rollback: %+v", delta)
	}
}

func TestWildcardFullNotificationPreservesQueuedRemovals(t *testing.T) {
	resource := addressResource(t, "a", "a")
	before := selectionSnapshot(t, []model.Resource{resource})
	empty := selectionSnapshot(t, nil)
	resources := xdsstore.New(before)
	sub := resources.Subscribe(t.Context(), model.ClientScope{})
	sub.Watch(model.AddressType)
	resources.Replace(empty)
	resources.Notify()
	update := <-sub.Updates()
	server := newTestServer(t, ztunnelScope(), nil, nil)
	watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: map[string]string{}}
	stream := newFakeStream(t.Context(), 1)
	if err := server.server.pushUpdate(
		stream,
		server.scope,
		log,
		map[string]*watchState{model.AddressType: watch},
		update,
	); err != nil {
		t.Fatal(err)
	}
	responses := stream.sent()
	if len(responses) != 1 || !slices.Equal(responses[0].RemovedResources, []string{"a"}) {
		t.Fatalf("full notification lost removal: %v", responses)
	}
	if len(watch.sent) != 0 {
		t.Fatal("wildcard retained sent state")
	}
}

func TestQueuedDeletionKeepsCurrentWireReplacement(t *testing.T) {
	old := gatewayResource(t, "demo/egress", "shared", "old")
	replacement, err := model.NewResource(
		model.ResourceKey{TypeURL: model.ClusterType, Name: "replacement-key"},
		old.XDSName,
		old.Value,
		nil,
		old.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	before := selectionSnapshot(t, []model.Resource{old})
	empty := selectionSnapshot(t, nil)
	current := selectionSnapshot(t, []model.Resource{replacement})
	for _, tc := range []struct {
		name          string
		sent          map[string]string
		wantResources int
	}{
		{name: "replacement already sent", sent: map[string]string{replacement.XDSName: replacement.Hash}},
		{name: "old resource sent", sent: map[string]string{old.XDSName: old.Hash}, wantResources: 1},
		{name: "never sent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delta, err := (SnapshotGenerator{}).Generate(t.Context(), GenerationRequest{
				Scope:        gatewayScope(),
				TypeURL:      model.ClusterType,
				Snapshot:     current,
				Update:       updateBetween(before, empty, before.Diff(empty)),
				Subscription: SubscriptionView{wildcard: true, sent: tc.sent},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(delta.Resources) != tc.wantResources || len(delta.Removed) != 0 {
				t.Fatalf("old deletion changed current replacement: %+v", delta)
			}
			if len(delta.Resources) != 0 && delta.Resources[0].Key != replacement.Key {
				t.Fatalf("selected stale replacement: %+v", delta)
			}
			// A client with no withdrawal obligation learns the replacement from
			// its own publication, not from another key's queued deletion.
			delta, err = (SnapshotGenerator{}).Generate(t.Context(), GenerationRequest{
				Scope:        gatewayScope(),
				TypeURL:      model.ClusterType,
				Snapshot:     current,
				Update:       updateBetween(empty, current, empty.Diff(current)),
				Subscription: SubscriptionView{wildcard: true},
			})
			if err != nil || len(delta.Resources) != 1 || len(delta.Removed) != 0 {
				t.Fatalf("replacement publication: delta=%+v err=%v", delta, err)
			}
		})
	}
}

// Wildcard Address watches have no sent table: historical scope grants must
// still protect a currently visible replacement from a queued deletion.
func TestWildcardQueuedDeletionKeepsCurrentWireReplacement(t *testing.T) {
	old := selectionWorkload(t, "shared", "demo", "node-a", "", "")
	before := selectionSnapshot(t, []model.Resource{old})
	empty := selectionSnapshot(t, nil)
	for _, node := range []string{"node-a", "node-b"} {
		t.Run(node, func(t *testing.T) {
			next := selectionWorkload(t, "shared", "demo", node, "", "")
			replacement, err := model.NewResource(
				model.ResourceKey{TypeURL: model.AddressType, Name: "replacement-key"},
				old.XDSName, next.Value, nil, next.Facts)
			if err != nil {
				t.Fatal(err)
			}
			current := selectionSnapshot(t, []model.Resource{replacement})
			delta, err := (WorkloadGenerator{}).Generate(t.Context(), GenerationRequest{
				Scope:        model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"},
				TypeURL:      model.AddressType,
				Snapshot:     current,
				Update:       updateBetween(before, empty, before.Diff(empty)),
				Subscription: SubscriptionView{wildcard: true},
			})
			if err != nil {
				t.Fatal(err)
			}
			if node == "node-a" {
				if len(delta.Resources) != 1 || delta.Resources[0].Key != replacement.Key || len(delta.Removed) != 0 {
					t.Fatalf("visible replacement lost: %+v", delta)
				}
			} else if len(delta.Resources) != 0 || !slices.Equal(delta.Removed, []string{old.XDSName}) {
				t.Fatalf("invisible replacement prevented withdrawal: %+v", delta)
			}
			if !delta.elideSentState {
				t.Fatal("wildcard Address started retaining sent state")
			}
		})
	}
}

func TestMergedDependencyScopesRemainImmutable(t *testing.T) {
	a := selectionWorkload(t, "a", "demo", "node-a", "svc", "")
	b := selectionWorkload(t, "b", "demo", "node-b", "svc", "")
	service := selectionService(t, "demo/svc")
	before := selectionSnapshot(t, []model.Resource{a, b, service})
	middle := selectionSnapshot(t, []model.Resource{b, service})
	after := selectionSnapshot(t, []model.Resource{service})
	first := updateBetween(before, middle, before.Diff(middle))
	second := updateBetween(middle, after, middle.Diff(after))
	merged := xdsstore.Merge(first, second)
	for _, tc := range []struct {
		update xdsstore.Update
		scopes int
	}{{first, 1}, {second, 1}, {merged, 2}} {
		found := false
		for _, candidate := range tc.update.Candidates(model.AddressType) {
			if candidate.Key == service.Key {
				found = true
				if len(candidate.Identities) != 1 || len(candidate.Identities[0].Workloads) != tc.scopes {
					t.Fatalf("dependency scopes mutated or lost: %+v, want %d", candidate, tc.scopes)
				}
			}
		}
		if !found {
			t.Fatal("lost dependent Service")
		}
	}
}

// A withdrawal can overlap a selected key, repeat across historical identities,
// or resolve to a replacement absent from the notification. All three cases
// must still produce one deterministic result per wire name.
func TestIncrementalCombinesSelectedAndWithdrawnNames(t *testing.T) {
	oldA := gatewayResource(t, "demo/egress", "a", "old-a")
	oldB := gatewayResource(t, "demo/egress", "b", "old-b")
	oldC := gatewayResource(t, "demo/egress", "c", "old-c")
	middleA := gatewayResource(t, "demo/egress", "a", "middle-a")
	newC := gatewayResource(t, "demo/egress", "c", "new-c")
	replacement, err := model.NewResource(
		model.ResourceKey{TypeURL: model.ClusterType, Name: "replacement-a"},
		oldA.XDSName, oldA.Value, nil, oldA.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	aliasOnly, err := model.NewResource(
		model.ResourceKey{TypeURL: model.ClusterType, Name: "alias-only"},
		"unrelated", oldB.Value, []string{oldB.XDSName}, oldB.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	before := selectionSnapshot(t, []model.Resource{oldA, oldB, oldC})
	middle := selectionSnapshot(t, []model.Resource{middleA, oldB, oldC})
	after := selectionSnapshot(t, []model.Resource{newC})
	current := selectionSnapshot(t, []model.Resource{replacement, newC, aliasOnly})
	update := xdsstore.Merge(
		updateBetween(before, middle, before.Diff(middle)),
		updateBetween(middle, after, middle.Diff(after)),
	)
	delta, err := (SnapshotGenerator{}).Generate(t.Context(), GenerationRequest{
		Scope:    gatewayScope(),
		TypeURL:  model.ClusterType,
		Snapshot: current,
		Update:   update,
		Subscription: SubscriptionView{
			wildcard: true,
			sent: map[string]string{
				oldA.XDSName: oldA.Hash,
				oldB.XDSName: oldB.Hash,
				oldC.XDSName: oldC.Hash,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"a", "c"}) {
		t.Fatalf("resources = %v, want sorted replacement and selected resource", names)
	}
	if delta.Resources[0].Key != replacement.Key || delta.Resources[1].Hash != newC.Hash {
		t.Fatalf("wrong current resource: %+v", delta.Resources)
	}
	if !slices.Equal(delta.Removed, []string{"b"}) {
		t.Fatalf("removals = %v, want b only", delta.Removed)
	}
}
