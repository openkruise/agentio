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
	"slices"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestWorkloadVisibilityFollowsScopedWorkloads(t *testing.T) {
	owned := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		"agentio-system/egress-a")
	sameNode := selectionWorkload(t, "uid-b", "other", "node-a", "svc-b", "")
	remote := selectionWorkload(t, "uid-c", "remote", "node-b", "svc-c", "")
	serviceA := selectionService(t, "demo/svc-a")
	serviceB := selectionService(t, "demo/svc-b")
	serviceC := selectionService(t, "demo/svc-c")
	gateway := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""),
		"agentio-system/egress-a")
	snapshot := selectionSnapshot(t, []model.Resource{
		owned, sameNode, remote, serviceA, serviceB, serviceC, gateway,
	})

	dedicated := newAddressSelection(
		model.ClientScope{
			Class:       model.ClientDedicatedZTunnel,
			Principal:   model.MustServiceAccountPrincipal("demo", "default"),
			WorkloadUID: "uid-a",
			Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
		},
		snapshot,
		model.AddressType, SubscriptionView{wildcard: true},
	)
	if !dedicated.visible(owned) || dedicated.visible(sameNode) || dedicated.visible(remote) {
		t.Fatal("dedicated Workload visibility did not follow the sandbox scope")
	}
	if !dedicated.visible(serviceA) || dedicated.visible(serviceB) {
		t.Fatal("dedicated Service visibility did not follow its scoped Workload")
	}
	if !dedicated.visible(gateway) {
		t.Fatal("referenced Gateway workload is not visible")
	}

	node := newAddressSelection(
		model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"},
		snapshot, model.AddressType, SubscriptionView{wildcard: true},
	)
	if !node.visible(owned) || !node.visible(sameNode) || node.visible(remote) {
		t.Fatal("node Workload visibility did not follow the node scope")
	}
	if !node.visible(serviceB) || node.visible(serviceC) {
		t.Fatal("node Service visibility did not follow its scoped Workloads")
	}
}

func TestWildcardWDSIncrementalDiffsPublicationTransitionClosure(t *testing.T) {
	plain := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	attached := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""),
		"agentio-system/egress-a")
	service := selectionService(t, "demo/svc-a")
	gateway := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""),
		"agentio-system/egress-a")
	before := selectionSnapshot(t, []model.Resource{plain, service, gateway})
	after := selectionSnapshot(t, []model.Resource{attached, service, gateway})
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   model.MustServiceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}

	added, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     after,
		Update: updateBetween(before, after, []model.ResourceChange{{
			Key: plain.Key,
			Old: &plain,
			New: &attached,
		}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := selectedNames(
		added.Resources,
	), []string{
		"demo/svc-a",
		"gateway-a",
		"uid-a",
	}; !slices.Equal(got, want) ||
		len(added.Removed) != 0 {
		t.Fatalf("reference addition resources=%v removed=%v, want resources=%v", got, added.Removed, want)
	}

	removed, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.AddressType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     before,
		Update: updateBetween(after, before, []model.ResourceChange{{
			Key: plain.Key,
			Old: &attached,
			New: &plain,
		}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := selectedNames(removed.Resources), []string{"uid-a"}; !slices.Equal(got, want) {
		t.Fatalf("reference removal resources=%v, want %v", got, want)
	}
	slices.Sort(removed.Removed)
	if got, want := removed.Removed, []string{"demo/svc-a", "gateway-a"}; !slices.Equal(got, want) {
		t.Fatalf("reference removal removed=%v, want %v", got, want)
	}
}

// Node moves and relationship changes must converge to the same selection as a
// fresh full generation, including implicit resources in named subscriptions.
func TestAddressSelectionFullAndIncrementalConverge(t *testing.T) {
	gatewayA := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-a", "agentio-system", "gateway-node", "", ""), "agentio-system/egress-a")
	gatewayB := selectionOwnedByGateway(t,
		selectionWorkload(t, "gateway-b", "agentio-system", "gateway-node", "", ""), "agentio-system/egress-b")
	serviceA := selectionService(t, "demo/svc-a", "/10.96.0.1")
	serviceB := selectionService(t, "demo/svc-b", "/10.96.0.2")
	ownedBefore := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", ""), "agentio-system/egress-a")
	ownedAfter := selectionWithGatewayReference(t,
		selectionWorkload(t, "uid-a", "demo", "node-b", "svc-b", ""), "agentio-system/egress-b")
	remoteBefore := selectionWorkload(t, "uid-b", "demo", "node-b", "svc-b", "")
	remoteAfter := selectionWorkload(t, "uid-b", "demo", "node-a", "svc-a", "")
	before := selectionSnapshot(t, []model.Resource{ownedBefore, remoteBefore, serviceA, serviceB, gatewayA, gatewayB})
	after := selectionSnapshot(t, []model.Resource{ownedAfter, remoteAfter, serviceA, serviceB, gatewayA, gatewayB})
	changes := []model.ResourceChange{
		{Key: ownedBefore.Key, Old: &ownedBefore, New: &ownedAfter},
		{Key: remoteBefore.Key, Old: &remoteBefore, New: &remoteAfter},
	}
	shared := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"}
	dedicated := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		WorkloadUID: "uid-a",
		Source:      ownedBefore.Facts.Workload.Source,
		Principal:   ownedBefore.Facts.Workload.Principal,
	}
	type selectionCase struct {
		name         string
		scope        model.ClientScope
		subscription SubscriptionView
		before       []string
		after        []string
	}
	tests := []selectionCase{
		{
			name:         "shared wildcard",
			scope:        shared,
			subscription: SubscriptionView{wildcard: true},
			before:       []string{"demo/svc-a", "gateway-a", "uid-a"},
			after:        []string{"demo/svc-a", "uid-b"},
		},
		{
			name:   "shared empty named",
			scope:  shared,
			before: []string{"gateway-a", "uid-a"},
			after:  []string{"uid-b"},
		},
		{
			name:         "shared remote workload",
			scope:        shared,
			subscription: SubscriptionView{names: []string{"uid-b"}},
			before:       []string{"gateway-a", "uid-a", "uid-b"},
			after:        []string{"uid-b"},
		},
		{
			name:         "shared remote service alias",
			scope:        shared,
			subscription: SubscriptionView{names: []string{"/10.96.0.2"}},
			before: []string{
				"demo/svc-b",
				"gateway-a",
				"uid-a",
				"uid-b",
			},
			after: []string{"demo/svc-b", "uid-a", "uid-b"},
		},
		{
			name:         "dedicated wildcard",
			scope:        dedicated,
			subscription: SubscriptionView{wildcard: true},
			before:       []string{"demo/svc-a", "gateway-a", "uid-a"},
			after:        []string{"demo/svc-b", "gateway-b", "uid-a"},
		},
		{name: "dedicated empty named", scope: dedicated},
		{
			name:         "dedicated service alias",
			scope:        dedicated,
			subscription: SubscriptionView{names: []string{"/10.96.0.1"}},
			before:       []string{"demo/svc-a", "gateway-a", "uid-a"},
			after:        []string{"gateway-b"},
		},
		{
			name:         "dedicated remote workload",
			scope:        dedicated,
			subscription: SubscriptionView{names: []string{"uid-b"}},
			before:       []string{"gateway-a"},
			after:        []string{"gateway-b"},
		},
	}
	for _, class := range []model.ClientClass{model.ClientEgressGateway, model.ClientAgentioEgress} {
		for _, subscription := range []SubscriptionView{{wildcard: true}, {}, {names: []string{"/10.96.0.2"}}} {
			tests = append(
				tests,
				selectionCase{name: string(class), scope: model.ClientScope{Class: class}, subscription: subscription},
			)
			tc := &tests[len(tests)-1]
			switch {
			case subscription.wildcard:
				tc.name += " wildcard"
				tc.before = []string{"demo/svc-a", "demo/svc-b", "gateway-a", "gateway-b", "uid-a", "uid-b"}
				tc.after = tc.before
			case len(subscription.names) != 0:
				tc.name += " service alias"
				tc.before = []string{"demo/svc-b", "uid-b"}
				tc.after = []string{"demo/svc-b", "uid-a"}
			default:
				tc.name += " empty named"
			}
		}
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := GenerationRequest{
				Scope:        tc.scope,
				TypeURL:      model.AddressType,
				Subscription: tc.subscription,
				Snapshot:     before,
				Full:         true,
			}
			initial, err := (WorkloadGenerator{}).Generate(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if got := selectedNames(initial.Resources); !slices.Equal(got, tc.before) {
				t.Fatalf("initial selection = %v, want %v", got, tc.before)
			}
			request.Snapshot = after
			full, err := (WorkloadGenerator{}).Generate(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if got := selectedNames(full.Resources); !slices.Equal(got, tc.after) {
				t.Fatalf("full selection after transition = %v, want %v", got, tc.after)
			}
			state := make(map[string]string)
			for _, resource := range initial.Resources {
				state[resource.XDSName] = resource.Hash
			}
			if !tc.subscription.wildcard {
				request.Subscription.sent = state
			}
			request.Full = false
			request.Update = updateBetween(before, after, changes)
			delta, err := (WorkloadGenerator{}).Generate(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range delta.Removed {
				delete(state, name)
			}
			for _, resource := range delta.Resources {
				state[resource.XDSName] = resource.Hash
			}
			if len(state) != len(full.Resources) {
				t.Fatalf("incremental state = %v, want resources %v", state, tc.after)
			}
			for _, resource := range full.Resources {
				if state[resource.XDSName] != resource.Hash {
					t.Fatalf("incremental state for %s differs from full generation", resource.XDSName)
				}
			}
		})
	}
}
