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

	"istio.io/istio/pkg/util/sets"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestAuthorizationSelectionIncludesGlobalNamespaceAndWorkloadSelector(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-a"),
		selectionWorkload(t, "uid-b", "other", "node-b", "", "other/selector-b"),
		selectionAuthorization(t, "agentio-system/global", model.AuthorizationScopeGlobal, ""),
		selectionAuthorization(t, "demo/namespace", model.AuthorizationScopeNamespace, "demo"),
		selectionAuthorization(t, "other/namespace", model.AuthorizationScopeNamespace, "other"),
		selectionAuthorization(t, "demo/selector-a", model.AuthorizationScopeWorkload, ""),
		selectionAuthorization(t, "other/selector-b", model.AuthorizationScopeWorkload, ""),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   model.MustServiceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}

	got := selectAuthorizationResources(scope, snapshot, nil)
	want := []string{"agentio-system/global", "demo/namespace", "demo/selector-a"}
	if names := selectedNames(got); !slices.Equal(names, want) {
		t.Fatalf("selected authorizations = %v, want %v", names, want)
	}
}

func TestNodeAuthorizationSelectionUsesLocalWorkloadFacts(t *testing.T) {
	resources := []model.Resource{
		selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-a"),
		selectionWorkload(t, "uid-b", "other", "node-a", "", "other/selector-b"),
		selectionWorkload(t, "uid-c", "remote", "node-b", "", "remote/selector-c"),
		selectionAuthorization(t, "agentio-system/global", model.AuthorizationScopeGlobal, ""),
		selectionAuthorization(t, "demo/namespace", model.AuthorizationScopeNamespace, "demo"),
		selectionAuthorization(t, "other/namespace", model.AuthorizationScopeNamespace, "other"),
		selectionAuthorization(t, "remote/namespace", model.AuthorizationScopeNamespace, "remote"),
		selectionAuthorization(t, "demo/selector-a", model.AuthorizationScopeWorkload, ""),
		selectionAuthorization(t, "other/selector-b", model.AuthorizationScopeWorkload, ""),
		selectionAuthorization(t, "remote/selector-c", model.AuthorizationScopeWorkload, ""),
	}
	snapshot := selectionSnapshot(t, resources)
	scope := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: model.MustServiceAccountPrincipal("agentio-system", "ztunnel"),
		NodeName:  "node-a",
	}

	got := selectAuthorizationResources(scope, snapshot, nil)
	want := []string{
		"agentio-system/global", "demo/namespace", "demo/selector-a", "other/namespace", "other/selector-b",
	}
	if names := selectedNames(got); !slices.Equal(names, want) {
		t.Fatalf("selected node authorizations = %v, want %v", names, want)
	}
}

func TestGatewayNamedAuthorizationSelectionDoesNotAllocateSnapshotScale(t *testing.T) {
	const resourceCount = 10_000
	const runs = 10
	var before, after runtime.MemStats
	var selected []model.Resource
	authorizationValue := mustWireAny(model.WorkloadAuthorizationType, &securityv1.Authorization{Name: "policy"})
	authorizations := make([]model.Resource, 0, resourceCount+1)
	for i := range resourceCount {
		name := fmt.Sprintf("unrelated-policy-%06d", i)
		authorizations = append(authorizations, model.Resource{
			Key:     model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: name},
			XDSName: name,
			Value:   authorizationValue,
			Hash:    name,
			Facts:   model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{Scope: model.AuthorizationScopeWorkload}},
		})
	}
	target := selectionAuthorization(t, "demo/target", model.AuthorizationScopeWorkload, "")
	authorizations = append(authorizations, target, selectionWorkload(t, "target-workload", "demo", "node-a", "", target.XDSName))
	authorizationSnapshot := selectionSnapshot(t, authorizations)
	runtime.GC()
	runtime.ReadMemStats(&before)
	allocations := testing.AllocsPerRun(runs, func() {
		selected = selectAuthorizationResources(gatewayScope(), authorizationSnapshot, []string{target.XDSName})
	})
	runtime.ReadMemStats(&after)
	if names := selectedNames(selected); !slices.Equal(names, []string{target.XDSName}) {
		t.Fatalf("selected authorizations = %v, want target only", names)
	}
	if allocations > 32 {
		t.Fatalf("named gateway authorization allocations = %.1f/run, want <= 32", allocations)
	}
	if bytesPerRun := (after.TotalAlloc - before.TotalAlloc) / runs; bytesPerRun > 64<<10 {
		t.Fatalf("named gateway authorization allocated %d bytes/run, want <= %d", bytesPerRun, 64<<10)
	}
}

func TestUnrelatedWorkloadAddressChangeDoesNotReconcileAuthorization(t *testing.T) {
	owned := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/selector-a")
	oldUnrelated := selectionWorkload(t, "uid-b", "other", "node-b", "", "other/selector-b")
	newUnrelated := selectionWorkload(t, "uid-b", "other", "node-b", "svc-b", "other/selector-b")
	before := selectionSnapshot(t, []model.Resource{owned, oldUnrelated})
	after := selectionSnapshot(t, []model.Resource{owned, newUnrelated})
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: oldUnrelated.Key,
		Old: &oldUnrelated,
		New: &newUnrelated,
	}})
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   model.MustServiceAccountPrincipal("demo", "default"),
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}

	delta, err := (AuthorizationGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.WorkloadAuthorizationType,
		Subscription: SubscriptionView{wildcard: true},
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

func TestGatewayAuthorizationIncrementalAllowsNonGlobalPolicy(t *testing.T) {
	oldResource := selectionAuthorization(t, "demo/selector-a", model.AuthorizationScopeWorkload, "")
	newResource, err := model.NewResource(
		oldResource.Key, oldResource.XDSName,
		mustWireAny(model.WorkloadAuthorizationType, &securityv1.Authorization{Name: "selector-a", Namespace: "demo"}),
		oldResource.Aliases, oldResource.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := selectionAuthorization(t, "other/selector-b", model.AuthorizationScopeWorkload, "")
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
	view := newIncrementalSubscriptionView(watch, model.WorkloadAuthorizationType, update)
	if names := view.SentNames(); !slices.Equal(names, []string{oldResource.XDSName}) {
		t.Fatalf("gateway incremental sent-state = %v, want only changed authorization", names)
	}

	delta, err := (AuthorizationGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        gatewayScope(),
		TypeURL:      model.WorkloadAuthorizationType,
		Subscription: view,
		Snapshot:     snapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if names := selectedNames(delta.Resources); !slices.Equal(names, []string{"demo/selector-a"}) {
		t.Fatalf("incremental gateway authorizations = %v, want updated selector policy", names)
	}
}

func TestAuthorizationPolicyOnlyDeltaKeepsRenameAndRemovalSemantics(t *testing.T) {
	oldPolicy := selectionAuthorization(t, "demo/policy", model.AuthorizationScopeWorkload, "")
	newPolicy, err := model.NewResource(
		oldPolicy.Key,
		"demo/renamed",
		oldPolicy.Value,
		[]string{"demo/alias"},
		oldPolicy.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	workload := selectionWorkload(t, "uid-a", "demo", "node-a", "", oldPolicy.Key.Name)
	before := selectionSnapshot(t, []model.Resource{workload, oldPolicy})
	after := selectionSnapshot(t, []model.Resource{workload, newPolicy})
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		Principal:   workload.Facts.Workload.Principal,
		WorkloadUID: "uid-a",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
	}
	for _, tc := range []struct {
		name                     string
		names, selected, removed []string
	}{
		{"wildcard", nil, []string{"demo/renamed"}, []string{"demo/policy"}},
		{"old-name", []string{"demo/policy"}, nil, []string{"demo/policy"}},
		{"new-alias", []string{"demo/alias"}, []string{"demo/renamed"}, nil},
		{"unrelated", []string{"demo/unrelated"}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delta := generateAuthorizationIncremental(
				GenerationRequest{
					Scope:   scope,
					TypeURL: model.WorkloadAuthorizationType,
					Subscription: initializedSubscription(
						t,
						AuthorizationGenerator{},
						scope,
						model.WorkloadAuthorizationType,
						before,
						SubscriptionView{wildcard: tc.names == nil, names: tc.names},
					),
					Snapshot: after,
					Update:   updateBetween(before, after, before.Diff(after)),
				},
			)
			if !slices.Equal(selectedNames(delta.Resources), tc.selected) ||
				!slices.Equal(delta.Removed, tc.removed) {
				t.Fatalf(
					"delta resources=%v removed=%v, want resources=%v removed=%v",
					selectedNames(delta.Resources),
					delta.Removed,
					tc.selected,
					tc.removed,
				)
			}
		})
	}
	empty := selectionSnapshot(t, []model.Resource{workload})
	deleted := generateAuthorizationIncremental(
		GenerationRequest{
			Scope:   scope,
			TypeURL: model.WorkloadAuthorizationType,
			Subscription: initializedSubscription(
				t,
				AuthorizationGenerator{},
				scope,
				model.WorkloadAuthorizationType,
				after,
				SubscriptionView{wildcard: true},
			),
			Snapshot: empty,
			Update:   updateBetween(after, empty, after.Diff(empty)),
		},
	)
	if len(deleted.Resources) != 0 || !slices.Equal(deleted.Removed, []string{"demo/renamed"}) {
		t.Fatalf("delete = %#v", deleted)
	}
}

func TestOpaquePrincipalKeepsSourceNamespacePolicySelection(t *testing.T) {
	workload := selectionWorkload(t, "opaque", "demo", "node-a", "", "")
	workload.Facts.Workload.Principal = model.MustPrincipal("cluster.local", "workload/app")
	if got := workloadNamespaces([]model.Resource{workload}); !got.Contains("demo") {
		t.Fatalf("source namespace lost for opaque principal: %v", got)
	}
}
