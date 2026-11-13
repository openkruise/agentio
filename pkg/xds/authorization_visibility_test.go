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

	"github.com/openkruise/agentio/pkg/model"
)

func TestAuthorizationVisibilityUsesScopedIdentityAndExactReferences(t *testing.T) {
	workload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/exact")
	global := selectionAuthorization(t, "agentio-system/global", model.AuthorizationScopeGlobal, "")
	namespace := selectionAuthorization(t, "demo/namespace", model.AuthorizationScopeNamespace, "demo")
	exact := selectionAuthorization(t, "demo/exact", model.AuthorizationScopeWorkload, "")
	unrelated := selectionAuthorization(t, "other/unrelated", model.AuthorizationScopeNamespace, "other")
	visibility := newAuthorizationVisibility(
		model.ClientScope{
			Class:       model.ClientDedicatedZTunnel,
			Principal:   model.MustServiceAccountPrincipal("demo", "default"),
			WorkloadUID: "uid-a",
			Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
		},
		selectionSnapshot(t, []model.Resource{workload, global, namespace, exact, unrelated}),
	)

	for _, resource := range []model.Resource{global, namespace, exact} {
		if !visibility.visible(resource) {
			t.Errorf("authorization %q is not visible", resource.XDSName)
		}
	}
	if visibility.visible(unrelated) {
		t.Fatalf("unrelated authorization %q is visible", unrelated.XDSName)
	}
}

func TestAuthorizationIncrementalDiffsExactReferenceTransition(t *testing.T) {
	oldWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/old")
	newWorkload := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/new")
	oldPolicy := selectionAuthorization(t, "demo/old", model.AuthorizationScopeWorkload, "")
	newPolicy := selectionAuthorization(t, "demo/new", model.AuthorizationScopeWorkload, "")
	before := selectionSnapshot(t, []model.Resource{oldWorkload, oldPolicy, newPolicy})
	after := selectionSnapshot(t, []model.Resource{newWorkload, oldPolicy, newPolicy})
	request := GenerationRequest{
		Scope: model.ClientScope{
			Class:       model.ClientDedicatedZTunnel,
			Principal:   model.MustServiceAccountPrincipal("demo", "default"),
			WorkloadUID: "uid-a",
			Source:      model.SourceRef{Registry: "kubernetes/test", Key: "uid-a"},
		},
		TypeURL:      model.WorkloadAuthorizationType,
		Subscription: SubscriptionView{wildcard: true, sent: map[string]string{oldPolicy.XDSName: oldPolicy.Hash}},
		Snapshot:     after,
		Update: updateBetween(before, after, []model.ResourceChange{{
			Key: oldWorkload.Key,
			Old: &oldWorkload,
			New: &newWorkload,
		}}),
	}

	delta := generateAuthorizationIncremental(request)
	if got, want := selectedNames(delta.Resources), []string{"demo/new"}; !slices.Equal(got, want) {
		t.Fatalf("Authorization resources = %v, want %v", got, want)
	}
	if got, want := delta.Removed, []string{"demo/old"}; !slices.Equal(got, want) {
		t.Fatalf("Authorization removals = %v, want %v", got, want)
	}
}

func TestAuthorizationIncludesBaselinesWithoutWorkloadReferences(t *testing.T) {
	host := selectionWorkload(t, "host", "demo", "node-a", "", "")
	global := selectionAuthorization(t, "global", model.AuthorizationScopeGlobal, "")
	namespace := selectionAuthorization(t, "demo/baseline", model.AuthorizationScopeNamespace, "demo")
	unbound := selectionAuthorization(t, "demo/unbound", model.AuthorizationScopeWorkload, "")
	unrelated := selectionAuthorization(t, "other/baseline", model.AuthorizationScopeNamespace, "other")
	before := selectionSnapshot(t, []model.Resource{host, global, namespace, unbound, unrelated})
	after := selectionSnapshot(t, []model.Resource{global, namespace, unbound, unrelated})
	for _, scope := range []model.ClientScope{
		{Class: model.ClientDedicatedZTunnel, WorkloadUID: "host", Source: model.SourceRef{Registry: "kubernetes/test", Key: "host"}, Principal: host.Facts.Workload.Principal},
		{Class: model.ClientSharedZTunnel, NodeName: "node-a"},
	} {
		want := []string{"demo/baseline", "global"}
		for _, names := range [][]string{nil, {"demo/baseline", "demo/unbound", "global", "other/baseline"}} {
			if got := selectedNames(selectAuthorizationResources(scope, before, names)); !slices.Equal(got, want) {
				t.Fatalf("scope %+v: got %v, want %v", scope, got, want)
			}
			delta := generateAuthorizationIncremental(GenerationRequest{
				Scope:   scope,
				TypeURL: model.WorkloadAuthorizationType,
				Subscription: initializedSubscription(
					t,
					AuthorizationGenerator{},
					scope,
					model.WorkloadAuthorizationType,
					before,
					SubscriptionView{wildcard: names == nil, names: names},
				),
				Snapshot: after,
				Update:   updateBetween(before, after, before.Diff(after)),
			})
			if len(delta.Resources) != 0 || !slices.Equal(delta.Removed, want) {
				t.Fatalf("removed last workload: %+v", delta)
			}
		}
		updated, err := model.NewResource(
			global.Key,
			"",
			testResourceContents(testResourceValue(global)),
			[]string{"updated"},
			global.Facts,
		)
		if err != nil {
			t.Fatal(err)
		}
		latest, _, err := before.Apply([]model.ResourceChange{{Key: global.Key, Old: &global, New: &updated}})
		if err != nil {
			t.Fatal(err)
		}
		delta := generateAuthorizationIncremental(GenerationRequest{
			Scope:        scope,
			TypeURL:      model.WorkloadAuthorizationType,
			Subscription: SubscriptionView{wildcard: true},
			Snapshot:     latest,
			Update:       updateBetween(before, latest, before.Diff(latest)),
		})
		if !slices.Equal(selectedNames(delta.Resources), []string{"global"}) {
			t.Fatalf("baseline update was not delivered: %+v", delta)
		}
	}
}

func TestSandboxHostExplicitAuthorizationVisibility(t *testing.T) {
	host := selectionWorkload(t, "host", "demo", "node-a", "", "demo/compat")
	facts := *host.Facts.Workload
	compat := selectionAuthorization(t, "demo/compat", model.AuthorizationScopeWorkload, "")
	unrelated := selectionAuthorization(t, "demo/unrelated", model.AuthorizationScopeWorkload, "")
	scope := model.ClientScope{
		Class:       model.ClientDedicatedZTunnel,
		WorkloadUID: "host",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: "host"},
		Principal:   facts.Principal,
	}
	before := selectionSnapshot(t, []model.Resource{host, compat, unrelated})
	if got := selectedNames(
		selectAuthorizationResources(scope, before, nil),
	); !slices.Equal(
		got,
		[]string{compat.Key.Name},
	) {
		t.Fatalf("compatibility visibility = %v", got)
	}
	facts.AuthorizationRefs = nil
	host, err := model.NewResource(
		host.Key,
		host.XDSName,
		testResourceContents(testResourceValue(host)),
		host.Aliases,
		model.ResourceFacts{Workload: &facts},
	)
	if err != nil {
		t.Fatal(err)
	}
	after := selectionSnapshot(t, []model.Resource{host, compat, unrelated})
	delta, err := (AuthorizationGenerator{}).Generate(t.Context(), GenerationRequest{
		Scope:        scope,
		TypeURL:      model.WorkloadAuthorizationType,
		Snapshot:     after,
		Update:       updateBetween(before, after, before.Diff(after)),
		Subscription: SubscriptionView{wildcard: true, sent: map[string]string{compat.Key.Name: compat.Hash}},
	})
	if err != nil || !slices.Equal(delta.Removed, []string{compat.Key.Name}) {
		t.Fatalf("lost binding: delta=%v err=%v", delta, err)
	}
}
