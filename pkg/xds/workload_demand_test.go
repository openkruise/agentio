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

	"github.com/openkruise/agentio/pkg/model"
)

func TestWorkloadDemandAliasResendAndMissing(t *testing.T) {
	resource := addressResource(t, "canonical", "pod", "instance/one", "/10.0.0.1")
	snapshot := selectionSnapshot(t, []model.Resource{resource})
	for _, name := range []string{resource.XDSName, "instance/one", "/10.0.0.1", "missing"} {
		t.Run(name, func(t *testing.T) {
			view, ok := demandSubscriptionView(snapshot, model.WorkloadType, []string{name})
			if !ok {
				t.Fatal("unique alias/missing demand did not use incremental selection")
			}
			req := GenerationRequest{
				Scope:           gatewayScope(),
				Snapshot:        snapshot,
				TypeURL:         model.WorkloadType,
				Subscription:    view,
				SubscribedNames: []string{name},
				Full:            true,
			}
			first, err := (WorkloadGenerator{}).Generate(t.Context(), req)
			if err != nil {
				t.Fatal(err)
			}
			if name == "missing" {
				if len(first.Resources) != 0 || !slices.Equal(first.Removed, []string{name}) {
					t.Fatalf("missing demand: %v", first)
				}
				return
			}
			if len(first.Resources) != 1 || first.Resources[0].XDSName != resource.XDSName || len(first.Removed) != 0 {
				t.Fatalf("alias resolved incorrectly: %v", first)
			}
			req.Subscription.sent = map[string]string{resource.XDSName: first.Resources[0].Hash}
			again, err := (WorkloadGenerator{}).Generate(t.Context(), req)
			if err != nil {
				t.Fatal(err)
			}
			if len(again.Resources) != 1 || len(again.Removed) != 0 {
				t.Fatalf("explicit alias resubscribe omitted or removed cached resource: %v", again)
			}
		})
	}
}

func TestWorkloadDemandAmbiguousAliasKeepsFullSelection(t *testing.T) {
	resources := []model.Resource{
		addressResource(t, "one", "one", "shared-ip"),
		addressResource(t, "two", "two", "shared-ip"),
	}
	snapshot := selectionSnapshot(t, resources)
	if _, ok := demandSubscriptionView(snapshot, model.WorkloadType, []string{"shared-ip"}); ok {
		t.Fatal("ambiguous alias entered unique-resource fast path")
	}
	delta, err := (WorkloadGenerator{}).Generate(
		t.Context(),
		GenerationRequest{
			Scope:           gatewayScope(),
			Snapshot:        snapshot,
			TypeURL:         model.WorkloadType,
			Subscription:    SubscriptionView{names: []string{"shared-ip"}},
			SubscribedNames: []string{"shared-ip"},
			Full:            true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 2 || len(delta.Removed) != 0 {
		t.Fatalf("ambiguous alias lost owners: %v", delta)
	}
}

func TestWorkloadEvictionRetainsOtherAliasSubscriptions(t *testing.T) {
	a := addressResource(t, "a", "a", "instance-a", "ip-a")
	a.Key.Name = "storage-a"
	a.Facts.Workload.ServiceKeys = []string{"demo/service"}
	service := selectionService(t, "demo/service", "service-ip")
	b := addressResource(t, "b", "b", "instance-b", "ip-a")
	snapshot := selectionSnapshot(t, []model.Resource{a, b, service})
	projected, err := (WorkloadGenerator{}).projectAddresses([]model.Resource{a})
	if err != nil {
		t.Fatal(err)
	}
	for _, remaining := range []string{"", "a", "storage-a", "ip-a", "demo/service", "service-ip"} {
		keep := remaining != ""
		names := sets.New("instance-b")
		if keep {
			names.Insert(remaining)
		}
		watch := &watchState{names: names, sent: map[string]string{"a": projected[0].Hash}}
		view, ok := demandReconciliationView(
			snapshot,
			model.WorkloadType,
			gatewayScope(),
			watch,
			[]string{"instance-b"},
			[]string{"instance-a"},
		)
		if !ok {
			t.Fatal("cache eviction fell back to full generation")
		}
		delta, err := (WorkloadGenerator{}).Generate(
			t.Context(),
			GenerationRequest{
				Scope:           gatewayScope(),
				Snapshot:        snapshot,
				TypeURL:         model.WorkloadType,
				Subscription:    view,
				SubscribedNames: []string{"instance-b"},
				Full:            true,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(delta.Resources) != 1 || delta.Resources[0].XDSName != "b" {
			t.Fatalf("eviction regenerated unrelated Workload: %v", delta)
		}
		if len(delta.Removed) != 0 {
			t.Fatalf("unsubscribe must not delete a resource: %v", delta)
		}
		if _, retained := watch.sent["a"]; retained != keep {
			t.Fatalf("retained sent state = %t, want %t", retained, keep)
		}
	}
}

func TestWorkloadDemandFullDiffResendsOnlyRequestedResources(t *testing.T) {
	a := addressResource(t, "a", "a", "a-alias", "shared")
	b := addressResource(t, "b", "b", "shared")
	a.Facts.Workload.ServiceKeys = []string{"demo/service"}
	b.Facts.Workload.ServiceKeys = []string{"demo/service"}
	unrelated := addressResource(t, "unrelated", "unrelated")
	snapshot := selectionSnapshot(t, []model.Resource{
		a, b, unrelated,
		selectionService(t, "demo/service", "service-alias"),
		selectionService(t, "demo/empty", "empty-service"),
	})
	projected, err := (WorkloadGenerator{}).projectAddresses([]model.Resource{a, b, unrelated})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		requested []string
		initial   bool
		changed   bool
		want      []string
		removed   []string
	}{
		{
			name:      "initial with missing names",
			initial:   true,
			requested: []string{"service-alias", "missing"},
			want:      []string{"a", "b", "unrelated"},
			removed:   []string{"missing"},
		},
		{name: "ordinary full push"},
		{name: "service resubscribe", requested: []string{"service-alias"}, want: []string{"a", "b"}},
		{name: "shared alias resubscribe", requested: []string{"shared"}, want: []string{"a", "b"}},
		{
			name:      "overlapping requests",
			requested: []string{"a-alias", "a", "shared", "service-alias", "a-alias"},
			want:      []string{"a", "b"},
		},
		{
			name:      "missing and empty service",
			requested: []string{"missing", "empty-service", "gone", "missing"},
			removed:   []string{"empty-service", "gone", "missing"},
		},
		{name: "wildcard with explicit resend", requested: []string{"*", "a-alias"}, want: []string{"a"}},
		{name: "wildcard only", requested: []string{"*"}},
		{
			name:      "changed and explicitly requested",
			requested: []string{"a-alias"},
			changed:   true,
			want:      []string{"a", "b"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			names := sets.New("shared", "unrelated")
			names.InsertAll(tt.requested...)
			sent := make(map[string]string)
			if !tt.initial {
				for _, resource := range projected {
					sent[resource.XDSName] = resource.Hash
				}
				if slices.Contains(tt.requested, "gone") {
					sent["gone"] = "deleted-version"
				}
			}
			if tt.changed {
				sent["b"] = "old-version"
			}
			delta, err := (WorkloadGenerator{}).Generate(t.Context(), GenerationRequest{
				Scope:    gatewayScope(),
				Snapshot: snapshot,
				TypeURL:  model.WorkloadType,
				Subscription: SubscriptionView{
					wildcard: names.Contains("*"),
					names:    sets.SortedList(names),
					sent:     sent,
				},
				SubscribedNames: tt.requested,
				Full:            true,
			})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, resource := range delta.Resources {
				got = append(got, resource.XDSName)
			}
			if !slices.Equal(got, tt.want) || !slices.Equal(delta.Removed, tt.removed) {
				t.Fatalf(
					"resources=%v removed=%v, want resources=%v removed=%v",
					got, delta.Removed, tt.want, tt.removed,
				)
			}
		})
	}
}
