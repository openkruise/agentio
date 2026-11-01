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

func TestGatewayIndexedSelectionPreservesNamesAndScope(t *testing.T) {
	own := gatewayResource(t, "demo/egress", "shared", "own")
	var err error
	own, err = model.NewResource(own.Key, own.XDSName, own.Value, []string{"alias"}, own.Facts)
	if err != nil {
		t.Fatal(err)
	}
	other := gatewayResource(t, "demo/other", "shared", "other")
	snapshot := selectionSnapshot(t, []model.Resource{own, other})
	for _, names := range [][]string{nil, {"shared"}, {"alias"}, {own.Key.Name}, {"alias", "shared", own.Key.Name}} {
		got := selectGeneric(gatewayScope(), snapshot, model.ClusterType, names)
		if len(got) != 1 || got[0].Key != own.Key {
			t.Fatalf("names=%v selected=%v, want only own resource", names, got)
		}
	}
	for _, names := range [][]string{{}, {other.Key.Name}, {"missing"}} {
		if got := selectGeneric(gatewayScope(), snapshot, model.ClusterType, names); len(got) != 0 {
			t.Fatalf("names=%v selected=%v, want empty", names, got)
		}
	}
}

func TestGatewayIncrementalOwnerChangeWithdrawsOldScope(t *testing.T) {
	old := gatewayResource(t, "demo/egress", "shared", "before")
	other := gatewayResource(t, "demo/other", "shared", "after")
	// Retain the storage key: visibility must use the old identity's facts.
	next, err := model.NewResource(old.Key, other.XDSName, other.Value, nil, other.Facts)
	if err != nil {
		t.Fatal(err)
	}
	before := selectionSnapshot(t, []model.Resource{old})
	after := selectionSnapshot(t, []model.Resource{next})
	for _, owner := range []string{"demo/egress", "demo/other"} {
		scope := gatewayScope()
		scope.GatewayKey = owner
		sent := map[string]string{}
		if owner == "demo/egress" {
			sent[old.XDSName] = old.Hash
		}
		delta, err := (SnapshotGenerator{}).Generate(t.Context(), GenerationRequest{
			Scope:        scope,
			Snapshot:     after,
			TypeURL:      model.ClusterType,
			Subscription: SubscriptionView{wildcard: true, sent: sent},
			Update:       updateBetween(before, after, before.Diff(after)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if owner == "demo/egress" {
			if len(delta.Resources) != 0 || !slices.Equal(delta.Removed, []string{"shared"}) {
				t.Fatalf("old owner retained resource: %+v", delta)
			}
		} else if len(delta.Resources) != 1 || delta.Resources[0].Hash != next.Hash || len(delta.Removed) != 0 {
			t.Fatalf("new owner did not receive resource: %+v", delta)
		}
	}
}
