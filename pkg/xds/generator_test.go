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

// Mixed cached, changed, and absent resources must retain explicit resubscribe
// semantics, including duplicate names and names already in the ordinary diff.
func TestDiffSubscribedResendsWithoutDuplicates(t *testing.T) {
	selected := map[string]model.Resource{
		"changed": {XDSName: "changed", Hash: "new"},
		"cached":  {XDSName: "cached", Hash: "same"},
		"new":     {XDSName: "new", Hash: "new"},
		"quiet":   {XDSName: "quiet", Hash: "same"},
	}
	sub := SubscriptionView{sent: map[string]string{
		"changed": "old",
		"cached":  "same",
		"quiet":   "same",
		"deleted": "old",
	}}
	for _, tc := range []struct {
		name          string
		requested     []string
		wantResources []string
		wantRemoved   []string
	}{
		{"ordinary diff", nil, []string{"changed", "new"}, []string{"deleted"}},
		{"explicit replay", []string{"new", "cached", "cached", "changed", "deleted", "deleted", "missing", "missing", "*"}, []string{"changed", "new", "cached"}, []string{"deleted", "missing"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := diffSubscribed(sub, selected, tc.requested)
			names := make([]string, len(got.Resources))
			for i, r := range got.Resources {
				names[i] = r.XDSName
				if r.Hash != selected[r.XDSName].Hash {
					t.Fatalf("stale resource: %+v", r)
				}
			}
			if !slices.Equal(names, tc.wantResources) || !slices.Equal(got.Removed, tc.wantRemoved) {
				t.Fatalf(
					"resources=%v removed=%v; want resources=%v removed=%v",
					names,
					got.Removed,
					tc.wantResources,
					tc.wantRemoved,
				)
			}
		})
	}
}
