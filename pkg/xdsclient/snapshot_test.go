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

package xdsclient

import (
	"testing"
	"time"
)

func TestSnapshotForPinsOnlySelectedValuesAndReadiness(t *testing.T) {
	policyType := testType + "/policy"
	w, p := &Resource{Value: "workload"}, &Resource{Value: "policy"}
	c := &Client{connected: true,
		changed: make(chan struct{}),
		types: map[string]*typeState{
			testType:   {synced: true, resources: map[string]*Resource{"wanted": w, "unrelated": {Value: "unused"}}},
			policyType: {synced: true, resources: map[string]*Resource{"policy": p}},
		}}
	selected := map[string][]string{testType: {"wanted", "missing"}, policyType: {"policy"}}
	view := c.SnapshotFor(selected)
	if !view.Connected || !view.Synced[testType] || !view.Synced[policyType] ||
		len(
			view.Resources[testType],
		) != 1 || view.Resources[testType]["wanted"] != w || view.Resources[policyType]["policy"] != p {
		t.Fatalf("incorrect selected publication: %+v", view)
	}
	c.types[testType].resources["wanted"] = &Resource{Value: "updated"}
	if view.Resources[testType]["wanted"] != w {
		t.Fatal("selected snapshot mutated with the source")
	}
	if len(c.Snapshot().Resources[testType]) != 2 ||
		len(c.SnapshotFor(map[string][]string{}).Resources[testType]) != 0 {
		t.Fatal("full and empty selection semantics changed")
	}
	c.reset()
	current := c.SnapshotFor(selected)
	if current.Connected || current.Synced[testType] || current.Synced[policyType] ||
		len(current.Resources[testType]) != 1 {
		t.Fatal("disconnect lost retained values or kept stale synchronization")
	}
	select {
	case <-view.Changed:
	default:
		t.Fatal("selected view missed source invalidation")
	}
	if !view.Connected || !view.Synced[testType] {
		t.Fatal("old synchronization state mutated")
	}
}

func TestLookupResourceCanonicalNameAndGrace(t *testing.T) {
	old := &Resource{Value: "policy"}
	st := &typeState{
		synced:    true,
		resources: map[string]*Resource{"global/policy": old},
		aliases:   map[string]string{"alias": "global/policy"},
	}
	c := &Client{changed: make(chan struct{}), types: map[string]*typeState{testType: st}}
	channel := c.changed
	if v, changed, ready := c.LookupResource(testType, "global/policy"); v != old || changed != channel || !ready {
		t.Fatal("canonical read did not capture the current publication")
	}
	if v, _, ready := c.LookupResource(testType, "alias"); v != nil || !ready {
		t.Fatal("alias treated as a canonical resource")
	}
	st.synced, st.epoch = false, 1
	st.graceUntil = time.Now().Add(time.Minute)
	st.graceTimer = time.NewTimer(time.Hour)
	defer st.graceTimer.Stop()
	if v, _, ready := c.LookupResource(testType, "global/policy"); v != old || !ready {
		t.Fatal("usable resource lost during reconnect grace")
	}
	st.graceUntil = time.Now().Add(-time.Second)
	if v, changed, ready := c.LookupResource(testType, "global/policy"); v != nil || changed == channel || ready {
		t.Fatal("expired publication accepted")
	}
}
