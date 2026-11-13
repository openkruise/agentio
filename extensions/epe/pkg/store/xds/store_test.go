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
	"maps"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/store"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

type fakeSource struct {
	snapshot xdsclient.Snapshot
	demand   func(string)
	demands  int
	reads    int
	changed  chan struct{}
}

func (f *fakeSource) Snapshot() xdsclient.Snapshot {
	f.reads++
	result := xdsclient.Snapshot{
		Changed:   f.snapshot.Changed,
		Synced:    map[string]bool{},
		InGrace:   maps.Clone(f.snapshot.InGrace),
		Resources: map[string]map[string]*xdsclient.Resource{},
	}
	for typ, resources := range f.snapshot.Resources {
		result.Resources[typ] = maps.Clone(resources)
	}
	maps.Copy(result.Synced, f.snapshot.Synced)
	return result
}

func (f *fakeSource) Demand(_ context.Context, typ, name string) (*xdsclient.Resource, error) {
	f.demands++
	if f.demand != nil {
		f.demand(name)
	}
	v := f.snapshot.Resources[typ][name]
	if v == nil {
		return nil, xdsclient.ErrNotFound
	}
	return v, nil
}

func packed(m proto.Message) *anypb.Any {
	v, err := anypb.New(m)
	if err != nil {
		panic(err)
	}
	return v
}

func published(m proto.Message) *xdsclient.Resource {
	return &xdsclient.Resource{Value: m}
}

func testSource() *fakeSource {
	w := &workload.Workload{
		Uid:       "uid",
		Name:      "pod",
		Namespace: "ns",
		Addresses: [][]byte{{192, 0, 2, 1}},
		Extensions: []*workload.Extension{
			{
				Name: "security-profile-reference",
				Config: packed(
					&ext.PolicyReference{
						TypeUrl:   model.SecurityProfileType,
						Resources: []*ext.PolicyResourceReference{{Name: "allow"}},
					},
				),
			},
		},
	}
	return &fakeSource{
		snapshot: xdsclient.Snapshot{
			Synced: map[string]bool{model.WorkloadType: true},
			Resources: map[string]map[string]*xdsclient.Resource{
				model.WorkloadType: {
					"uid": published(w),
				},
			},
		},
	}
}

func (f *fakeSource) notify() {
	if f.changed != nil {
		close(f.changed)
	}
	f.changed = make(chan struct{})
	f.snapshot.Changed = f.changed
}

func (f *fakeSource) Observe(types ...string) (<-chan struct{}, bool) {
	for _, typ := range types {
		if !f.snapshot.Usable(typ) {
			return f.snapshot.Changed, false
		}
	}
	return f.snapshot.Changed, true
}

func TestReconnectGracePublicationAndExpiry(t *testing.T) {
	f := testSource()
	f.notify()
	s := New(f)
	before := s.Read()
	f.snapshot.Synced = map[string]bool{}
	f.snapshot.InGrace = map[string]bool{model.WorkloadType: true}
	f.notify()
	during := s.Read()
	if !during.Ready || during.Status != s.Status() {
		t.Fatal("retained resource set became unavailable during grace")
	}
	for _, typ := range s.Types() {
		if during.Snapshots[typ] != before.Snapshots[typ] {
			t.Fatal("disconnect rebuilt unchanged resources")
		}
	}
	keys := []store.Key{{Type: store.Workload, Name: "uid"}}
	if !s.ReadKeys(keys).Ready {
		t.Fatal("selected request rejected usable grace values")
	}
	f.snapshot.InGrace = nil
	f.notify()
	after := s.Read()
	if after.Ready || s.Status().Ready || s.ReadKeys(keys).Ready {
		t.Fatal("expired source remained available")
	}
	if _, err := after.Snapshots[store.Workload].Get("uid"); err == nil {
		t.Fatal("published snapshot served expired Workload")
	}
}

func TestTrafficPolicyNotConsumed(t *testing.T) {
	f := testSource()
	f.snapshot.Synced[model.TrafficPolicyType] = false
	f.notify()
	s := New(f)
	if types := s.Types(); len(types) != 1 || types[0] != store.Workload {
		t.Fatalf("unexpected resource types: %v", types)
	}
	batch := s.ReadKeys([]store.Key{{Type: store.Workload, Name: "uid"}})
	if !batch.Ready || !s.Status().Ready {
		t.Fatal("TrafficPolicy synchronization affected Workload availability")
	}
	if _, found := batch.Snapshots[store.Type("TrafficPolicy")]; found {
		t.Fatal("TrafficPolicy snapshot was published")
	}
	resource, release, err := s.Acquire(t.Context(), store.Key{Type: store.Type("TrafficPolicy"), Name: "deny"})
	if err != nil || resource != nil || release != nil || f.demands != 0 {
		t.Fatalf("TrafficPolicy was consumed: resource=%v err=%v demands=%d", resource, err, f.demands)
	}
}

func TestResourceQueriesAndFetch(t *testing.T) {
	f := testSource()
	f.notify()
	s := New(f)
	before := s.Read()
	workloads, err := before.Snapshots[store.Workload].List()
	if err != nil || len(workloads) != 1 || workloads[0].Value.(*workload.Workload).Name != "pod" {
		t.Fatalf("workloads: %v %v", workloads, err)
	}
	key := store.Key{Type: store.Workload, Name: "uid"}
	first, err := s.Read().Snapshots[key.Type].Get(key.Name)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot.Resources[model.WorkloadType]["uid"] = published(&workload.Workload{Uid: "uid", Name: "updated"})
	f.notify()
	select {
	case <-before.Changed:
	default:
		t.Fatal("batch missed update notification")
	}
	if s.Read().Status != s.Status() {
		t.Fatal("batch and status disagree")
	}
	updated, err := s.Read().Snapshots[key.Type].Get(key.Name)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Value.(*workload.Workload).Name != "updated" ||
		first.Value.(*workload.Workload).Name != "pod" {
		t.Fatal("update or snapshot ownership incorrect")
	}
	delete(f.snapshot.Resources[model.WorkloadType], "uid")
	f.notify()
	if resource, err := s.Read().Snapshots[key.Type].Get(key.Name); err != nil || resource != nil || f.demands != 0 {
		t.Fatal("Get must not fetch", resource, err)
	}
	if resource, err := s.Fetch(t.Context(), key); err != nil || resource != nil || f.demands != 1 {
		t.Fatal("not-found fetch", resource, err)
	}
	f.demand = func(name string) {
		f.snapshot.Resources[model.WorkloadType][name] = published(&workload.Workload{Uid: name})
		f.notify()
	}
	if resource, err := s.Fetch(t.Context(), key); err != nil || resource == nil {
		t.Fatal("fetch did not retrieve resource", err)
	}
	f.snapshot.Synced[model.WorkloadType] = false
	f.notify()
	if _, err := s.Read().Snapshots[key.Type].Get(key.Name); err == nil {
		t.Fatal("unsynced resource served")
	}
	if s.Status().Ready {
		t.Fatal("unsynced backend ready")
	}
}

func TestReadReusesUnchangedTypeSnapshots(t *testing.T) {
	f := testSource()
	f.notify()
	s := New(f)
	before := s.Read()
	unchanged := s.Read()
	if f.reads != 1 || unchanged.Changed != before.Changed {
		t.Fatal("unchanged publication copied again")
	}
	f.notify()
	after := s.Read()
	if f.reads != 2 || after.Changed == before.Changed ||
		before.Snapshots[store.Workload] != after.Snapshots[store.Workload] {
		t.Fatal("unchanged Workload snapshot was rebuilt")
	}
	f.snapshot.Synced[model.WorkloadType] = false
	f.notify()
	unavailable := s.Read()
	if unavailable.Ready {
		t.Fatal("readiness change lost")
	}
	if _, err := unavailable.Snapshots[store.Workload].List(); err == nil {
		t.Fatal("unsynced type served")
	}
	f.snapshot.Synced[model.WorkloadType] = true
	f.notify()
	recovered := s.Read()
	if !recovered.Ready {
		t.Fatal("readiness recovery lost")
	}
	if resources, err := recovered.Snapshots[store.Workload].List(); err != nil || len(resources) != 1 {
		t.Fatal(resources, err)
	}
}

func TestReadReusesResourcesWithinChangedType(t *testing.T) {
	f := testSource()
	f.snapshot.Resources[model.WorkloadType]["other"] = published(&workload.Workload{Uid: "other", Name: "other"})
	f.notify()
	s := New(f)
	a := store.NewAggregate(s)
	before := a.Snapshot()
	unchanged, err := before.Get(store.Key{Type: store.Workload, Name: "uid"})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := before.Get(store.Key{Type: store.Workload, Name: "other"})
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot.Resources[model.WorkloadType]["other"] = published(&workload.Workload{Uid: "other", Name: "updated"})
	f.notify()
	batch := s.Read()
	current, err := batch.Snapshots[store.Workload].Get("uid")
	if err != nil || current != unchanged {
		t.Fatal("unchanged resource was decoded/replaced", err)
	}
	a.Refresh()
	if a.Snapshot().Type(store.Workload) != batch.Snapshots[store.Workload] {
		t.Fatal("single source snapshot rebuilt")
	}
	updated, err := a.Get(store.Key{Type: store.Workload, Name: "other"})
	if err != nil || updated == changed || updated.Value.(*workload.Workload).Name != "updated" {
		t.Fatal(updated, err)
	}
	if changed.Value.(*workload.Workload).Name != "other" {
		t.Fatal("old snapshot mutated")
	}
	delete(f.snapshot.Resources[model.WorkloadType], "other")
	f.notify()
	a.Refresh()
	if r, err := a.Get(store.Key{Type: store.Workload, Name: "other"}); err != nil || r != nil {
		t.Fatal("removed resource retained", r, err)
	}
	if r, err := a.Get(store.Key{Type: store.Workload, Name: "uid"}); err != nil || r != unchanged {
		t.Fatal("deletion replaced unrelated resource", err)
	}
}

func TestWatchTransforms(t *testing.T) {
	if watches := Watches(); len(watches) != 1 || watches[0].TypeURL != model.WorkloadType {
		t.Fatalf("EPE must discover only Workloads: %v", watches)
	}
	for _, watch := range Watches() {
		t.Run(watch.TypeURL, func(t *testing.T) {
			var message proto.Message = &workload.Workload{Uid: "uid", Name: "pod"}
			value, err := watch.Transform(packed(message))
			if err != nil || !proto.Equal(value.(proto.Message), message) {
				t.Fatalf("transform: %v %v", value, err)
			}
			if _, err := watch.Transform(&anypb.Any{TypeUrl: watch.TypeURL, Value: []byte{0xff}}); err == nil {
				t.Fatal("malformed resource accepted")
			}
			if watch.Wildcard || watch.OnDelete("uid") != xdsclient.ReleaseSubscription {
				t.Fatal("must use named watches and release deleted demands")
			}
		})
	}
}

func TestSelectedSnapshotOwnershipAndList(t *testing.T) {
	f := testSource()
	f.snapshot.Resources[model.WorkloadType]["other"] = published(&workload.Workload{Uid: "other", Name: "before"})
	s := New(f)
	keys := []store.Key{
		{Type: store.Workload, Name: "uid"},
		{Type: store.Workload, Name: "other"},
		{Type: store.Workload, Name: "uid"},
	}
	before := s.ReadKeys(keys)
	view := before.Snapshots[store.Workload]
	values, err := view.List()
	if err != nil || len(values) != 2 || values[0].Key.Name != "other" || values[1].Key.Name != "uid" {
		t.Fatalf("selected list: %v, %v", values, err)
	}
	old, err := view.Get("other")
	if err != nil {
		t.Fatal(err)
	}
	again, err := view.Get("other")
	if err != nil {
		t.Fatal(err)
	}
	if old != again {
		t.Fatal("resource identity changed within one snapshot")
	}
	f.snapshot.Resources[model.WorkloadType]["other"] = published(&workload.Workload{Uid: "other", Name: "after"})
	delete(f.snapshot.Resources[model.WorkloadType], "uid")
	after := s.ReadKeys(keys)
	updated, err := after.Snapshots[store.Workload].Get("other")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Value.(*workload.Workload).Name != "after" || old.Value.(*workload.Workload).Name != "before" {
		t.Fatal("update mutated a selected publication")
	}
	if value, err := after.Snapshots[store.Workload].Get("uid"); value != nil || err != nil {
		t.Fatal("deleted selected resource retained", value, err)
	}
	if value, err := view.Get("uid"); value == nil || err != nil {
		t.Fatal("deletion mutated old publication", value, err)
	}
}
