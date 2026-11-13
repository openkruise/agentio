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

package workload

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/model"
)

func TestWorkloadSecurityProfileBinding(t *testing.T) {
	pack := func(name string, value proto.Message) *workload.Extension {
		v, err := anypb.New(value)
		if err != nil {
			t.Fatal(err)
		}
		return &workload.Extension{Name: name, Config: v}
	}
	w := &workload.Workload{Uid: "uid",
		Namespace: "ns",
		Name:      "pod",
		Extensions: []*workload.Extension{
			pack(
				"security-profile-reference",
				&ext.PolicyReference{
					TypeUrl: model.SecurityProfileType,
					Resources: []*ext.PolicyResourceReference{
						{
							Name:       "global/g",
							Uid:        "source-g",
							Extensions: []*anypb.Any{{TypeUrl: "test.example/Metadata", Value: []byte("metadata")}},
						},
						{Name: "namespaced/ns/a", Uid: "source-a"},
					},
				},
			),
			pack("workload-metadata", &ext.WorkloadMetadata{Labels: map[string]string{"app": "wds"}}),
		}}
	f := &fakeStore{
		types:     []store.Type{store.Workload},
		resources: map[store.Key]store.Resource{},
		ready:     true,
	}
	fetches := 0
	f.fetch = func(key store.Key) {
		fetches++
		if key.Type != store.Workload {
			t.Fatalf("profile binding demanded TrafficPolicy: %v", key)
		}
		if key.Name == "uid" {
			f.put(store.Workload, "uid", w)
		}
	}
	aggregate := testAggregate(f)
	before := aggregate.Snapshot()
	resolve := func(ctx context.Context, identity subject.Workload) (subject.Workload, error) {
		return lookupBinding(ctx, aggregate, subject.Subject{Workload: identity})
	}
	identity := subject.Workload{UID: "uid", Labels: map[string]string{"app": "untrusted"}}
	got, err := resolve(t.Context(), identity)
	if err != nil || got.Name != "pod" || got.Namespace != "ns" || got.Labels["app"] != "wds" ||
		!slices.Equal(got.SecurityProfileReferences, []string{"global/g", "namespaced/ns/a"}) ||
		fetches != 1 {
		t.Fatalf("cold binding: %+v %v fetches=%d", got, err, fetches)
	}
	if _, err := resolve(t.Context(), identity); err != nil || fetches != 1 {
		t.Fatalf("hot binding fetched: %v %d", err, fetches)
	}
	if aggregate.Snapshot() != before {
		t.Fatal("cold lookup rebuilt the global index")
	}
	w = proto.Clone(w).(*workload.Workload)
	w.Extensions = []*workload.Extension{
		pack("security-profile-reference", &ext.PolicyReference{TypeUrl: model.SecurityProfileType}),
	}
	f.put(store.Workload, "uid", w)
	got, err = resolve(t.Context(), identity)
	if err != nil || got.SecurityProfileReferences == nil || len(got.SecurityProfileReferences) != 0 ||
		len(got.Labels) != 0 {
		t.Fatalf("empty binding: %+v %v", got, err)
	}
	if _, err := resolve(t.Context(), subject.Workload{UID: "missing", Name: "pod", Namespace: "ns"}); err == nil {
		t.Fatal("missing explicit UID fell back to name")
	}
	for _, extensions := range [][]*workload.Extension{
		nil,
		{pack("security-profile-reference", &ext.PolicyReference{TypeUrl: model.TrafficPolicyType})},
		{w.Extensions[0], w.Extensions[0]},
		{{Name: "security-profile-reference"}},
	} {
		bad := proto.Clone(w).(*workload.Workload)
		bad.Extensions = extensions
		f.put(store.Workload, "uid", bad)
		if _, err := resolve(t.Context(), identity); err == nil {
			t.Fatal("missing or invalid profile binding accepted")
		}
	}
	f.ready = false
	if _, err := resolve(t.Context(), identity); err == nil {
		t.Fatal("unpublished synchronization loss accepted")
	}
}

func TestContextResolverPinsWorkloadMetadata(t *testing.T) {
	const uid = "Kubernetes//Pod/ns/pod"
	f := &fakeStore{types: []store.Type{store.Workload}, resources: map[store.Key]store.Resource{}, ready: true}
	install := func(id, version string) {
		t.Helper()
		refs, err := anypb.New(
			&ext.PolicyReference{
				TypeUrl:   model.SecurityProfileType,
				Resources: []*ext.PolicyResourceReference{{Name: "global/" + version}},
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := anypb.New(&ext.WorkloadMetadata{Labels: map[string]string{"version": version}})
		if err != nil {
			t.Fatal(err)
		}
		f.put(
			store.Workload,
			id,
			&workload.Workload{
				Uid:       id,
				Namespace: "ns",
				Name:      "pod",
				Extensions: []*workload.Extension{
					{Name: "security-profile-reference", Config: refs},
					{Name: "workload-metadata", Config: metadata},
				},
			},
		)
	}
	f.fetch = func(key store.Key) {
		if key != (store.Key{Type: store.Workload, Name: uid}) {
			t.Fatalf("unexpected discovery: %v", key)
		}
		install(uid, "old")
	}
	a := testAggregate(f)
	resolve := NewContextResolver(a)
	input := filter.RequestContext{Caller: filter.CallerContext{
		Subject: subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod", IP: "192.0.2.1"}},
		Token:   &filter.SandboxToken{AccessToken: "token"},
	}}
	old, err := resolve(t.Context(), input)
	if err != nil || old.Caller.Subject.Workload.UID != uid || old.Caller.Subject.Workload.Labels["version"] != "old" ||
		old.Caller.Token != input.Caller.Token || old.Caller.Subject.Workload.IP != "192.0.2.1" {
		t.Fatalf("cold context: %+v %v", old, err)
	}
	f.fetch = nil
	install(uid, "new")
	a.Refresh()
	current, err := resolve(t.Context(), input)
	if err != nil || current.Caller.Subject.Workload.Labels["version"] != "new" ||
		!slices.Equal(current.Caller.Subject.Workload.SecurityProfileReferences, []string{"global/new"}) ||
		old.Caller.Subject.Workload.Labels["version"] != "old" ||
		!slices.Equal(old.Caller.Subject.Workload.SecurityProfileReferences, []string{"global/old"}) {
		t.Fatalf("context update mixed request snapshots: old=%+v current=%+v err=%v", old, current, err)
	}
	install("other", "other")
	a.Refresh()
	if _, err := resolve(t.Context(), input); err == nil {
		t.Fatal("ambiguous namespace/name accepted")
	}
	input.Caller.Subject.Workload.UID = uid
	if _, err := resolve(t.Context(), input); err != nil {
		t.Fatalf("explicit UID rejected because another Workload shares its name: %v", err)
	}
	delete(f.resources, store.Key{Type: store.Workload, Name: uid})
	f.notify()
	a.Refresh()
	if _, err := resolve(t.Context(), input); err == nil {
		t.Fatal("deleted UID fell back to another Workload")
	}
}

type fakeStore struct {
	types     []store.Type
	resources map[store.Key]store.Resource
	changed   chan struct{}
	ready     bool
	err       error
	lookups   int
	fetch     func(store.Key)
}

func (s *fakeStore) Types() []store.Type { return s.types }

func (s *fakeStore) Status() store.Status {
	if s.changed == nil {
		s.changed = make(chan struct{})
	}
	return store.Status{Ready: s.ready, Changed: s.changed}
}

func (s *fakeStore) notify() {
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}

func (s *fakeStore) Read() store.Batch {
	batch := store.Batch{Status: s.Status(), Snapshots: map[store.Type]store.TypeSnapshot{}}
	for _, typ := range s.types {
		resources, err := s.List(typ)
		batch.Snapshots[typ] = store.NewDefaultSnapshot(resources, err)
	}
	return batch
}

func testAggregate(stores ...store.Store) *store.Aggregate {
	a := store.NewAggregate(stores...)
	RegisterQueries(a, "Kubernetes")
	return a
}

func (s *fakeStore) Get(key store.Key) (*store.Resource, error) {
	if s.err != nil {
		return nil, s.err
	}
	r, ok := s.resources[key]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

func (s *fakeStore) List(typ store.Type) ([]store.Resource, error) {
	s.lookups++
	if s.err != nil {
		return nil, s.err
	}
	var result []store.Resource
	for key, r := range s.resources {
		if key.Type == typ {
			result = append(result, r)
		}
	}
	return result, nil
}

func (s *fakeStore) Fetch(_ context.Context, key store.Key) (*store.Resource, error) {
	if s.fetch != nil {
		s.fetch(key)
	}
	return s.Get(key)
}

func (s *fakeStore) put(typ store.Type, name string, value any) {
	key := store.Key{Type: typ, Name: name}
	s.resources[key] = store.Resource{Key: key, Value: value}
	s.notify()
}
