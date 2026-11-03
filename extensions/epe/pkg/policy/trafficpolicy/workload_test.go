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

package trafficpolicy

import (
	"slices"
	"testing"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestWorkloadSecurityProfileBinding(t *testing.T) {
	pack := func(name string, value proto.Message) *workload.Extension {
		v, err := anypb.New(value)
		if err != nil {
			t.Fatal(err)
		}
		return &workload.Extension{Name: name, Config: v}
	}
	w := &workload.Workload{Uid: "uid", Namespace: "ns", Name: "pod", Extensions: []*workload.Extension{
		pack("security-profile-reference", &ext.PolicyReference{TypeUrl: model.SecurityProfileType, ResourceNames: []string{"global/g", "namespaced/ns/a"}}),
		pack("workload-metadata", &ext.WorkloadMetadata{Labels: map[string]string{"app": "wds"}}),
	}}
	f := &fakeStore{types: []store.Type{store.Workload, store.TrafficPolicy}, resources: map[store.Key]store.Resource{}, ready: true}
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
	resolve := NewWorkloadResolver(aggregate)
	identity := subject.Workload{UID: "uid", Labels: map[string]string{"app": "untrusted"}}
	got, err := resolve(t.Context(), identity)
	if err != nil || got.Name != "pod" || got.Namespace != "ns" || got.Labels["app"] != "wds" || !slices.Equal(got.SecurityProfileReferences, []string{"global/g", "namespaced/ns/a"}) || fetches != 1 {
		t.Fatalf("cold binding: %+v %v fetches=%d", got, err, fetches)
	}
	if _, err := resolve(t.Context(), identity); err != nil || fetches != 1 {
		t.Fatalf("hot binding fetched: %v %d", err, fetches)
	}
	if aggregate.Snapshot() != before {
		t.Fatal("cold lookup rebuilt the global index")
	}
	w = proto.Clone(w).(*workload.Workload)
	w.Extensions = []*workload.Extension{pack("security-profile-reference", &ext.PolicyReference{TypeUrl: model.SecurityProfileType})}
	f.put(store.Workload, "uid", w)
	got, err = resolve(t.Context(), identity)
	if err != nil || got.SecurityProfileReferences == nil || len(got.SecurityProfileReferences) != 0 || len(got.Labels) != 0 {
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
