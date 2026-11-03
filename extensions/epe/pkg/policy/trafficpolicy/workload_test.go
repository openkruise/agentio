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
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
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
					TypeUrl:       model.SecurityProfileType,
					ResourceNames: []string{"global/g", "namespaced/ns/a"},
				},
			),
			pack("workload-metadata", &ext.WorkloadMetadata{Labels: map[string]string{"app": "wds"}}),
		}}
	f := &fakeStore{
		types:     []store.Type{store.Workload, store.TrafficPolicy},
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
	resolve := workloadResolver(aggregate)
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

func snapshotWorkload(t *testing.T, policy, version string) *workload.Workload {
	t.Helper()
	w := &workload.Workload{Uid: "uid", Name: "pod", Namespace: "ns"}
	for _, extension := range []struct {
		name  string
		value proto.Message
	}{
		{"traffic-policy-reference", &ext.PolicyReference{TypeUrl: model.TrafficPolicyType, ResourceNames: []string{policy}}},
		{"security-profile-reference", &ext.PolicyReference{TypeUrl: model.SecurityProfileType, ResourceNames: []string{"namespaced/ns/" + version}}},
		{"workload-metadata", &ext.WorkloadMetadata{Labels: map[string]string{"version": version}}},
	} {
		config, err := anypb.New(extension.value)
		if err != nil {
			t.Fatal(err)
		}
		w.Extensions = append(w.Extensions, &workload.Extension{Name: extension.name, Config: config})
	}
	return w
}

func TestCallerSnapshotSurvivesCacheChanges(t *testing.T) {
	f := testStore()
	f.put(store.Workload, "uid", snapshotWorkload(t, "allow", "old"))
	a := testAggregate(f)
	resolve := NewContextResolver(a, true)
	input := filter.RequestContext{Caller: filter.CallerContext{
		Subject: subject.Subject{Workload: subject.Workload{UID: "uid", IP: "192.0.2.1"}},
		Token:   &filter.SandboxToken{AccessToken: "token"},
	}}
	caller, err := resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if caller.Caller.Token != input.Caller.Token ||
		caller.Caller.Subject.Workload.IP != input.Caller.Subject.Workload.IP {
		t.Fatal("snapshot lost request identity or credentials")
	}
	f.put(store.Workload, "uid", snapshotWorkload(t, "deny", "new"))
	delete(f.resources, store.Key{Type: store.TrafficPolicy, Name: "allow"})
	f.put(store.TrafficPolicy, "deny", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}})
	f.ready = false
	f.err = errors.New("cache unavailable")
	f.notify()
	a.Refresh()
	target := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:443")}
	stream := &filter.Stream{RequestContext: caller, StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()}}
	allowed, err := NewAuthorizer().Authorize(t.Context(), stream, target)
	if err != nil || len(allowed) != 1 || caller.Caller.Subject.Workload.Labels["version"] != "old" ||
		!slices.Equal(caller.Caller.Subject.Workload.SecurityProfileReferences, []string{"namespaced/ns/old"}) {
		t.Fatalf("in-flight snapshot changed: caller=%+v allowed=%v err=%v", caller, allowed, err)
	}
	if _, err := resolve(t.Context(), input); err == nil {
		t.Fatal("new request accepted unavailable dependencies")
	}
	f.ready, f.err = true, nil
	f.notify()
	a.Refresh()
	stream.RequestContext, err = resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err = NewAuthorizer().Authorize(t.Context(), stream, target)
	if err != nil || len(allowed) != 0 || stream.Caller.Subject.Workload.Labels["version"] != "new" ||
		!slices.Equal(stream.Caller.Subject.Workload.SecurityProfileReferences, []string{"namespaced/ns/new"}) {
		t.Fatalf("new request did not see replacement: %+v allowed=%v err=%v", stream.Caller, allowed, err)
	}
}

func TestCallerSnapshotRebuildsDuringColdDiscovery(t *testing.T) {
	for _, oldPolicyArrives := range []bool{false, true} {
		t.Run(fmt.Sprint(oldPolicyArrives), func(t *testing.T) {
			f := testStore()
			delete(f.resources, store.Key{Type: store.TrafficPolicy, Name: "allow"})
			f.put(store.Workload, "uid", snapshotWorkload(t, "allow", "old"))
			fetches := 0
			f.fetch = func(key store.Key) {
				fetches++
				if key != (store.Key{Type: store.TrafficPolicy, Name: "allow"}) {
					t.Fatalf("unexpected fetch: %v", key)
				}
				f.put(store.Workload, "uid", snapshotWorkload(t, "deny", "new"))
				f.put(store.TrafficPolicy, "deny", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}})
				if oldPolicyArrives {
					f.put(store.TrafficPolicy, "allow", &sec.TrafficPolicy{})
				}
			}
			caller, err := NewContextResolver(
				testAggregate(f),
				true,
			)(
				t.Context(),
				filter.RequestContext{
					Caller: filter.CallerContext{Subject: subject.Subject{Workload: subject.Workload{UID: "uid"}}},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			stream := &filter.Stream{
				RequestContext: caller,
				StreamRuntime:  filter.StreamRuntime{Info: filter.NewStreamInfo()},
			}
			allowed, err := NewAuthorizer().Authorize(t.Context(), stream, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:443")})
			if err != nil || len(allowed) != 0 || fetches != 1 ||
				caller.Caller.Subject.Workload.Labels["version"] != "new" ||
				!slices.Equal(caller.Caller.Subject.Workload.SecurityProfileReferences, []string{"namespaced/ns/new"}) {
				t.Fatalf("mixed snapshot: %+v allowed=%v err=%v fetches=%d", caller, allowed, err, fetches)
			}
		})
	}
}

func TestAuthorizerRequiresPreparedSnapshot(t *testing.T) {
	stream := &filter.Stream{
		RequestContext: filter.RequestContext{
			Caller: filter.CallerContext{Subject: subject.Subject{Workload: subject.Workload{UID: "uid"}}},
		},
		StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
	}
	if _, err := NewAuthorizer().Authorize(t.Context(), stream, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:443")}); err == nil {
		t.Fatal("identified request without policy snapshot was accepted")
	}
}

func TestCallerPreparationRequiresProfileBindingWithNativePolicies(t *testing.T) {
	f := testStore()
	w := proto.Clone(f.resources[store.Key{Type: store.Workload, Name: "uid"}].Value.(*workload.Workload)).(*workload.Workload)
	w.Extensions = slices.DeleteFunc(
		w.Extensions,
		func(e *workload.Extension) bool { return e.Name == "security-profile-reference" },
	)
	f.put(store.Workload, "uid", w)
	caller, err := NewContextResolver(
		testAggregate(f),
		true,
	)(
		t.Context(),
		filter.RequestContext{
			Caller: filter.CallerContext{Subject: subject.Subject{Workload: subject.Workload{UID: "uid"}}},
		},
	)
	if err == nil || caller.Policies.DestinationAuthorizer != nil {
		t.Fatalf("native policy prepared without profile binding: caller=%+v err=%v", caller, err)
	}
}
