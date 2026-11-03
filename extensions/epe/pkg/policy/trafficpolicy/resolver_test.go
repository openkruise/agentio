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
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/model"

	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

// These helpers exercise discovery construction separately from immutable authorization.
type resourceResolver struct{ source Resources }

func (r *resourceResolver) config(ctx context.Context, subj subject.Subject) (egressauthz.Config, error) {
	snapshot, err := lookup(ctx, r.source, subj)
	if err != nil {
		return egressauthz.Config{}, err
	}
	return snapshot.entry.compiled.config, snapshot.entry.compiled.err
}

func workloadResolver(source Resources) func(context.Context, subject.Workload) (subject.Workload, error) {
	return func(ctx context.Context, w subject.Workload) (subject.Workload, error) {
		caller, err := NewContextResolver(source, false)(ctx, filter.RequestContext{Caller: filter.CallerContext{Subject: subject.Subject{Workload: w}}})
		return caller.Caller.Subject.Workload, err
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

func (s *fakeStore) bind(names ...string) {
	key := store.Key{Type: store.Workload, Name: "uid"}
	w := proto.Clone(s.resources[key].Value.(*workload.Workload)).(*workload.Workload)
	ref, err := anypb.New(&ext.PolicyReference{TypeUrl: model.TrafficPolicyType, ResourceNames: names})
	if err != nil {
		panic(err)
	}
	w.Extensions = slices.DeleteFunc(w.Extensions, func(e *workload.Extension) bool { return e.Name == "traffic-policy-reference" })
	w.Extensions = append(w.Extensions, &workload.Extension{Name: "traffic-policy-reference", Config: ref})
	s.put(store.Workload, "uid", w)
}

func testStore() *fakeStore {
	s := &fakeStore{
		types:     []store.Type{store.Workload, store.TrafficPolicy},
		resources: map[store.Key]store.Resource{},
		ready:     true,
	}
	profile, err := anypb.New(&ext.PolicyReference{TypeUrl: model.SecurityProfileType})
	if err != nil {
		panic(err)
	}
	s.put(store.Workload, "uid", &workload.Workload{Uid: "uid", Name: "pod", Namespace: "ns", Addresses: [][]byte{{192, 0, 2, 1}}, Extensions: []*workload.Extension{{Name: "security-profile-reference", Config: profile}}})
	s.bind("allow")
	s.put(
		store.TrafficPolicy,
		"allow",
		&sec.TrafficPolicy{
			Egress: &sec.TrafficPolicy_RuleSet{
				Rules: []*sec.TrafficPolicy_Rule{
					{
						Match: &sec.TrafficPolicy_Match{
							DestinationIps: []*sec.TrafficPolicy_Address{address("203.0.113.0/24")},
						},
					},
				},
			},
		},
	)
	return s
}

func TestResolverCacheUpdates(t *testing.T) {
	f := testStore()
	source := testAggregate(f)
	s := &resourceResolver{source: source}
	subj := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod", IP: "192.0.2.1"}}
	target := netip.MustParseAddrPort("203.0.113.7:443")
	cfg, err := s.config(t.Context(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Evaluate(target).Action != egressauthz.Allow {
		t.Fatal("not allowed")
	}
	if _, err := s.config(t.Context(), subj); err != nil {
		t.Fatal("published index not used", err)
	}
	f.put(store.TrafficPolicy, "allow", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}})
	source.Refresh()
	updated, err := s.config(t.Context(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Evaluate(target).Action != egressauthz.Deny {
		t.Fatal("policy update did not revoke")
	}
	if cfg.Evaluate(target).Action != egressauthz.Allow {
		t.Fatal("in-flight config mutated")
	}
	f.ready = false
	f.notify()
	source.Refresh()
	if _, err := s.config(t.Context(), subj); err == nil {
		t.Fatal("unsynchronized resources accepted")
	}
	f.ready = true
	f.notify()
	source.Refresh()
	f.err = fmt.Errorf("missing resource")
	f.notify()
	source.Refresh()
	if _, err := s.config(t.Context(), subj); err == nil {
		t.Fatal("lookup error ignored")
	}
}

func TestAuthorizerUsesWorkloadBinding(t *testing.T) {
	f := testStore()
	f.bind()
	prepare := NewContextResolver(testAggregate(f), true)
	authorize := egressauthz.NewAggregate(
		dns.NewClient(nil, 0),
		NewAuthorizer(),
	).Authorize
	stream := &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: "203.0.113.7", Port: 443}}, StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()}}
	stream.Caller.Subject.Workload = subject.Workload{Namespace: "ns", Name: "pod"}
	var err error
	stream.RequestContext, err = prepare(t.Context(), stream.RequestContext)
	if err != nil {
		t.Fatal(err)
	}
	target, reply, err := authorize(t.Context(), stream)
	if err != nil || reply != nil || target == nil || target.Address.String() != "203.0.113.7:443" {
		t.Fatalf("empty binding should allow: target=%v reply=%v err=%v", target, reply, err)
	}
	decision := stream.Info.Authorization
	if decision == nil || decision.Action != "allow" || decision.Reason != "" ||
		decision.Policy != "" || decision.RuleIndex != nil {
		t.Fatalf("unexpected default authorization: %+v", decision)
	}
}

func TestAuthorizerAcceptsWorkloadUIDOnly(t *testing.T) {
	prepare := NewContextResolver(testAggregate(testStore()), true)
	authorizer := NewAuthorizer()
	for _, workload := range []subject.Workload{{UID: "uid"}, {}} {
		stream := &filter.Stream{RequestContext: filter.RequestContext{Caller: filter.CallerContext{Subject: subject.Subject{
			Workload: workload,
			Sandbox:  &subject.Sandbox{UID: "kruise:sbx"},
		}}}, StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
		}
		if workload.HasIdentity() {
			caller, err := prepare(t.Context(), stream.RequestContext)
			if err != nil {
				t.Fatal(err)
			}
			stream.RequestContext = caller
		}
		got, err := authorizer.Authorize(
			t.Context(),
			stream,
			[]netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:443")},
		)
		if err != nil || (workload.UID != "" && len(got) != 1) || (workload.UID == "" && len(got) != 0) {
			t.Fatalf("workload=%v candidates=%v err=%v", workload, got, err)
		}
	}
}

func TestCrossStorePoliciesAndFetchRebind(t *testing.T) {
	workloads := testStore()
	workloads.types = []store.Type{store.Workload}
	policies := testStore()
	policies.types = []store.Type{store.TrafficPolicy}
	source := testAggregate(workloads, policies)
	subj := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}}
	result, err := lookup(t.Context(), source, subj)
	if err != nil || len(result.TrafficPolicies) != 1 {
		t.Fatalf("cross-store lookup: %+v %v", result, err)
	}
	workloads.bind("missing")
	source.Refresh()
	if _, err := lookup(t.Context(), source, subj); err == nil {
		t.Fatal("missing policy silently skipped")
	}
	policies.fetch = func(key store.Key) {
		policies.put(key.Type, key.Name, &sec.TrafficPolicy{})
		workloads.bind("allow", "missing")
	}
	result, err = lookup(t.Context(), source, subj)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.TrafficPolicies) != 2 || result.TrafficPolicies[0].Name != "allow" ||
		result.TrafficPolicies[1].Name != "missing" {
		t.Fatalf("binding not reloaded after fetch: %+v", result)
	}
	w := proto.Clone(workloads.resources[store.Key{Type: store.Workload, Name: "uid"}].Value.(*workload.Workload)).(*workload.Workload)
	w.Extensions = nil
	workloads.put(store.Workload, "uid", w)
	source.Refresh()
	if _, err := lookup(t.Context(), source, subj); err == nil {
		t.Fatal("missing binding treated as empty")
	}
}

func TestResourcesForIndexesPrecedenceAndDependencyReuse(t *testing.T) {
	high, low := testStore(), testStore()
	high.bind()
	source := testAggregate(high, low)
	subject := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod", IP: "192.0.2.1"}}
	resources, err := source.ResourcesFor(store.TrafficPolicy, subject)
	if err != nil || len(resources) != 0 {
		t.Fatal("shadowed source matched", resources, err)
	}
	resources, err = source.ResourcesFor(store.Workload, subject)
	if err != nil || len(resources) != 1 {
		t.Fatal(resources, err)
	}
	high.bind("allow")
	source.Refresh()
	before := source.Snapshot()
	previous := before.Query(store.TrafficPolicy).(*queryIndex).workloads[subjectKey{"ns", "pod"}]
	high.put(store.TrafficPolicy, "unrelated", &sec.TrafficPolicy{})
	source.Refresh()
	current := source.Snapshot().Query(store.TrafficPolicy).(*queryIndex).workloads[subjectKey{"ns", "pod"}]
	if current != previous {
		t.Fatal("unrelated update invalidated compiled configuration")
	}
	high.put(store.TrafficPolicy, "allow", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}})
	source.Refresh()
	current = source.Snapshot().Query(store.TrafficPolicy).(*queryIndex).workloads[subjectKey{"ns", "pod"}]
	if current == previous {
		t.Fatal("dependency update reused stale configuration")
	}
	target := netip.MustParseAddrPort("203.0.113.7:443")
	if current.compiled.config.Evaluate(target).Action != egressauthz.Deny ||
		previous.compiled.config.Evaluate(target).Action != egressauthz.Allow {
		t.Fatal("immutable configuration boundary broken")
	}
	delete(high.resources, store.Key{Type: store.TrafficPolicy, Name: "allow"})
	high.notify()
	// Remove the lower-priority copy too, to exercise referenced-resource deletion.
	delete(low.resources, store.Key{Type: store.TrafficPolicy, Name: "allow"})
	low.notify()
	source.Refresh()
	if _, err := source.ResourcesFor(store.TrafficPolicy, subject); err == nil {
		t.Fatal("removed dependency accepted")
	}
}

func TestResourcesForUsesExplicitWorkloadUID(t *testing.T) {
	f := testStore()
	emptyBinding, err := anypb.New(&ext.PolicyReference{TypeUrl: model.TrafficPolicyType})
	if err != nil {
		t.Fatal(err)
	}
	f.put(store.Workload, "other-uid", &workload.Workload{
		Name:       "pod",
		Namespace:  "ns",
		Extensions: []*workload.Extension{{Name: "traffic-policy-reference", Config: emptyBinding}},
	})
	source := testAggregate(f)
	for _, tc := range []struct {
		uid  string
		want int
	}{{"uid", 1}, {"other-uid", 0}} {
		policies, err := source.ResourcesFor(
			store.TrafficPolicy,
			subject.Subject{Workload: subject.Workload{UID: tc.uid}},
		)
		if err != nil || len(policies) != tc.want {
			t.Fatalf("UID %q policies = %v, %v", tc.uid, policies, err)
		}
	}
	if _, err := source.ResourcesFor(
		store.TrafficPolicy,
		subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}},
	); err == nil {
		t.Fatal("ambiguous namespace/name accepted without a UID")
	}
	_, err = source.ResourcesFor(
		store.TrafficPolicy,
		subject.Subject{Workload: subject.Workload{UID: "missing-uid", Namespace: "ns", Name: "pod"}},
	)
	var missing *store.MissingResource
	if !errors.As(err, &missing) || missing.Key != (store.Key{Type: store.Workload, Name: "missing-uid"}) {
		t.Fatalf("missing explicit UID = %v, want exact resource request without name fallback", err)
	}
}

func TestResourcesForRequiresWorkloadIdentity(t *testing.T) {
	source := testAggregate(testStore())
	for _, subject := range []subject.Subject{
		{},
		{Sandbox: &subject.Sandbox{UID: "kruise:sbx"}},
		{Workload: subject.Workload{Namespace: "ns"}},
		{Workload: subject.Workload{Labels: map[string]string{"app": "test"}}},
	} {
		_, err := source.ResourcesFor(store.TrafficPolicy, subject)
		var missing *store.MissingResource
		if err == nil || errors.As(err, &missing) {
			t.Fatalf("missing Workload identity should fail without synthesizing a resource to fetch: %v", err)
		}
	}
}

func TestWorkloadConfigDoesNotDependOnSourceIP(t *testing.T) {
	for _, addresses := range [][][]byte{nil, {{192, 0, 2, 1}}, {{192, 0, 2, 1}, netip.MustParseAddr("2001:db8::1").AsSlice()}} {
		f := testStore()
		w := proto.Clone(f.resources[store.Key{Type: store.Workload, Name: "uid"}].Value.(*workload.Workload)).(*workload.Workload)
		w.Addresses = addresses
		f.put(store.Workload, "uid", w)
		source := testAggregate(f)
		resolver := &resourceResolver{source: source}
		expected, err := resolver.config(
			t.Context(),
			subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}},
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range []string{"", "192.0.2.1", "2001:db8::1", "198.51.100.9", "not-an-ip"} {
			got, err := resolver.config(
				t.Context(),
				subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod", IP: ip}},
			)
			if err != nil {
				t.Fatalf("source IP %q affected lookup: %v", ip, err)
			}
			if &got.Policies[0] != &expected.Policies[0] ||
				got.Evaluate(netip.MustParseAddrPort("203.0.113.7:443")).Action != egressauthz.Allow {
				t.Fatalf("source IP %q did not reuse the Workload's compiled config", ip)
			}
		}
	}
}

func TestLookupFetchesAllMissingPolicies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := testStore()
		names := make([]string, 9)
		for i := range names {
			names[i] = fmt.Sprintf("missing-%d", i)
		}
		f.bind(names...)
		calls := 0
		f.fetch = func(key store.Key) {
			calls++
			f.put(key.Type, key.Name, &sec.TrafficPolicy{})
		}
		started := time.Now()
		result, err := lookup(
			t.Context(),
			testAggregate(f),
			subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}},
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.TrafficPolicies) != len(names) || calls != len(names) {
			t.Fatalf("policies=%d fetches=%d, want %d", len(result.TrafficPolicies), calls, len(names))
		}
		for i, policy := range result.TrafficPolicies {
			if policy.Name != names[i] {
				t.Fatalf("binding order changed: %v", result.TrafficPolicies)
			}
		}

		if elapsed := time.Since(started); elapsed != 0 {
			t.Fatalf("ready dependencies incurred artificial waiting: %s", elapsed)
		}
	})
}

func TestUnchangedMissingDependencyReusesIndex(t *testing.T) {
	f := testStore()
	f.bind("missing")
	aggregate := testAggregate(f, &fakeStore{types: []store.Type{store.Workload}, ready: true})
	before := aggregate.Snapshot().Query(store.Workload).(*queryIndex).byUID["uid"]
	unrelated := proto.Clone(before.workload.Value.(*workload.Workload)).(*workload.Workload)
	unrelated.Uid, unrelated.Name = "unrelated", "unrelated"
	f.put(store.Workload, "unrelated", unrelated)
	aggregate.Refresh()
	after := aggregate.Snapshot().Query(store.Workload).(*queryIndex).byUID["uid"]
	if after != before {
		t.Fatal("unrelated Workload forced unresolved bindings to be decoded again")
	}
	f.put(store.TrafficPolicy, "missing", &sec.TrafficPolicy{})
	aggregate.Refresh()
	resolved := aggregate.Snapshot().Query(store.Workload).(*queryIndex).byUID["uid"]
	if resolved == before || resolved.err != nil || len(resolved.named) != 1 {
		t.Fatal("newly available dependency was not resolved")
	}
}

func TestLookupReadsUnpublishedPolicyUpdates(t *testing.T) {
	f := testStore()
	aggregate := testAggregate(f)
	before := aggregate.Snapshot()
	previous := before.Query(store.Workload).(*queryIndex).byUID["uid"]
	f.put(store.TrafficPolicy, "allow", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}})
	result, err := lookup(t.Context(), aggregate, subject.Subject{Workload: subject.Workload{UID: "uid"}})
	if err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddrPort("203.0.113.7:443")
	if result.entry.compiled.config.Evaluate(target).Action != egressauthz.Deny ||
		previous.compiled.config.Evaluate(target).Action != egressauthz.Allow {
		t.Fatal("unpublished update reused an old policy or mutated its compiled view")
	}
	if aggregate.Snapshot() != before {
		t.Fatal("request synchronously rebuilt the global index")
	}
}

func TestLookupStopsFetchingWhenCanceled(t *testing.T) {
	f := testStore()
	f.bind("first", "second")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	f.fetch = func(key store.Key) {
		calls++
		f.put(key.Type, key.Name, &sec.TrafficPolicy{})
		cancel()
	}
	_, err := lookup(ctx, testAggregate(f), subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("error=%v fetches=%d, want cancellation after first fetch", err, calls)
	}
}

func TestLookupDemandsUnsynchronizedWorkload(t *testing.T) {
	for _, identity := range []subject.Workload{{UID: "uid"}, {Name: "pod", Namespace: "ns"}} {
		f := &fakeStore{types: []store.Type{store.Workload, store.TrafficPolicy}, resources: map[store.Key]store.Resource{}}
		calls := 0
		f.fetch = func(key store.Key) {
			calls++
			if key.Type != store.Workload || key.Name == "" {
				t.Fatalf("unexpected cold discovery: %+v", key)
			}
		}
		if _, err := lookup(t.Context(), testAggregate(f), subject.Subject{Workload: identity}); err == nil || calls != 1 {
			t.Fatalf("unsynchronized lookup: err=%v demands=%d", err, calls)
		}
	}
}

// overrideAcquire leaves the published snapshot unchanged to exercise a lookup
// result racing with publication or deletion.
type overrideAcquire struct {
	Resources
	acquire func(context.Context, store.Key) (*store.Resource, error)
}

func (s overrideAcquire) Acquire(ctx context.Context, key store.Key) (*store.Resource, func(), error) {
	if key.Type == store.Workload {
		return s.Resources.Acquire(ctx, key)
	}
	r, err := s.acquire(ctx, key)
	return r, func() {}, err
}

func TestLookupAcquisitionFailure(t *testing.T) {
	fetchErr := errors.New("fetch failed")
	for _, tc := range []struct {
		name     string
		resource *store.Resource
		fetchErr error
		want     error
	}{
		{name: "not found"},
		{name: "fetch failure", fetchErr: fetchErr, want: fetchErr},
		{name: "unchanged snapshot", resource: &store.Resource{Key: store.Key{Type: store.TrafficPolicy, Name: "missing"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := testStore()
			f.bind("missing")
			calls := 0
			source := overrideAcquire{
				Resources: testAggregate(f),
				acquire: func(context.Context, store.Key) (*store.Resource, error) {
					calls++
					return tc.resource, tc.fetchErr
				},
			}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			_, err := lookup(ctx, source, subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}})
			if tc.want == nil {
				if missing, ok := errors.AsType[*store.MissingResource](err); !ok || missing.Key.Name != "missing" {
					t.Fatalf("want missing resource, got %v", err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			if calls != 1 {
				t.Fatalf("terminal acquisition retried %d times", calls)
			}
		})
	}
}

func TestLookupRefreshesRemovedPolicyBinding(t *testing.T) {
	for _, hot := range []bool{false, true} {
		for _, binding := range []string{"empty", "deny", "unchanged", "evicted"} {
			t.Run(fmt.Sprintf("hot=%v/%s", hot, binding), func(t *testing.T) {
				f := testStore()
				policyKey := store.Key{Type: store.TrafficPolicy, Name: "allow"}
				if !hot {
					delete(f.resources, policyKey)
				}
				a := testAggregate(f)
				calls := 0
				source := overrideAcquire{Resources: a, acquire: func(_ context.Context, key store.Key) (*store.Resource, error) {
					calls++
					if key == policyKey {
						delete(f.resources, policyKey)
						switch binding {
						case "empty", "evicted":
							f.bind()
							if binding == "evicted" {
								workloadKey := store.Key{Type: store.Workload, Name: "uid"}
								current := f.resources[workloadKey]
								delete(f.resources, workloadKey)
								f.fetch = func(key store.Key) {
									if key == workloadKey {
										f.put(key.Type, key.Name, current.Value)
									}
								}
							}
						case "deny":
							f.bind("deny")
							f.put(store.TrafficPolicy, "deny", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}})
						case "unchanged":
							f.bind("allow")
						}
					}
					return f.Get(key)
				}}
				result, err := lookup(t.Context(), source, subject.Subject{Workload: subject.Workload{UID: "uid"}})
				if binding == "unchanged" {
					if _, ok := errors.AsType[*store.MissingResource](err); !ok || calls != 1 {
						t.Fatalf("missing policy did not fail closed: %v calls=%d", err, calls)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if (binding == "empty" || binding == "evicted") && len(result.TrafficPolicies) != 0 {
					t.Fatal("removed binding still used")
				}
				if binding == "deny" && (len(result.TrafficPolicies) != 1 || result.TrafficPolicies[0].Name != "deny") {
					t.Fatal("replacement binding was not resolved")
				}
				if a.Snapshot().Query(store.Workload).(*queryIndex).byUID["uid"].workload.Value == result.Workload {
					t.Fatal("retry used the stale published Workload")
				}
			})
		}
	}
}

func TestCallerPreparationRejectsUnavailablePolicy(t *testing.T) {
	source := testStore()
	source.err = errors.New("xDS unavailable")
	caller, err := NewContextResolver(testAggregate(source), true)(t.Context(), filter.RequestContext{Caller: filter.CallerContext{Subject: subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}}}})
	if err == nil || caller.Policies.DestinationAuthorizer != nil {
		t.Fatalf("unavailable policy prepared: caller=%+v err=%v", caller, err)
	}
}

func TestGlobalDenyOverridesWorkloadPolicy(t *testing.T) {
	f := testStore() // Workload policy allows 203.0.113.0/24.
	prepare := NewContextResolver(testAggregate(f), true)
	global := egressauthz.Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}}
	authorize := egressauthz.NewAggregate(
		dns.NewClient(nil, 0),
		egressauthz.NewStaticAuthorizer(global),
		NewAuthorizer(),
	).Authorize
	for _, tc := range []struct {
		host    string
		allowed bool
	}{
		{"203.0.113.7", false}, // Global restriction overrides workload allow.
		{"203.0.113.8", true},
		{"192.0.2.1", false}, // Global miss preserves workload default-deny.
	} {
		stream := &filter.Stream{RequestContext: filter.RequestContext{Caller: filter.CallerContext{
			Subject: subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod"}},
		},
			Request: httpreq.HTTPRequest{Host: tc.host, Port: 443}},
		}
		caller, err := prepare(t.Context(), stream.RequestContext)
		if err != nil {
			t.Fatal(err)
		}
		stream.RequestContext = caller
		target, reply, err := authorize(t.Context(), stream)
		if err != nil {
			t.Fatal(err)
		}
		if tc.allowed {
			if target == nil || reply != nil {
				t.Fatalf("%s: target=%v reply=%v", tc.host, target, reply)
			}
		} else if target != nil || reply == nil || reply.Status != 403 {
			t.Fatalf("%s: target=%v reply=%v", tc.host, target, reply)
		}
	}
}

func TestAuthorizerRejectsMissingIdentityBeforeLookup(t *testing.T) {
	for _, tc := range []struct {
		name string
		pod  types.NamespacedName
	}{
		{name: "absent"},
		{name: "missing namespace", pod: types.NamespacedName{Name: "pod"}},
		{name: "missing name", pod: types.NamespacedName{Namespace: "ns"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := &filter.Stream{RequestContext: filter.RequestContext{Caller: filter.CallerContext{
				Subject: subject.Subject{
					Workload: subject.Workload{Namespace: tc.pod.Namespace, Name: tc.pod.Name},
				},
			}}, StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
			}
			// No resource store is needed: rejection must precede any lookup.
			allowed, err := NewAuthorizer().Authorize(t.Context(), stream, []netip.AddrPort{
				netip.MustParseAddrPort("203.0.113.7:443"),
			})
			if err != nil || len(allowed) != 0 {
				t.Fatalf("allowed=%v err=%v", allowed, err)
			}
			audit := stream.Info.Authorization
			if audit == nil || audit.Action != "deny" || audit.Reason != filter.AuthorizationReasonMissingIdentity ||
				audit.Policy != "" || audit.Destination != "" {
				t.Fatalf("audit=%+v", audit)
			}
		})
	}
}
