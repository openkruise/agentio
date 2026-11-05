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

package store

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/model"
)

var _ Subscription = (*subscription)(nil)

func TestNotificationsPreserveTypeSubscriptions(t *testing.T) {
	store := New(newSnapshot(t))
	subscriptions := map[string]Subscription{}
	for name, types := range map[string][]string{
		"address": {model.AddressType},
		"cluster": {model.ClusterType},
		"both":    {model.AddressType, model.ClusterType},
		"secret":  {model.SecretType},
	} {
		sub := store.Subscribe(t.Context(), model.ClientScope{})
		for _, typeURL := range types {
			sub.Watch(typeURL)
		}
		subscriptions[name] = sub
	}

	// Single-type notifications after a union must not inherit subscribers
	// from the other type, regardless of which index was borrowed first.
	for _, tc := range []struct {
		name  string
		types []string
		want  []string
	}{
		{"unwatched", []string{model.RouteType}, nil},
		{"union", []string{model.AddressType, model.ClusterType}, []string{"address", "cluster", "both"}},
		{"address after union", []string{model.AddressType}, []string{"address", "both"}},
		{"cluster after union", []string{model.ClusterType}, []string{"cluster", "both"}},
		{"empty alias", []string{model.AddressType, model.WorkloadType}, []string{"address", "both"}},
		{"all", nil, []string{"address", "cluster", "both", "secret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store.mu.Lock()
			store.notifyLocked(Update{full: true, fullTypes: sets.New(tc.types...)})
			store.mu.Unlock()
			want := sets.New(tc.want...)
			for name, sub := range subscriptions {
				select {
				case <-sub.Updates():
					if !want.Contains(name) {
						t.Errorf("unexpected notification for %s", name)
					}
				default:
					if want.Contains(name) {
						t.Errorf("missing notification for %s", name)
					}
				}
			}
		})
	}
}

// Publication returns the committed snapshot on every path, so Controller can
// record metrics without racing a later Store commit by rereading it.
func TestStorePublicationCarriesCommittedSnapshot(t *testing.T) {
	initial := newSnapshot(t, "a")
	store := New(initial)
	store.Subscribe(t.Context(), model.ClientScope{}).Watch(model.ClusterType)

	publication := store.Replace(newSnapshot(t, "a"))
	if publication.Changed {
		t.Fatal("identical snapshot publication reported a change")
	}
	if got, want := publication.Snapshot.Version(), initial.Version(); got != want {
		t.Fatalf("no-op snapshot version = %q, want %q", got, want)
	}
	if publication.SubscriberCount != 1 {
		t.Fatalf("no-op publication subscribers = %d, want 1", publication.SubscriberCount)
	}

	resource := newSnapshot(t, "b").List(model.AddressType)[0]
	publication, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}})
	if err != nil {
		t.Fatal(err)
	}
	if !publication.Changed || publication.Snapshot.Len() != 2 || publication.SubscriberCount != 1 {
		t.Fatalf("Apply publication = %#v, want changed two-resource snapshot", publication)
	}

	publication, err = store.Apply(
		[]model.ResourceChange{
			{Key: model.ResourceKey{TypeURL: model.AddressType, Name: "invalid"}, New: &model.Resource{}},
		},
	)
	if err == nil {
		t.Fatal("invalid resource was accepted")
	}
	if publication.Changed || publication.Snapshot.Len() != 2 || publication.SubscriberCount != 1 {
		t.Fatalf("failed Apply publication = %#v, want unchanged two-resource snapshot", publication)
	}
	publication = store.Replace(newSnapshot(t, "c"))
	if !publication.Changed || publication.SubscriberCount != 1 {
		t.Fatalf("Replace publication = %#v, want changed snapshot with one subscriber", publication)
	}
}

func TestStoreUpdateRetainsWireIdentities(t *testing.T) {
	old := updateTestResource(t, model.AddressType, "key", "old-name", "old", "old-alias")
	next := updateTestResource(t, model.AddressType, "key", "new-name", "new", "new-alias")
	snapshot, err := model.NewResourceSet([]model.Resource{old})
	if err != nil {
		t.Fatal(err)
	}
	store := New(snapshot)
	sub := store.Subscribe(t.Context(), model.ClientScope{})
	sub.Watch(model.AddressType)
	if _, err := store.Apply([]model.ResourceChange{{Key: next.Key, New: &next}}); err != nil {
		t.Fatal(err)
	}
	update := <-sub.Updates()
	candidates := update.Candidates(model.AddressType)
	if len(candidates) != 1 || candidates[0].Key != next.Key || len(candidates[0].Identities) != 2 {
		t.Fatalf("candidates = %#v, want both wire identities", candidates)
	}
	if candidates[0].Identities[0].Name != old.XDSName || candidates[0].Identities[1].Name != next.XDSName {
		t.Fatalf("identities = %#v", candidates[0].Identities)
	}
	if update.Version() != store.Snapshot().Version() || !update.Affects(model.WorkloadType) ||
		update.Affects(model.SecretType) {
		t.Fatalf("unexpected update scope: %#v", update)
	}
}

func TestMergeRetainsIntermediateIdentitiesWithoutMutatingInputs(t *testing.T) {
	a := updateTestResource(t, model.AddressType, "key", "a", "a")
	b := updateTestResource(t, model.AddressType, "key", "b", "b")
	before, err := model.NewResourceSet([]model.Resource{a})
	if err != nil {
		t.Fatal(err)
	}
	middle, err := model.NewResourceSet([]model.Resource{b})
	if err != nil {
		t.Fatal(err)
	}
	forward := updateBetween(before, middle, before.Diff(middle))
	reverse := updateBetween(middle, before, middle.Diff(before))
	merged := Merge(forward, reverse)
	got := merged.Candidates(model.AddressType)
	if !merged.Affects(model.AddressType) || len(got) != 1 || len(got[0].Identities) != 2 {
		t.Fatalf("rollback lost observed identities: %#v", got)
	}
	c := updateTestResource(t, model.AddressType, "key", "c", "c")
	last, err := model.NewResourceSet([]model.Resource{c})
	if err != nil {
		t.Fatal(err)
	}
	final := Merge(merged, updateBetween(before, last, before.Diff(last)))
	if len(final.Candidates(model.AddressType)[0].Identities) != 3 ||
		len(merged.Candidates(model.AddressType)[0].Identities) != 2 ||
		len(forward.Candidates(model.AddressType)[0].Identities) != 2 {
		t.Fatal("merge lost an identity or mutated a shared input")
	}
}

func TestApplySuppressesUnpublishedRollback(t *testing.T) {
	a := updateTestResource(t, model.AddressType, "key", "a", "a")
	b := updateTestResource(t, model.AddressType, "key", "a", "b")
	snapshot, err := model.NewResourceSet([]model.Resource{a})
	if err != nil {
		t.Fatal(err)
	}
	store := New(snapshot)
	publication, err := store.Apply([]model.ResourceChange{
		{Key: a.Key, Old: &a, New: &b}, {Key: a.Key, Old: &b, New: &a},
	})
	if err != nil || publication.Changed {
		t.Fatalf("atomic rollback: %#v, %v", publication, err)
	}
}

func updateTestResource(t testing.TB, typeURL, keyName, xdsName, payload string, aliases ...string) model.Resource {
	t.Helper()
	facts := model.ResourceFacts{}
	if typeURL == model.AddressType {
		facts.Workload = &model.WorkloadResourceFacts{
			WorkloadUID: keyName,
			Principal:   model.MustServiceAccountPrincipal("default", "default"),
		}
	}
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: typeURL, Name: keyName}, xdsName,
		&anypb.Any{TypeUrl: typeURL, Value: []byte(payload)}, aliases, facts)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

// Replacing a snapshot whose version has not changed is a no-op: every connected
// client would otherwise be woken to compute an empty diff.
func TestReplaceIgnoresUnchangedVersion(t *testing.T) {
	first := newSnapshot(t, "a")
	store := New(first)

	if store.Replace(newSnapshot(t, "a")).Changed {
		t.Fatal("republishing identical content reported a change")
	}
	if !store.Replace(newSnapshot(t, "a", "b")).Changed {
		t.Fatal("replacing with new content did not report a change")
	}
	if got := store.Snapshot().Len(); got != 2 {
		t.Fatalf("snapshot length = %d, want 2", got)
	}
}

// A subscriber is woken by a publish, with repeated wake-ups coalesced: the
// consumer re-reads the current snapshot.
func TestSubscribersAreWokenAndCoalesced(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t, "a"))
	subscription := store.Subscribe(ctx, model.ClientScope{})
	subscription.Watch(model.AddressType)
	updates := subscription.Updates()

	store.Replace(newSnapshot(t, "a", "b"))
	store.Replace(newSnapshot(t, "a", "b", "c"))

	select {
	case <-updates:
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber was not woken")
	}
	// The snapshot the consumer reads is the latest, regardless of how many
	// wake-ups were folded together.
	if got := store.Snapshot().Len(); got != 3 {
		t.Fatalf("snapshot length = %d, want 3", got)
	}
}

// A WDS-only connection must not wake on unrelated gateway updates.
func TestTypedSubscriberIsOnlyWokenForWatchedType(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t))
	subscription := store.Subscribe(ctx, model.ClientScope{})
	subscription.Watch(model.AddressType)

	cluster := model.Resource{
		Key:   model.ResourceKey{TypeURL: model.ClusterType, Name: "cluster-a"},
		Value: &anypb.Any{TypeUrl: model.ClusterType, Value: []byte("cluster")},
	}
	if _, err := store.Apply([]model.ResourceChange{{Key: cluster.Key, New: &cluster}}); err != nil {
		t.Fatal(err)
	}
	select {
	case update := <-subscription.Updates():
		t.Fatalf("unrelated update woke Address subscriber: %#v", update)
	case <-time.After(50 * time.Millisecond):
	}

	address := newSnapshot(t, "a").List(model.AddressType)[0]
	if _, err := store.Apply([]model.ResourceChange{{Key: address.Key, New: &address}}); err != nil {
		t.Fatal(err)
	}
	select {
	case update := <-subscription.Updates():
		changes := update.Candidates(model.AddressType)
		if len(changes) != 1 || changes[0].Key != address.Key {
			t.Fatalf("incremental update = %#v, want address add", update)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watched Address update did not wake subscriber")
	}
}

// A slow connection keeps one pending notification, but that notification must
// union key-level changes so a deletion or update is not lost while it sends an
// earlier response.
func TestSubscriberCoalescingMergesChangedKeys(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t))
	subscription := store.Subscribe(ctx, model.ClientScope{})
	subscription.Watch(model.AddressType)

	for _, name := range []string{"a", "b"} {
		resource := newSnapshot(t, name).List(model.AddressType)[0]
		if _, err := store.Apply([]model.ResourceChange{{Key: resource.Key, New: &resource}}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case update := <-subscription.Updates():
		changes := update.Candidates(model.AddressType)
		if len(changes) != 2 {
			t.Fatalf("merged changed keys = %d, want 2", len(changes))
		}
		for i, name := range []string{"a", "b"} {
			key := model.ResourceKey{TypeURL: model.AddressType, Name: name}
			if changes[i].Key != key {
				t.Fatalf("missing changed key %v in %#v", key, changes)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber was not woken")
	}
}

func TestTypedFullUpdateDoesNotHideIncrementalOtherType(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t))
	subscription := store.Subscribe(ctx, model.ClientScope{})
	subscription.Watch(model.AddressType)
	subscription.Watch(model.SecretType)
	address := newSnapshot(t, "a").List(model.AddressType)[0]
	if _, err := store.Apply([]model.ResourceChange{{Key: address.Key, New: &address}}); err != nil {
		t.Fatal(err)
	}
	store.NotifyType(model.SecretType)

	select {
	case update := <-subscription.Updates():
		if !update.Affects(model.AddressType) || !update.Affects(model.SecretType) {
			t.Fatalf("merged update lost an affected type: %#v", update)
		}
		if update.FullFor(model.AddressType) || !update.FullFor(model.SecretType) {
			t.Fatalf("full regeneration scope is wrong: %#v", update)
		}
		if changes := update.Candidates(model.AddressType); len(changes) != 1 || changes[0].Key != address.Key {
			t.Fatalf("Address changed key was lost: %#v", changes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber was not woken")
	}
}

// Notify exists for resources that live outside the snapshot -- on-demand
// certificates -- and must wake subscribers without changing the version.
func TestNotifyWakesSubscribersWithoutVersionChange(t *testing.T) {
	ctx := t.Context()
	store := New(newSnapshot(t, "a"))
	version := store.Snapshot().Version()
	subscription := store.Subscribe(ctx, model.ClientScope{})
	subscription.Watch(model.AddressType)
	updates := subscription.Updates()

	store.Notify()
	select {
	case update := <-updates:
		if update.Version() != version {
			t.Fatalf("notify changed the version: %s != %s", update.Version(), version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Notify did not wake the subscriber")
	}
}

func newSnapshot(t testing.TB, names ...string) model.ResourceSet {
	t.Helper()
	resources := make([]model.Resource, 0, len(names))
	for _, name := range names {
		value, err := anypb.New(&workloadv1.Address{Type: &workloadv1.Address_Workload{
			Workload: &workloadv1.Workload{Uid: name, Name: name},
		}})
		if err != nil {
			t.Fatal(err)
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.AddressType, Name: name}, "", value, nil,
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID: name,
				Principal:   model.MustServiceAccountPrincipal("default", "default"),
			}})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
	}
	set, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// Cancellation releases both the subscriber and any type-index entries.
func TestSubscriberIsReleasedOnContextCancel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		watch bool
	}{
		{name: "before watch"}, {name: "after watch", watch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := New(newSnapshot(t, "a"))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			subscription := store.Subscribe(ctx, model.ClientScope{})
			if tc.watch {
				subscription.Watch(model.AddressType)
			}
			cancel()
			testutil.Eventually(t, func() bool {
				store.mu.RLock()
				defer store.mu.RUnlock()
				return len(store.subscribers) == 0 && len(store.subscribersByType) == 0
			}, "subscriber and watched-type index released after cancel")
		})
	}
}

func TestNotifyKeysBeforePublication(t *testing.T) {
	store := New(newSnapshot(t))
	version := store.Snapshot().Version()
	subscription := store.Subscribe(t.Context(), model.ClientScope{})
	subscription.Watch(model.SandboxType)
	other := store.Subscribe(t.Context(), model.ClientScope{})
	other.Watch(model.TrafficPolicyType)
	for _, name := range []string{"pending-a", "pending-b", "pending-a"} {
		store.NotifyKeys([]model.ResourceKey{{TypeURL: model.SandboxType, Name: name}})
	}
	select {
	case update := <-subscription.Updates():
		candidates := update.Candidates(model.SandboxType)
		if update.FullFor(model.SandboxType) || len(candidates) != 2 ||
			candidates[0].Key.Name != "pending-a" || candidates[1].Key.Name != "pending-b" {
			t.Fatalf("source invalidations were lost or broadened: %+v", update)
		}
	default:
		t.Fatal("source deletion did not wake subscriber")
	}
	select {
	case <-other.Updates():
		t.Fatal("source deletion woke unrelated resource type")
	default:
	}
	if store.Snapshot().Version() != version || len(store.Snapshot().List(model.SandboxType)) != 0 {
		t.Fatal("source invalidation modified published snapshot")
	}
}
