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
	"reflect"
	"sync"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

// Streams can have the same latest snapshot version but different unconsumed
// identities. Reusing a merge must preserve each stream's complete history.
func TestMailboxMergePreservesDifferentHistories(t *testing.T) {
	resources := make([]model.Resource, 4)
	snapshots := make([]model.ResourceSet, 4)
	for i, name := range []string{"a", "b", "c", "d"} {
		resources[i] = updateTestResource(t, model.AddressType, "key", name, name)
		var err error
		snapshots[i], err = model.NewResourceSet(resources[i : i+1])
		if err != nil {
			t.Fatal(err)
		}
	}
	store := New(snapshots[0])
	subs := []Subscription{
		store.Subscribe(t.Context(), model.ClientScope{}),
		store.Subscribe(t.Context(), model.ClientScope{}),
		store.Subscribe(t.Context(), model.ClientScope{}),
	}
	for _, sub := range subs {
		sub.Watch(model.AddressType)
	}
	store.Replace(snapshots[1])
	consumed := <-subs[0].Updates()
	store.Replace(snapshots[2])
	store.Replace(snapshots[3])
	for i, sub := range subs {
		update := <-sub.Updates()
		if update.Version() != snapshots[3].Version() {
			t.Fatal("merged notice lost latest snapshot version")
		}
		var names []string
		for _, identity := range update.Candidates(model.AddressType)[0].Identities {
			names = append(names, identity.Name)
		}
		want := []string{"a", "b", "c", "d"}
		if i == 0 {
			want = want[1:]
		}
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("subscriber %d identities = %v, want %v", i, names, want)
		}
	}
	if got := len(consumed.Candidates(model.AddressType)[0].Identities); got != 2 {
		t.Fatalf("later shared merge changed consumed notice: identities=%d", got)
	}
}

// Dynamic notifications may share a snapshot version while requesting
// different full-refresh scopes. They must not be merged by version alone.
func TestMailboxMergePreservesDifferentFullScopes(t *testing.T) {
	store := New(model.ResourceSet{})
	fast, slow := store.Subscribe(t.Context(), model.ClientScope{}), store.Subscribe(t.Context(), model.ClientScope{})
	for _, sub := range []Subscription{fast, slow} {
		for _, typ := range []string{model.AddressType, model.SecretType, model.ClusterType} {
			sub.Watch(typ)
		}
	}
	store.NotifyType(model.AddressType)
	<-fast.Updates()
	store.NotifyType(model.SecretType)
	store.NotifyType(model.ClusterType)
	for i, sub := range []Subscription{fast, slow} {
		update := <-sub.Updates()
		if !update.FullFor(model.SecretType) || !update.FullFor(model.ClusterType) ||
			update.FullFor(model.AddressType) != (i == 1) {
			t.Fatalf("subscriber %d lost its full-refresh scope: %#v", i, update)
		}
	}
}

// The publisher may reuse one merged notice while readers independently merge
// that immutable input with their later updates. Run with -race.
func TestMailboxMergeConcurrentReaders(t *testing.T) {
	snapshots := make([]model.ResourceSet, 3)
	for i, name := range []string{"a", "b", "c"} {
		resource := updateTestResource(t, model.AddressType, "key", name, name)
		var err error
		snapshots[i], err = model.NewResourceSet([]model.Resource{resource})
		if err != nil {
			t.Fatal(err)
		}
	}
	store := New(snapshots[0])
	subs := make([]Subscription, 4)
	for i := range subs {
		subs[i] = store.Subscribe(t.Context(), model.ClientScope{})
		subs[i].Watch(model.AddressType)
	}
	// Establish a shared backlog before allowing readers to race the writer.
	store.Replace(snapshots[1])
	store.Replace(snapshots[2])
	var readers sync.WaitGroup
	for _, sub := range subs {
		readers.Go(func() {
			var accumulated Update
			for {
				update := <-sub.Updates()
				accumulated = Merge(accumulated, update)
				if update.FullFor(model.AddressType) {
					if got := len(accumulated.Candidates(model.AddressType)[0].Identities); got != 3 {
						t.Errorf("concurrent merges lost identity history: got %d, want 3", got)
					}
					return
				}
			}
		})
	}
	for i := range 100 {
		store.Replace(snapshots[i%len(snapshots)])
	}
	store.NotifyType(model.AddressType)
	readers.Wait()
}
