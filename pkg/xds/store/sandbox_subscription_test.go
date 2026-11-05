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
	"fmt"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/model"
)

func sandboxNoticeResource(t testing.TB, uid, owner, value string) model.Resource {
	t.Helper()
	r, err := model.NewResource(model.ResourceKey{TypeURL: model.SandboxType, Name: uid}, "",
		&anypb.Any{TypeUrl: model.SandboxType, Value: []byte(value)}, nil,
		model.ResourceFacts{Sandbox: &model.SandboxResourceFacts{AttesterWorkloadUID: owner}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSandboxNotificationsFollowOwnership(t *testing.T) {
	store := New(newSnapshot(t))
	scopes := map[string]model.ClientScope{
		"a":         {Class: model.ClientDedicatedZTunnel, WorkloadUID: "a"},
		"b":         {Class: model.ClientDedicatedZTunnel, WorkloadUID: "b"},
		"unrelated": {Class: model.ClientDedicatedZTunnel, WorkloadUID: "unrelated"},
		"gateway":   {Class: model.ClientEgressGateway, WorkloadUID: "gateway"},
		"shared":    {Class: model.ClientSharedZTunnel, NodeName: "node"},
	}
	subs := map[string]Subscription{}
	for name, scope := range scopes {
		sub := store.Subscribe(t.Context(), scope)
		sub.Watch(model.SandboxType)
		sub.Watch(model.SandboxType) // Repeated watches must not duplicate notifications.
		subs[name] = sub
	}
	other := store.Subscribe(t.Context(), scopes["a"])
	other.Watch(model.SecretType)
	check := func(want ...string) {
		t.Helper()
		expected := sets.New(want...)
		for name, sub := range subs {
			select {
			case <-sub.Updates():
				if !expected.Contains(name) {
					t.Errorf("unexpected notification: %s", name)
				}
			default:
				if expected.Contains(name) {
					t.Errorf("missing notification: %s", name)
				}
			}
		}
		select {
		case <-other.Updates():
			t.Fatal("Sandbox notice reached an unrelated type")
		default:
		}
	}
	a := sandboxNoticeResource(t, "sandbox", "a", "v1")
	b := sandboxNoticeResource(t, "sandbox", "b", "v2")
	var previous *model.Resource
	for _, tc := range []struct {
		name string
		next *model.Resource
		want []string
	}{
		{"create", &a, []string{"a", "gateway", "shared"}},
		{"move", &b, []string{"a", "b", "gateway", "shared"}},
		{"delete", nil, []string{"b", "gateway", "shared"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Apply([]model.ResourceChange{{Key: a.Key, Old: previous, New: tc.next}}); err != nil {
				t.Fatal(err)
			}
			check(tc.want...)
			previous = tc.next
		})
	}
	store.NotifyKeys([]model.ResourceKey{a.Key})
	check("a", "b", "unrelated", "gateway", "shared")
	store.NotifyType(model.SandboxType)
	check("a", "b", "unrelated", "gateway", "shared")
}

func TestSandboxNotificationBatchAndCancellation(t *testing.T) {
	store := New(newSnapshot(t))
	ctx, cancel := context.WithCancel(t.Context())
	sub := store.Subscribe(ctx, model.ClientScope{Class: model.ClientDedicatedZTunnel, WorkloadUID: "a"})
	sub.Watch(model.SandboxType)
	sub.Watch(model.AddressType)
	a := sandboxNoticeResource(t, "sandbox", "a", "one")
	b := sandboxNoticeResource(t, "sandbox", "b", "two")
	// The mailbox must retain the old owner's withdrawal across a move and delete.
	var previous *model.Resource
	for _, next := range []*model.Resource{&a, &b, nil} {
		if _, err := store.Apply([]model.ResourceChange{{Key: a.Key, Old: previous, New: next}}); err != nil {
			t.Fatal(err)
		}
		previous = next
	}
	update := <-sub.Updates()
	candidates := update.Candidates(model.SandboxType)
	if len(candidates) != 1 || len(candidates[0].Identities) != 2 {
		t.Fatalf("lost ownership history: %+v", candidates)
	}
	// Combining watched types must not mutate the reusable type or owner indexes.
	address := newSnapshot(t, "address").List(model.AddressType)[0]
	if _, err := store.Apply(
		[]model.ResourceChange{{Key: a.Key, New: &a}, {Key: address.Key, New: &address}},
	); err != nil {
		t.Fatal(err)
	}
	<-sub.Updates()
	cancel()
	testutil.Eventually(t, func() bool {
		store.mu.RLock()
		defer store.mu.RUnlock()
		return len(store.subscribers) == 0 && len(store.subscribersByType) == 0 &&
			len(store.sandboxSubscribersByWorkload) == 0
	}, "scope indexes released")
}

func BenchmarkSandboxNotificationFanout(b *testing.B) {
	for _, clients := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("clients=%d", clients), func(b *testing.B) {
			ctx := b.Context()
			store := New(newSnapshot(b))
			var owner Subscription
			for i := range clients {
				sub := store.Subscribe(
					ctx,
					model.ClientScope{Class: model.ClientDedicatedZTunnel, WorkloadUID: fmt.Sprint(i)},
				)
				sub.Watch(model.SandboxType)
				if i == 0 {
					owner = sub
				}
			}
			variants := []model.Resource{
				sandboxNoticeResource(b, "sandbox", "0", "a"),
				sandboxNoticeResource(b, "sandbox", "0", "b"),
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				next := variants[i%2]
				if _, err := store.Apply([]model.ResourceChange{{Key: next.Key, New: &next}}); err != nil {
					b.Fatal(err)
				}
				<-owner.Updates()
			}
		})
	}
}
