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
	"fmt"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// BenchmarkDeltaPushBacklog includes the real per-client coalescing boundaries.
// Each iteration publishes two batches before delivering their merged updates.
// Generation isolates selection costs; total also measures publication and merge.
func BenchmarkDeltaPushBacklog(b *testing.B) {
	const changedCount = 1000
	resources, before, _, forward := incrementalBatchScenario(b, changedCount)
	reverse := make([]model.ResourceChange, len(forward))
	for i, change := range forward {
		reverse[i] = model.ResourceChange{
			Key: change.Key,
			Old: change.New,
			New: change.Old,
		}
	}
	for _, clients := range []int{100, 1000} {
		for _, boundary := range []string{"mailbox", "scheduler"} {
			for _, phase := range []string{"generation", "total"} {
				b.Run(fmt.Sprintf("clients=%d/boundary=%s/phase=%s", clients, boundary, phase), func(b *testing.B) {
					ctx := b.Context()
					store := xdsstore.New(before)
					subscriptions := make([]xdsstore.Subscription, clients)
					for i := range subscriptions {
						subscriptions[i] = store.Subscribe(ctx, model.ClientScope{})
						subscriptions[i].Watch(model.AddressType)
					}
					var scheduler *PushScheduler
					var connections []*pushConnection
					if boundary == "scheduler" {
						scheduler = NewPushScheduler(clients)
						defer scheduler.Close()
						connections = make([]*pushConnection, clients)
						for i := range connections {
							connections[i] = newPushConnection(ctx)
						}
					}
					server := newTestServer(b, ztunnelScope(), resources, nil)
					server.server.resources = store
					scopes, watches := distributedSharedClients(clients)
					stream := &countingDeltaStream{ctx: ctx}
					updates := make([]xdsstore.Update, clients)
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						if phase == "generation" {
							b.StopTimer()
						}
						changes := forward
						if iteration%2 != 0 {
							changes = reverse
						}
						for _, batch := range [][]model.ResourceChange{changes[:changedCount/2], changes[changedCount/2:]} {
							if _, err := store.Apply(batch); err != nil {
								b.Fatal(err)
							}
							if scheduler != nil {
								for i, subscription := range subscriptions {
									scheduler.Enqueue(connections[i], <-subscription.Updates())
								}
							}
						}
						for i, subscription := range subscriptions {
							if scheduler == nil {
								updates[i] = <-subscription.Updates()
							} else {
								push := scheduler.Next(ctx)
								updates[i] = push.Update
								scheduler.Done(push)
							}
						}
						stream.resources = 0
						if phase == "generation" {
							b.StartTimer()
						}
						for i, scope := range scopes {
							if err := server.server.sendIncremental(
								stream,
								scope,
								log,
								model.AddressType,
								watches[i],
								updates[i],
							); err != nil {
								b.Fatal(err)
							}
						}
						if stream.resources != changedCount*clients/scenarioNodeCount {
							b.Fatalf("resources=%d, want %d", stream.resources, changedCount*clients/scenarioNodeCount)
						}
					}
				})
			}
		}
	}
}

// BenchmarkDeltaPushBacklogWithdrawals exercises actual withdrawals and late
// same-wire replacements, where snapshot wire indexes can benefit readers.
func BenchmarkDeltaPushBacklogWithdrawals(b *testing.B) {
	const clients, changedCount = 100, 1000
	resources, before, _, _ := incrementalBatchScenario(b, changedCount)
	removals := make([]model.ResourceChange, changedCount)
	replacements := make([]model.ResourceChange, changedCount)
	for i := range removals {
		old := resources[i]
		removals[i] = model.ResourceChange{
			Key: old.Key,
			Old: &old,
		}
		replacement := old
		replacement.Key.Name += "-replacement"
		replacement.Hash += "-replacement"
		replacements[i] = model.ResourceChange{
			Key: replacement.Key,
			New: &replacement,
		}
	}
	removed, _, err := before.Apply(removals)
	if err != nil {
		b.Fatal(err)
	}
	replaced, _, err := removed.Apply(replacements)
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		snapshot model.ResourceSet
	}{
		{
			name:     "deleted",
			snapshot: removed,
		},
		{
			name:     "late-replacement",
			snapshot: replaced,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			server := newTestServer(b, ztunnelScope(), resources, nil)
			server.resources.snapshot = tc.snapshot
			scopes, watches := distributedSharedClients(clients)
			stream := &countingDeltaStream{ctx: b.Context()}
			updates := make([]xdsstore.Update, clients)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				// Independent merges mirror each client's queue; lookups remain cold for
				// every publication, including candidates with resource-level caches.
				publication := updateBetween(before, removed, removals)
				for i := range updates {
					updates[i] = xdsstore.Merge(xdsstore.Update{}, publication)
				}
				stream.resources = 0
				b.StartTimer()
				for i, scope := range scopes {
					if err := server.server.sendIncremental(
						stream,
						scope,
						log,
						model.AddressType,
						watches[i],
						updates[i],
					); err != nil {
						b.Fatal(err)
					}
				}
				if stream.resources != changedCount*clients/scenarioNodeCount {
					b.Fatalf("resources=%d, want %d", stream.resources, changedCount*clients/scenarioNodeCount)
				}
			}
		})
	}
}
