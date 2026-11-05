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
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestReconnectGraceDoesNotReplayIdleSubscriptions(t *testing.T) {
	withSubscriptionClient(t, Watch{TypeURL: testType, ReconnectGrace: 5 * time.Second}, func(t *testing.T, c *Client) {
		const count = 10000
		value, err := anypb.New(wrapperspb.String("old"))
		if err != nil {
			t.Fatal(err)
		}
		resources := make([]*discovery.Resource, count)
		leases := make([]*Subscription, count)
		for i := range count {
			name := fmt.Sprintf("workload-%05d", i)
			leases[i] = acquire(t, c, name)
			resources[i] = &discovery.Resource{Name: name, Resource: value}
		}
		defer func() {
			for _, lease := range leases {
				lease.Release()
			}
		}()
		if err = c.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType, Resources: resources}); err != nil {
			t.Fatal(err)
		}
		c.reset()
		sent := map[string]map[string]*subscription{}
		initial := c.initialRequests(sent)
		if !slices.Equal(initial[0].ResourceNamesSubscribe, []string{"*"}) ||
			!slices.Equal(initial[0].ResourceNamesUnsubscribe, []string{"*"}) {
			t.Fatalf("replayed idle resources: %v", initial)
		}
		// An empty initial response acknowledges the type, not all retained names.
		if err = c.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType}); err != nil {
			t.Fatal(err)
		}
		if len(c.Snapshot().Resources[testType]) != count {
			t.Fatal("initial response discarded grace values")
		}
		var group sync.WaitGroup
		for range 64 {
			group.Go(func() {
				got, err := leases[0].Demand(t.Context())
				if err != nil || got.Value.(*anypb.Any).GetValue() == nil {
					t.Errorf("hot grace demand: %v %v", got, err)
				}
			})
		}
		group.Wait()
		requests := c.pendingRequests(sent)
		if len(requests) != 1 || !slices.Equal(requests[0].ResourceNamesSubscribe, []string{"workload-00000"}) {
			t.Fatalf("hot demand did not coalesce: %v", requests)
		}
		publishString(t, c, "workload-00000", "fresh")
		before := c.Snapshot()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		after := c.Snapshot()
		if len(after.Resources[testType]) != 1 || after.Resources[testType]["workload-00000"] == nil {
			t.Fatal("expiry retained idle data or lost refreshed data")
		}
		select {
		case <-before.Changed:
		default:
			t.Fatal("expiry did not invalidate snapshots")
		}
		if len(c.pendingRequests(sent)) != 0 {
			t.Fatal("expiry replayed idle subscriptions")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := leases[1].Demand(ctx)
			done <- err
		}()
		synctest.Wait()
		requests = c.pendingRequests(sent)
		if len(requests) != 1 || !slices.Equal(requests[0].ResourceNamesSubscribe, []string{"workload-00001"}) {
			t.Fatalf("expired resource not demanded: %v", requests)
		}
		time.Sleep(time.Second)
		if err = <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expired resource served: %v", err)
		}
	})
}

func TestReconnectGraceDeadlineSurvivesPartialSyncAndRetries(t *testing.T) {
	withSubscriptionClient(t, Watch{TypeURL: testType, ReconnectGrace: 5 * time.Second}, func(t *testing.T, c *Client) {
		a, b := acquire(t, c, "a"), acquire(t, c, "b")
		defer a.Release()
		defer b.Release()
		publishString(t, c, "a", "old")
		publishString(t, c, "b", "old")
		c.reset()
		deadline := c.types[testType].graceUntil
		time.Sleep(2 * time.Second)
		publishString(t, c, "b", "fresh")
		time.Sleep(time.Second)
		c.reset()
		if c.types[testType].graceUntil != deadline {
			t.Fatal("partial synchronization extended grace")
		}
		for range 3 {
			c.reset()
		}
		if _, err := a.Demand(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if _, usable := c.Observe(testType); usable || len(c.Snapshot().Resources[testType]) != 0 {
			t.Fatal("old values survived the original deadline")
		}
		// No successful refresh means failed retries cannot create another window.
		c.reset()
		if !c.types[testType].graceUntil.IsZero() {
			t.Fatal("retry restarted grace")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := beginDemand(ctx, c, "a")
		time.Sleep(time.Second)
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("outage lookup: %v", err)
		}
	})
}

func TestReconnectGraceDeletionNeverFallsBack(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{
			TypeURL:        testType,
			ReconnectGrace: 5 * time.Second,
			OnDelete:       func(string) DeleteAction { return ReleaseSubscription },
		},
		func(t *testing.T, c *Client) {
			lease := acquire(t, c, "a")
			defer lease.Release()
			publishString(t, c, "a", "old", "alias")
			c.reset()
			removeNames(t, c, "a")
			if _, err := lease.Demand(t.Context()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("deleted generation: %v", err)
			}
			view := c.Snapshot()
			if view.Resources[testType]["a"] != nil || c.types[testType].aliases["alias"] != "" {
				t.Fatal("deletion retained stale value or alias")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := beginDemand(ctx, c, "a")
			select {
			case err := <-done:
				t.Fatalf("new demand reused deleted value: %v", err)
			default:
			}
			publishString(t, c, "a", "recreated")
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		},
	)
}

func TestReconnectGracePreservesPendingWaiters(t *testing.T) {
	withSubscriptionClient(t, Watch{TypeURL: testType, ReconnectGrace: 5 * time.Second}, func(t *testing.T, c *Client) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := beginDemand(ctx, c, "cold")
		c.reset()
		initial := c.initialRequests(map[string]map[string]*subscription{})
		if !slices.Equal(initial[0].ResourceNamesSubscribe, []string{"cold"}) {
			t.Fatalf("pending waiter lost: %v", initial)
		}
		publishString(t, c, "cold", "fresh")
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}
