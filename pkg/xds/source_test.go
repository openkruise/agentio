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
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func TestOnlySandboxDemandWaitsForObservedSource(t *testing.T) {
	for _, typ := range []string{model.SandboxType, model.TrafficPolicyType} {
		for _, observed := range []bool{true, false} {
			t.Run(typ+"/"+fmt.Sprint(observed), func(t *testing.T) {
				snapshot := selectionSnapshot(t, nil)
				source := sourceReaderFunc(func(key model.ResourceKey) (model.SourceIdentity, bool) {
					return model.SourceIdentity{UID: "source"}, observed && key.Name == "pending"
				})
				var generator ResourceGenerator = SandboxGenerator{Source: source}
				if typ == model.TrafficPolicyType {
					generator = TrafficPolicyGenerator{}
				}
				request := GenerationRequest{
					Scope:           gatewayScope(),
					Snapshot:        snapshot,
					TypeURL:         typ,
					Full:            true,
					Subscription:    SubscriptionView{names: []string{"pending", "missing"}},
					SubscribedNames: []string{"pending", "missing"},
				}
				delta, err := generator.Generate(context.Background(), request)
				if err != nil {
					t.Fatal(err)
				}
				want := 1
				if !observed || typ == model.TrafficPolicyType {
					want = 2
				}
				if len(delta.Removed) != want || delta.Removed[len(delta.Removed)-1] != "missing" {
					t.Fatalf("observed=%t: removals=%v", observed, delta.Removed)
				}
				// Loss of authorization for an already delivered resource must still
				// withdraw it; source presence cannot keep access alive.
				request.Subscription.sent = map[string]string{"pending": "old"}
				delta, err = generator.Generate(context.Background(), request)
				if err != nil || len(delta.Removed) != 2 {
					t.Fatalf("existing resource was not withdrawn: %v, %v", delta.Removed, err)
				}
			})
		}
	}
}

func TestDemandDoesNotReplayPreviousSourceIncarnation(t *testing.T) {
	resource := sandboxResource(t, "reused")
	facts := resource.Facts
	facts.SourceIdentity = model.SourceIdentity{UID: "old-object"}
	resource, err := model.NewResource(
		resource.Key,
		resource.XDSName,
		testResourceContents(testResourceValue(resource)),
		resource.Aliases,
		facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := GenerationRequest{
		Scope:           gatewayScope(),
		TypeURL:         model.SandboxType,
		Snapshot:        selectionSnapshot(t, []model.Resource{resource}),
		Full:            true,
		Subscription:    SubscriptionView{names: []string{"reused"}},
		SubscribedNames: []string{"reused"}}
	generator := SandboxGenerator{
		Source: sourceReaderFunc(func(model.ResourceKey) (model.SourceIdentity, bool) {
			return model.SourceIdentity{UID: "new-object"}, true
		}),
	}
	delta, err := generator.Generate(t.Context(), request)
	if err != nil || len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("replayed old incarnation: %+v, %v", delta, err)
	}
	request.Subscription.sent = map[string]string{"reused": resource.Hash}
	delta, err = generator.Generate(t.Context(), request)
	if err != nil || len(delta.Resources) != 0 || len(delta.Removed) != 1 {
		t.Fatalf("old incarnation not withdrawn: %+v, %v", delta, err)
	}
}

type sourceReaderFunc func(model.ResourceKey) (model.SourceIdentity, bool)

func (f sourceReaderFunc) Lookup(key model.ResourceKey) (model.SourceIdentity, bool) {
	return f(key)
}

func TestPendingConfigDeletionAndUnsubscribe(t *testing.T) {
	typ := model.SandboxType
	present := true
	source := sourceReaderFunc(func(key model.ResourceKey) (model.SourceIdentity, bool) {
		if !present && key.Name != "pending" {
			t.Fatalf("rechecked unsubscribed key %q", key.Name)
		}
		return model.SourceIdentity{UID: "source"}, present
	})
	server := newTestServer(t, gatewayScope(), nil, nil)
	server.server.generators[typ] = SandboxGenerator{Source: source}
	stream := newFakeStream(t.Context(), 1)
	watches := map[string]*watchState{}
	store := xdsstore.New(selectionSnapshot(t, nil))
	server.server.resources = store
	subscription := store.Subscribe(t.Context(), model.ClientScope{})
	push := func(name string) {
		t.Helper()
		store.NotifyKeys([]model.ResourceKey{{TypeURL: typ, Name: name}})
		if err := server.server.pushUpdate(
			stream,
			server.scope,
			log,
			watches,
			<-subscription.Updates(),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.server.handleRequest(stream, server.scope, log, watches, subscription,
		nodeRequest(typ, "pending", "cancelled")); err != nil {
		t.Fatal(err)
	}
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		watches,
		subscription,
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                  typ,
			ResourceNamesUnsubscribe: []string{"cancelled"},
		},
	); err != nil {
		t.Fatal(err)
	}
	before := len(stream.sent())
	present = false
	push("unrelated")
	if len(stream.sent()) != before {
		t.Fatal("unrelated key completed pending demand")
	}
	push("pending")
	responses := stream.sent()
	if len(responses) != before+1 || !slices.Equal(responses[before].RemovedResources, []string{"pending"}) {
		t.Fatalf("deleted demand did not receive exactly one removal: %v", responses)
	}
	if hasPendingConfigs(watches) {
		t.Fatal("resolved demand remains pending")
	}
	push("pending")
	if len(stream.sent()) != len(responses) {
		t.Fatal("resolved demand emitted a duplicate removal")
	}
}

func TestPublicationCompletesPendingConfig(t *testing.T) {
	resource := sandboxResource(t, "pending")
	server := newTestServer(t, gatewayScope(), []model.Resource{resource}, nil)
	watch := &watchState{
		names:   sets.New("pending"),
		sent:    make(map[string]string),
		pending: sets.New("pending"),
	}
	watches := map[string]*watchState{model.SandboxType: watch}
	stream := newFakeStream(t.Context(), 1)
	if err := server.server.sendDiff(stream, server.scope, log, model.SandboxType, watch, false); err != nil {
		t.Fatal(err)
	}
	if len(stream.sent()) != 1 || len(stream.sent()[0].Resources) != 1 {
		t.Fatal("publication did not deliver pending resource")
	}
	if hasPendingConfigs(watches) {
		t.Fatal("published demand remains pending")
	}
}

func TestDedicatedSandboxRefreshCompletesPendingSourceDeletion(t *testing.T) {
	present := true
	scope := model.ClientScope{Class: model.ClientDedicatedZTunnel, WorkloadUID: "own"}
	server := newTestServerWithGenerators(t, scope, nil, map[string]ResourceGenerator{
		model.SandboxType: SandboxGenerator{
			Source: sourceReaderFunc(func(model.ResourceKey) (model.SourceIdentity, bool) {
				return model.SourceIdentity{UID: "source"}, present
			}),
		},
	})
	store := xdsstore.New(selectionSnapshot(t, nil))
	server.server.resources = store
	subscription := store.Subscribe(t.Context(), scope)
	stream := newFakeStream(t.Context(), 1)
	watches := map[string]*watchState{}
	if err := server.server.handleRequest(stream, scope, log, watches, subscription,
		nodeRequest(model.SandboxType, "pending")); err != nil {
		t.Fatal(err)
	}
	if !hasPendingConfigs(watches) {
		t.Fatal("unpublished Sandbox demand was not retained")
	}
	before := len(stream.sent())
	present = false
	store.NotifyKeys([]model.ResourceKey{{TypeURL: model.SandboxType, Name: "pending"}})
	if err := server.server.pushUpdate(stream, scope, log, watches, <-subscription.Updates()); err != nil {
		t.Fatal(err)
	}
	responses := stream.sent()
	if len(responses) != before+1 || !slices.Equal(responses[before].RemovedResources, []string{"pending"}) ||
		hasPendingConfigs(watches) {
		t.Fatalf("indexed refresh did not complete deleted demand: %v", responses)
	}
}

func TestPendingConfigCompletesAfterHalfClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var deleted atomic.Bool
		source := sourceReaderFunc(func(model.ResourceKey) (model.SourceIdentity, bool) {
			return model.SourceIdentity{UID: "source"}, !deleted.Load()
		})
		server := newTestServerWithGenerators(t, gatewayScope(), nil, map[string]ResourceGenerator{
			model.SandboxType: SandboxGenerator{Source: source},
		})
		store := xdsstore.New(selectionSnapshot(t, nil))
		server.server.resources = store
		stream := newFakeStream(t.Context(), 1)
		stream.send(nodeRequest(model.SandboxType, "pending"))
		done := server.start(stream)
		synctest.Wait()
		stream.closeRequests()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("half-close abandoned pending demand: %v", err)
		default:
		}
		deleted.Store(true)
		time.Sleep(time.Second)
		synctest.Wait()
		if len(stream.sent()) != 1 {
			t.Fatal("pending demand was polled without a source event")
		}
		store.NotifyKeys([]model.ResourceKey{{TypeURL: model.SandboxType, Name: "pending"}})
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("completed demand kept half-closed stream alive")
		}
		responses := stream.sent()
		if len(responses) != 2 || !slices.Equal(responses[1].RemovedResources, []string{"pending"}) {
			t.Fatalf("missing deletion response: %v", responses)
		}
	})
}
