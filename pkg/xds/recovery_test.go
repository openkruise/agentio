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
	"maps"
	"slices"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

func TestGatewayNACKRecoveryIncludesUnacceptedUpdatesAndRemovals(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "latest NACK"
		if late {
			name = "NACK before newer response ACK"
		}
		t.Run(name, func(t *testing.T) {
			a := gatewayResourceOfType(t, model.RouteType, "demo/egress", "a", "initial")
			b := gatewayResourceOfType(t, model.RouteType, "demo/egress", "b", "initial")
			c := gatewayResourceOfType(t, model.RouteType, "demo/egress", "c", "initial")
			d := gatewayResourceOfType(t, model.RouteType, "demo/egress", "d", "initial")
			other := gatewayResourceOfType(t, model.RouteType, "demo/other", "a", "initial")
			sibling := gatewayResourceOfType(t, model.RouteType, "demo/egress", "a", "initial")
			sibling.Key.Name += "|native"
			sibling.Facts.AgentioEgress = true
			server := newTestServer(t, gatewayScope(), []model.Resource{a, b, c, d, other, sibling}, nil)
			stream := newFakeStream(t.Context(), 8)
			watches := map[string]*watchState{}
			subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
			handle := func(req *discoveryv3.DeltaDiscoveryRequest) {
				t.Helper()
				if err := server.server.handleRequest(
					stream,
					server.scope,
					log,
					watches,
					subscription,
					req,
				); err != nil {
					t.Fatal(err)
				}
			}
			push := func(resources ...model.Resource) *discoveryv3.DeltaDiscoveryResponse {
				t.Helper()
				before := server.resources.Snapshot()
				after, err := model.NewResourceSet(append(resources, other, sibling))
				if err != nil {
					t.Fatal(err)
				}
				server.resources.publish(after)
				update := updateBetween(before, after, before.Diff(after))
				if err := server.server.pushUpdate(stream, server.scope, log, watches, update); err != nil {
					t.Fatal(err)
				}
				sent := stream.sent()
				return sent[len(sent)-1]
			}
			ack := func(nonce string) {
				handle(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.RouteType, ResponseNonce: nonce})
			}
			handle(nodeRequest(model.RouteType, "a", "b", "c", "d"))
			ack(stream.sent()[0].Nonce)
			watch := watches[model.RouteType]
			if watch.pendingResponse != nil || watch.pendingAcks != nil {
				t.Fatal("ordinary ACK retained a response or allocated a per-resource index")
			}
			a = gatewayResourceOfType(t, model.RouteType, "demo/egress", "a", "invalid-at-client")
			b = gatewayResourceOfType(t, model.RouteType, "demo/egress", "b", "updated")
			rejected := push(a, b, c)
			newerNonce := ""
			if late {
				c = gatewayResourceOfType(t, model.RouteType, "demo/egress", "c", "updated")
				newerNonce = push(a, b, c).Nonce
			}
			count := len(stream.sent())
			handle(
				&discoveryv3.DeltaDiscoveryRequest{
					TypeUrl:       model.RouteType,
					ResponseNonce: rejected.Nonce,
					ErrorDetail:   &rpcstatus.Status{Code: 3, Message: "invalid route a"},
				},
			)
			if len(stream.sent()) != count {
				t.Fatal("NACK triggered an immediate retry")
			}
			if late {
				ack(newerNonce)
			}
			pendingBefore := maps.Clone(watch.pendingAcks)
			for i := range 3 {
				other = gatewayResourceOfType(t, model.RouteType, "demo/other", "a", fmt.Sprint(i))
				push(a, b, c)
				sibling.Hash = fmt.Sprint(i)
				push(a, b, c)
				if len(stream.sent()) != count {
					t.Fatal("unrelated gateway or variant update retried a rejected response")
				}
				if !watch.recovering || !maps.Equal(watch.pendingAcks, pendingBefore) {
					t.Fatal("unrelated update discarded uncertain updates or removals")
				}
			}
			a = gatewayResourceOfType(t, model.RouteType, "demo/egress", "a", "fixed")
			recovered := push(a, b, c)
			if got := resourceNames(recovered); !slices.Equal(got, []string{"a", "b"}) {
				t.Fatalf("recovery resources=%v, want a and b; an unrelated ACK cannot accept b", got)
			}
			if !slices.Equal(recovered.RemovedResources, []string{"d"}) {
				t.Fatalf("recovery removals=%v, want d", recovered.RemovedResources)
			}
			// Another push before the recovery ACK must keep covering uncertain names.
			c = gatewayResourceOfType(t, model.RouteType, "demo/egress", "c", "next")
			pending := push(a, b, c)
			if !slices.Equal(resourceNames(pending), []string{"a", "b", "c"}) ||
				!slices.Equal(pending.RemovedResources, []string{"d"}) {
				t.Fatalf("unacknowledged recovery lost resources: %v", pending)
			}
			ack(recovered.Nonce)
			ack(pending.Nonce)
			if watch.pendingResponse != nil || len(watch.pendingAcks) != 0 || watch.recovering {
				t.Fatal("accepted recovery retained outstanding delivery state")
			}
			c = gatewayResourceOfType(t, model.RouteType, "demo/egress", "c", "last")
			normal := push(a, b, c)
			if !slices.Equal(resourceNames(normal), []string{"c"}) || len(normal.RemovedResources) != 0 {
				t.Fatalf("ACKed recovery did not return to incremental pushes: %v", normal)
			}
			if watch.pendingResponse == nil || len(watch.pendingAcks) != 0 {
				t.Fatal("post-recovery delivery did not return to the single-response path")
			}
		})
	}
}

func TestGatewayExplicitSubscribeResendsCachedResources(t *testing.T) {
	for _, mode := range []string{"mixed", "reconnect", "ack", "alias", "internal key"} {
		t.Run(mode, func(t *testing.T) {
			a := gatewayResourceOfType(t, model.RouteType, "demo/egress", "a", "same")
			if mode == "alias" {
				var err error
				a, err = model.NewResource(a.Key, a.XDSName, a.Value, []string{"alias-a"}, a.Facts)
				if err != nil {
					t.Fatal(err)
				}
			}
			b := gatewayResourceOfType(t, model.RouteType, "demo/egress", "b", "same")
			server := newTestServer(t, gatewayScope(), []model.Resource{a, b}, nil)
			stream := newFakeStream(t.Context(), 4)
			watches := map[string]*watchState{}
			subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
			if err := server.server.handleRequest(
				stream,
				server.scope,
				log,
				watches,
				subscription,
				nodeRequest(model.RouteType, "a"),
			); err != nil {
				t.Fatal(err)
			}
			first := stream.sent()[0]
			req := request(model.RouteType, "a", "b")
			if mode == "reconnect" {
				watches = map[string]*watchState{}
				req.InitialResourceVersions = map[string]string{"a": a.Hash}
			}
			if mode == "ack" {
				req = request(model.RouteType, "a")
				req.ResponseNonce = first.Nonce
			}
			if mode == "alias" {
				req = request(model.RouteType, "alias-a")
			}
			if mode == "internal key" {
				req = request(model.RouteType, a.Key.Name)
			}
			if err := server.server.handleRequest(stream, server.scope, log, watches, subscription, req); err != nil {
				t.Fatal(err)
			}
			want := []string{"a", "b"}
			if mode == "ack" || mode == "alias" || mode == "internal key" {
				want = []string{"a"}
			}
			if len(stream.sent()) != 2 {
				t.Fatalf("responses=%d, want explicit subscribe response", len(stream.sent()))
			}
			got := stream.sent()[1]
			if !slices.Equal(resourceNames(got), want) || len(got.RemovedResources) != 0 {
				t.Fatalf("explicit subscribe response=%v, want %v", got, want)
			}
		})
	}
}

func TestGatewayFullySupersededResponse(t *testing.T) {
	for _, rejectLatest := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject_latest=%t", rejectLatest), func(t *testing.T) {
			a := gatewayResourceOfType(t, model.RouteType, "demo/egress", "a", "before")
			b := gatewayResourceOfType(t, model.RouteType, "demo/egress", "b", "before")
			server := newTestServer(t, gatewayScope(), []model.Resource{a, b}, nil)
			stream := newFakeStream(t.Context(), 4)
			watches := map[string]*watchState{}
			subscription := server.resources.Subscribe(t.Context(), server.scope)
			handle := func(req *discoveryv3.DeltaDiscoveryRequest) {
				t.Helper()
				if err := server.server.handleRequest(
					stream,
					server.scope,
					log,
					watches,
					subscription,
					req,
				); err != nil {
					t.Fatal(err)
				}
			}
			handle(nodeRequest(model.RouteType, "a", "b"))
			first := stream.sent()[0]
			before := server.resources.Snapshot()
			a = gatewayResourceOfType(t, model.RouteType, "demo/egress", "a", "after")
			b = gatewayResourceOfType(t, model.RouteType, "demo/egress", "b", "after")
			after, err := model.NewResourceSet([]model.Resource{a, b})
			if err != nil {
				t.Fatal(err)
			}
			server.resources.publish(after)
			if err := server.server.pushUpdate(
				stream,
				server.scope,
				log,
				watches,
				updateBetween(before, after, before.Diff(after)),
			); err != nil {
				t.Fatal(err)
			}
			latest := stream.sent()[1]
			watch := watches[model.RouteType]
			handle(&discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:       model.RouteType,
				ResponseNonce: first.Nonce,
				ErrorDetail:   &rpcstatus.Status{Code: 3, Message: "old response rejected"},
			})
			if watch.pendingResponse != latest || watch.pendingAcks != nil || watch.recovering {
				t.Fatal("fully superseded NACK indexed names or started recovery")
			}
			req := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.RouteType, ResponseNonce: latest.Nonce}
			if rejectLatest {
				req.ErrorDetail = &rpcstatus.Status{Code: 3, Message: "latest response rejected"}
			}
			handle(req)
			if watch.pendingResponse != nil || watch.recovering != rejectLatest ||
				(rejectLatest && len(watch.pendingAcks) != 2) || (!rejectLatest && len(watch.pendingAcks) != 0) {
				t.Fatal("latest acknowledgement lost outstanding delivery state")
			}
		})
	}
}

func TestGatewayNACKRecoveryTriggers(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, trigger := range []string{"delete", "transfer", "variant", "full", "subscribe", "key notification"} {
			t.Run(fmt.Sprintf("native=%t/%s", native, trigger), func(t *testing.T) {
				scope := gatewayScope()
				if native {
					scope.Class = model.ClientAgentioEgress
				}
				a := gatewayResourceOfType(t, model.RouteType, scope.GatewayKey, "a", "rejected")
				a.Facts.AgentioEgress = native
				a, err := model.NewResource(a.Key, a.XDSName, a.Value, nil, a.Facts)
				if err != nil {
					t.Fatal(err)
				}
				server := newTestServer(t, scope, []model.Resource{a}, nil)
				stream := newFakeStream(t.Context(), 4)
				watch := &watchState{
					started:     true,
					wildcard:    true,
					trackAcks:   true,
					recovering:  true,
					sent:        map[string]string{"a": a.Hash},
					pendingAcks: map[string]string{"a": "rejected", "deleted": "rejected"},
				}
				before := server.resources.Snapshot()
				next := a
				next.Hash = ""
				var resources []model.Resource
				switch trigger {
				case "transfer":
					next.Facts.GatewayOwner = "demo/other"
					resources = []model.Resource{next}
				case "variant":
					next.Facts.AgentioEgress = !native
					resources = []model.Resource{next}
				case "full", "subscribe", "key notification":
					resources = []model.Resource{a}
				}
				after, err := model.NewResourceSet(resources)
				if err != nil {
					t.Fatal(err)
				}
				server.resources.publish(after)
				switch trigger {
				case "subscribe":
					err = server.server.sendDiffForNames(
						stream,
						scope,
						log,
						model.RouteType,
						watch,
						true,
						[]string{"a"},
					)
				case "full":
					err = server.server.pushUpdate(
						stream,
						scope,
						log,
						map[string]*watchState{model.RouteType: watch},
						fullUpdate(t, "ignored"),
					)
				case "key notification":
					store := xdsstore.New(after)
					sub := store.Subscribe(t.Context(), scope)
					sub.Watch(model.RouteType)
					store.NotifyKeys([]model.ResourceKey{a.Key})
					err = server.server.sendIncremental(stream, scope, log, model.RouteType, watch, <-sub.Updates())
				default:
					err = server.server.sendIncremental(stream, scope, log, model.RouteType, watch,
						updateBetween(before, after, before.Diff(after)))
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(stream.sent()) != 1 {
					t.Fatal("recovery suppressed a relevant trigger")
				}
				response := stream.sent()[0]
				if trigger == "delete" || trigger == "transfer" || trigger == "variant" {
					if len(response.Resources) != 0 ||
						!slices.Equal(response.RemovedResources, []string{"a", "deleted"}) {
						t.Fatalf("lost ownership withdrawal or uncertain deletion: %v", response)
					}
				} else if !slices.Equal(resourceNames(response), []string{"a"}) ||
					!slices.Equal(response.RemovedResources, []string{"deleted"}) {
					t.Fatalf("lost uncertain updates or removals: %v", response)
				}
			})
		}
	}
}
