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
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

func TestApplySubscriptionRecognizesExplicitWildcard(t *testing.T) {
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	changed := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"*"},
	})
	if !changed || !watch.wildcard || !watch.started {
		t.Fatalf(
			"wildcard subscription = changed:%v wildcard:%v started:%v",
			changed,
			watch.wildcard,
			watch.started,
		)
	}
	if len(watch.names) != 0 {
		t.Fatalf("explicit wildcard retained as a literal resource name: %v", watch.names)
	}
}

func TestApplySubscriptionTypeAwareImplicitWildcard(t *testing.T) {
	tests := []struct {
		name     string
		typeURL  string
		wildcard bool
	}{
		{name: "CDS", typeURL: model.ClusterType, wildcard: true},
		{name: "Address", typeURL: model.AddressType, wildcard: true},
		{name: "Sandbox", typeURL: model.SandboxType, wildcard: true},
		{name: "RDS", typeURL: model.RouteType, wildcard: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
			changed := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: test.typeURL})
			if !changed || !watch.started || watch.wildcard != test.wildcard {
				t.Fatalf("subscription = changed:%t started:%t wildcard:%t, want wildcard:%t",
					changed, watch.started, watch.wildcard, test.wildcard)
			}
			changed = applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:       test.typeURL,
				ResponseNonce: "ack",
			})
			if changed || watch.wildcard != test.wildcard {
				t.Fatalf("empty ACK changed subscription: changed:%t wildcard:%t", changed, watch.wildcard)
			}
		})
	}
}

func TestApplySubscriptionRestoresNamedInitialVersions(t *testing.T) {
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	initial := map[string]string{"route-a": "v1", "route-b": "v2"}
	changed := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                 model.RouteType,
		InitialResourceVersions: initial,
	})
	if !changed || watch.wildcard {
		t.Fatalf("restored subscription = changed:%t wildcard:%t, want changed named watch", changed, watch.wildcard)
	}
	if !maps.Equal(watch.names, sets.New("route-a", "route-b")) {
		t.Fatalf("restored names = %v, want route-a and route-b", watch.names)
	}
	if !maps.Equal(watch.sent, initial) {
		t.Fatalf("restored sent versions = %v, want %v", watch.sent, initial)
	}
}

func TestApplySubscriptionCanLeaveExplicitWildcard(t *testing.T) {
	watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: map[string]string{}}
	changed := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe:   []string{"sandbox/default"},
		ResourceNamesUnsubscribe: []string{"*"},
	})
	if !changed || watch.wildcard {
		t.Fatalf("named subscription after wildcard = changed:%v wildcard:%v", changed, watch.wildcard)
	}
	if !watch.names.Contains("sandbox/default") {
		t.Fatalf("named subscription missing: %v", watch.names)
	}
}

func TestApplySubscriptionLargeReconnect(t *testing.T) {
	initial := make(map[string]string, 30_000)
	names := []string{"*"}
	for i := range 30_000 {
		name := fmt.Sprintf("name-%d", i)
		initial[name] = "v1"
		names = append(names, name)
	}
	for _, tc := range []struct {
		name         string
		typeURL      string
		subscribe    []string
		unsubscribe  []string
		wantWildcard bool
		wantNames    []string
	}{
		{name: "explicit wildcard", typeURL: model.AddressType, subscribe: []string{"*"}, wantWildcard: true},
		{name: "implicit wildcard", typeURL: model.AddressType, wantWildcard: true},
		{
			name:         "wildcard with named subscription",
			typeURL:      model.AddressType,
			subscribe:    []string{"name-0", "*"},
			wantWildcard: true,
			wantNames:    []string{"name-0"},
		},
		{
			name:        "leave wildcard on reconnect",
			typeURL:     model.AddressType,
			subscribe:   []string{"*", "name-0"},
			unsubscribe: []string{"*"},
			wantNames:   []string{"name-0"},
		},
		{name: "wildcard with large named subscription", typeURL: model.AddressType, subscribe: names, wantWildcard: true, wantNames: names[1:]},
		{name: "named reconnect", typeURL: model.RouteType, wantNames: names[1:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
			changed := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:                  tc.typeURL,
				ResourceNamesSubscribe:   tc.subscribe,
				ResourceNamesUnsubscribe: tc.unsubscribe,
				InitialResourceVersions:  initial,
			})
			if !changed || watch.wildcard != tc.wantWildcard {
				t.Fatalf("reconnect = changed:%t wildcard:%t", changed, watch.wildcard)
			}
			if !maps.Equal(watch.sent, initial) {
				t.Fatal("reconnect lost initial resource versions")
			}
			wantNames := sets.New(tc.wantNames...)
			if !maps.Equal(watch.names, wantNames) {
				t.Fatalf("retained %d named subscriptions, want %d", len(watch.names), len(wantNames))
			}
		})
	}
}

func TestApplySubscriptionLargeNamedSubscriptions(t *testing.T) {
	const count = 30_000
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("name-%d", i)
	}
	for _, batchSize := range []int{count, count / 3} {
		t.Run(fmt.Sprintf("batch=%d", batchSize), func(t *testing.T) {
			watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
			for offset := 0; offset < count; offset += batchSize {
				changed := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
					TypeUrl:                model.RouteType,
					ResourceNamesSubscribe: names[offset : offset+batchSize],
				})
				if !changed {
					t.Fatalf("subscription at offset %d: changed=%t", offset, changed)
				}
			}
			if watch.wildcard || !maps.Equal(watch.names, sets.New(names...)) {
				t.Fatal("large named subscription lost names or became wildcard")
			}
			changed := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:                model.RouteType,
				ResourceNamesSubscribe: names,
			})
			if changed {
				t.Fatalf("duplicate subscription: changed=%t", changed)
			}
			changed = applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:                  model.RouteType,
				ResourceNamesSubscribe:   []string{"replacement", "name-0"},
				ResourceNamesUnsubscribe: []string{"name-0"},
			})
			if !changed || len(watch.names) != count || watch.names.Contains("name-0") ||
				!watch.names.Contains("replacement") {
				t.Fatalf(
					"replacement lost names or unsubscribe precedence: changed=%t names=%d",
					changed,
					len(watch.names),
				)
			}
		})
	}
}

func TestAcknowledgementWithoutMatchingSendDoesNotChangeState(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sent     string
		response string
	}{
		{name: "spontaneous request", sent: "current"},
		{name: "fresh stream", response: "previous-stream"},
		{name: "fresh stream without nonce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watch := &watchState{nonceSent: tc.sent}
			for _, detail := range []*rpcstatus.Status{nil, {Code: int32(codes.InvalidArgument), Message: "rejected"}} {
				if watch.recordAcknowledgement(
					&discoveryv3.DeltaDiscoveryRequest{ResponseNonce: tc.response, ErrorDetail: detail},
				) {
					t.Fatal("matched without a corresponding successful send")
				}
				if watch.nonceAcked != "" || watch.nonceNacked != "" || watch.lastError != "" ||
					watch.lastErrorCode != codes.OK {
					t.Fatalf("unexpected acknowledgement state: %+v", watch)
				}
			}
		})
	}
}

func TestGatewayPendingResponseAcknowledgement(t *testing.T) {
	for _, mode := range []string{"ACK", "NACK", "unsubscribe"} {
		t.Run(mode, func(t *testing.T) {
			response := &discoveryv3.DeltaDiscoveryResponse{
				Nonce:            "current",
				Resources:        []*discoveryv3.Resource{{Name: "a"}, {Name: "b"}},
				RemovedResources: []string{"gone"},
			}
			watch := &watchState{
				trackAcks:       true,
				nonceSent:       response.Nonce,
				pendingResponse: response,
				names:           sets.New("a", "b"),
				sent:            map[string]string{"a": "v1", "b": "v1"},
				started:         true,
			}
			watch.recordAcknowledgement(&discoveryv3.DeltaDiscoveryRequest{ResponseNonce: "unknown"})
			if watch.pendingResponse != response || watch.pendingAcks != nil {
				t.Fatal("unknown nonce changed the outstanding response")
			}
			req := &discoveryv3.DeltaDiscoveryRequest{ResponseNonce: response.Nonce}
			if mode == "unsubscribe" {
				applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{ResourceNamesUnsubscribe: []string{"b"}})
				if watch.pendingResponse != nil || len(watch.pendingAcks) != 2 || watch.pendingAcks["b"] != "" {
					t.Fatal("unsubscribe retained b or discarded other outstanding names")
				}
			}
			if mode != "ACK" {
				req.ErrorDetail = &rpcstatus.Status{Code: int32(codes.InvalidArgument), Message: "invalid a"}
			}
			watch.recordAcknowledgement(req)
			if watch.pendingResponse != nil {
				t.Fatal("ACK/NACK retained the response payload")
			}
			if mode == "ACK" {
				if watch.pendingAcks != nil || watch.recovering {
					t.Fatal("ordinary ACK allocated an index or started recovery")
				}
			} else if !watch.recovering || watch.pendingAcks["a"] != response.Nonce || watch.pendingAcks["gone"] != response.Nonce {
				t.Fatal("NACK lost outstanding additions or removals")
			}
		})
	}
}
