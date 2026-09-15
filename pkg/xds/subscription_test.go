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
	"errors"
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
	changed, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"*"},
	})
	if err != nil || !changed || !watch.wildcard || !watch.started {
		t.Fatalf("wildcard subscription = changed:%v wildcard:%v started:%v err:%v", changed, watch.wildcard, watch.started, err)
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
			changed, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{TypeUrl: test.typeURL})
			if err != nil {
				t.Fatal(err)
			}
			if !changed || !watch.started || watch.wildcard != test.wildcard {
				t.Fatalf("subscription = changed:%t started:%t wildcard:%t, want wildcard:%t",
					changed, watch.started, watch.wildcard, test.wildcard)
			}
			changed, err = applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
				TypeUrl: test.typeURL, ResponseNonce: "ack",
			})
			if err != nil || changed || watch.wildcard != test.wildcard {
				t.Fatalf("empty ACK changed subscription: changed:%t wildcard:%t err:%v", changed, watch.wildcard, err)
			}
		})
	}
}

func TestApplySubscriptionRestoresNamedInitialVersions(t *testing.T) {
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	initial := map[string]string{"route-a": "v1", "route-b": "v2"}
	changed, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                 model.RouteType,
		InitialResourceVersions: initial,
	})
	if err != nil {
		t.Fatal(err)
	}
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
	changed, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe:   []string{"sandbox/default"},
		ResourceNamesUnsubscribe: []string{"*"},
	})
	if err != nil || !changed || watch.wildcard {
		t.Fatalf("named subscription after wildcard = changed:%v wildcard:%v err:%v", changed, watch.wildcard, err)
	}
	if !watch.names.Contains("sandbox/default") {
		t.Fatalf("named subscription missing: %v", watch.names)
	}
}

// A client must not be able to grow per-connection state without bound by
// enrolling ever more resource names across requests.
func TestApplySubscriptionRejectsNamesBeyondLimit(t *testing.T) {
	watch := &watchState{names: sets.New[string](), sent: map[string]string{}}
	for i := 0; i < maxSubscriptionNames; i += 2 {
		_, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
			ResourceNamesSubscribe: []string{fmt.Sprintf("name-%d", i), fmt.Sprintf("name-%d", i+1)},
		})
		if err != nil {
			t.Fatalf("subscription below limit rejected: %v", err)
		}
	}
	if len(watch.names) != maxSubscriptionNames {
		t.Fatalf("names = %d, want %d", len(watch.names), maxSubscriptionNames)
	}
	// Re-subscribing an existing name stays within the limit.
	if _, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"name-0"},
	}); err != nil {
		t.Fatalf("re-subscription of an existing name rejected: %v", err)
	}
	// A new name beyond the limit is refused.
	if _, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"one-name-too-many"},
	}); !errors.Is(err, errTooManySubscribedNames) {
		t.Fatalf("over-limit subscription error = %v, want errTooManySubscribedNames", err)
	}
	if watch.names.Contains("one-name-too-many") {
		t.Fatalf("over-limit name was recorded: %v", watch.names)
	}
	// Unsubscribing frees room again.
	if _, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesUnsubscribe: []string{"name-0"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := applySubscription(watch, &discoveryv3.DeltaDiscoveryRequest{
		ResourceNamesSubscribe: []string{"replacement-name"},
	}); err != nil {
		t.Fatalf("subscription after unsubscribe rejected: %v", err)
	}
}

func TestAcknowledgementWithoutMatchingSendDoesNotChangeState(t *testing.T) {
	for _, tc := range []struct{ name, sent, response string }{
		{name: "spontaneous request", sent: "current"},
		{name: "fresh stream", response: "previous-stream"},
		{name: "fresh stream without nonce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watch := &watchState{nonceSent: tc.sent}
			for _, detail := range []*rpcstatus.Status{nil, {Code: int32(codes.InvalidArgument), Message: "rejected"}} {
				if watch.recordAcknowledgement(&discoveryv3.DeltaDiscoveryRequest{ResponseNonce: tc.response, ErrorDetail: detail}) {
					t.Fatal("matched without a corresponding successful send")
				}
				if watch.nonceAcked != "" || watch.nonceNacked != "" || watch.lastError != "" || watch.lastErrorCode != codes.OK {
					t.Fatalf("unexpected acknowledgement state: %+v", watch)
				}
			}
		})
	}
}
