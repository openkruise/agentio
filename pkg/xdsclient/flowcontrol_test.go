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
	"testing"
	"testing/synctest"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type blockedADS struct {
	discovery.AggregatedDiscoveryServiceClient
	stream *blockedClientStream
}

func (a *blockedADS) DeltaAggregatedResources(
	ctx context.Context,
	_ ...grpc.CallOption,
) (discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesClient, error) {
	a.stream.ctx = ctx
	return a.stream, nil
}

type blockedClientStream struct {
	discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	ctx     context.Context
	replies chan *discovery.DeltaDiscoveryResponse
	sent    chan *discovery.DeltaDiscoveryRequest
	blocked chan struct{}
	release chan struct{}
}

func (s *blockedClientStream) Send(r *discovery.DeltaDiscoveryRequest) error {
	if r.Node == nil {
		select {
		case s.blocked <- struct{}{}:
		default:
		}
		select {
		case <-s.release:
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
	select {
	case s.sent <- r:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *blockedClientStream) Recv() (*discovery.DeltaDiscoveryResponse, error) {
	select {
	case r := <-s.replies:
		return r, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func TestReceiveContinuesWhileSendIsBlocked(t *testing.T) {
	withSubscriptionClient(t, Watch{TypeURL: testType, Wildcard: true}, func(t *testing.T, c *Client) {
		stream := &blockedClientStream{
			replies: make(chan *discovery.DeltaDiscoveryResponse, 4),
			sent:    make(chan *discovery.DeltaDiscoveryRequest, 4),
			blocked: make(chan struct{}, 1),
			release: make(chan struct{}),
		}
		c.ads = &blockedADS{stream: stream}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := c.runStream(ctx)
			done <- err
		}()
		synctest.Wait()
		if len(stream.sent) != 1 {
			t.Fatal("initial request not sent")
		}
		<-stream.sent
		value, err := anypb.New(wrapperspb.String("value"))
		if err != nil {
			t.Fatal(err)
		}
		stream.replies <- &discovery.DeltaDiscoveryResponse{TypeUrl: testType, Nonce: "1", Resources: []*discovery.Resource{{Name: "a", Resource: value}}}
		synctest.Wait()
		if len(stream.blocked) != 1 {
			t.Fatal("writer did not block")
		}
		stream.replies <- &discovery.DeltaDiscoveryResponse{TypeUrl: testType, Nonce: "2", Resources: []*discovery.Resource{{Name: "b", Resource: value}}}
		stream.replies <- &discovery.DeltaDiscoveryResponse{TypeUrl: testType, Nonce: "3", Resources: []*discovery.Resource{{Name: "invalid"}}}
		stream.replies <- &discovery.DeltaDiscoveryResponse{TypeUrl: testType, Nonce: "4", Resources: []*discovery.Resource{{Name: "c", Resource: value}}}
		synctest.Wait()
		if got := len(c.Snapshot().Resources[testType]); got != 3 {
			t.Fatalf("received resources while Send blocked = %d, want 3", got)
		}
		close(stream.release)
		synctest.Wait()
		if len(stream.sent) != 2 {
			t.Fatalf("sent acknowledgements = %d, want blocked ACK and latest ACK", len(stream.sent))
		}
		first, last := <-stream.sent, <-stream.sent
		if first.ResponseNonce != "1" || last.ResponseNonce != "4" || last.ErrorDetail != nil {
			t.Fatalf("ACK ordering: first=%v last=%v", first, last)
		}
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown: %v", err)
		}
	})
}

func TestAliasReassignmentInOneDeltaPreservesSubscription(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{TypeURL: testType, OnDelete: func(string) DeleteAction { return ReleaseSubscription }},
		func(t *testing.T, c *Client) {
			lease, err := c.Acquire(testType, "ip")
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			publishString(t, c, "old", "old", "ip")
			value, err := anypb.New(wrapperspb.String("new"))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.apply(
				&discovery.DeltaDiscoveryResponse{
					TypeUrl:          testType,
					Resources:        []*discovery.Resource{{Name: "new", Aliases: []string{"ip"}, Resource: value}},
					RemovedResources: []string{"old"},
				},
			); err != nil {
				t.Fatal(err)
			}
			if _, err := lease.Demand(t.Context()); err != nil {
				t.Fatalf("alias reassignment released live subscription: %v", err)
			}
			if got := c.types[testType].aliases["ip"]; got != "new" {
				t.Fatalf("alias owner=%s", got)
			}
			if len(c.types[testType].sharedAliases) != 0 {
				t.Fatal("shared alias owners retained after reassignment")
			}
		},
	)
}
