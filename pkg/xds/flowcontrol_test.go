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
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

func TestRequestSlotsBoundInitialSendWithoutBlockingACKOrPush(t *testing.T) {
	old := addressResource(t, "cluster//Pod/demo/a", "old")
	server := newTestServerWithScheduler(t, ztunnelScope(), []model.Resource{old}, nil, NewPushScheduler(1))
	server.server.flow.config.requestWait = 50 * time.Millisecond
	ctx := t.Context()
	ready := newFakeStream(ctx, 1)
	watches := map[string]*watchState{}
	subscription := server.resources.Subscribe(ctx, server.scope)
	readyLease := server.server.flow.newLease(ctx)
	defer readyLease.release()
	if err := server.server.handleClientRequest(
		ready,
		server.scope,
		log,
		watches,
		subscription,
		nodeRequest(model.AddressType),
		readyLease,
	); err != nil {
		t.Fatal(err)
	}
	nonce := ready.sent()[0].Nonce
	if err := server.server.handleClientRequest(
		ready,
		server.scope,
		log,
		watches,
		subscription,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: nonce},
		readyLease,
	); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	blocked := newFakeStream(ctx, 1)
	blocked.beforeSend = func() {
		close(entered)
		<-release
	}
	blockedLease := server.server.flow.newLease(ctx)
	done := make(chan error, 1)
	go func() {
		done <- server.server.handleClientRequest(blocked, server.scope, log, map[string]*watchState{},
			server.resources.Subscribe(ctx, server.scope), nodeRequest(model.AddressType), blockedLease)
	}()
	t.Cleanup(func() {
		close(release)
		<-done
		blockedLease.release()
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial response did not enter Send")
	}
	second := newFakeStream(ctx, 1)
	secondLease := server.server.flow.newLease(ctx)
	defer secondLease.release()
	err := server.server.handleClientRequest(second, server.scope, log, map[string]*watchState{},
		server.resources.Subscribe(ctx, server.scope), nodeRequest(model.AddressType), secondLease)
	if status.Code(err) != codes.ResourceExhausted || len(second.sent()) != 0 {
		t.Fatalf("second initial request = %v, responses = %d", err, len(second.sent()))
	}
	if err := server.server.handleClientRequest(ready, server.scope, log, watches, subscription,
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: nonce}, readyLease); err != nil {
		t.Fatalf("pure ACK consumed an occupied request slot: %v", err)
	}
	updated := addressResource(t, old.Key.Name, "updated")
	changes := []model.ResourceChange{{Key: old.Key, New: &updated}}
	if err := server.resources.apply(changes); err != nil {
		t.Fatal(err)
	}
	// Server pushes have their own scheduler capacity, including while a
	// client-triggered response is holding every request slot.
	if err := readyLease.acquire(server.server.flow.pushSlots); err != nil {
		t.Fatal(err)
	}
	if len(server.server.flow.pushSlots) != 1 || len(server.server.flow.initialSlots) != 1 ||
		len(server.server.flow.requestSlots) != 0 {
		t.Fatal("initial and push response pools are not independent")
	}
	if err := server.server.pushUpdate(ready, server.scope, log, watches, updateFromChanges(t, changes)); err != nil {
		t.Fatalf("push blocked by occupied request slot: %v", err)
	}
	if len(ready.sent()) != 2 {
		t.Fatalf("responses = %d, want initial plus push (ACK sends nothing)", len(ready.sent()))
	}
}

func TestRequestSlotWaitHonorsParentCancellation(t *testing.T) {
	server := newTestServerWithScheduler(t, ztunnelScope(), nil, nil, NewPushScheduler(1))
	server.server.flow.requestSlots <- struct{}{}
	defer func() { <-server.server.flow.requestSlots }()
	for _, tc := range []struct {
		name string
		code codes.Code
	}{
		{name: "canceled", code: codes.Canceled},
		{name: "deadline", code: codes.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if tc.code == codes.Canceled {
				cancel()
			}
			lease := server.server.flow.newLease(ctx)
			defer lease.release()
			if err := lease.acquire(server.server.flow.requestSlots); status.Code(err) != tc.code {
				t.Fatalf("acquireRequestSlot = %v, want %v", err, tc.code)
			}
			if len(server.server.flow.requestSlots) != 1 {
				t.Fatal("failed acquisition changed the occupied slot")
			}
		})
	}
}

func TestRequestCapacityWaitStillExpiresAfterOneSecond(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newTestServerWithScheduler(t, gatewayScope(), nil, nil, NewPushScheduler(1))
		server.server.flow.requestSlots <- struct{}{}
		defer func() { <-server.server.flow.requestSlots }()
		lease := server.server.flow.newLease(t.Context())
		defer lease.release()
		started := time.Now()
		if err := lease.acquire(server.server.flow.requestSlots); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("request capacity wait = %v, want ResourceExhausted", err)
		}
		if elapsed := time.Since(started); elapsed != time.Second {
			t.Fatalf("request capacity wait = %s, want one second", elapsed)
		}
	})
}

func TestSlowInitialStreamDoesNotBlockEstablishedDemand(t *testing.T) {
	for _, confirmation := range []string{"ACK", "NACK"} {
		t.Run(confirmation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				server := newTestServerWithScheduler(t, gatewayScope(), []model.Resource{
					gatewayResource(t, "demo/egress", "cluster", "payload"),
				}, nil, NewPushScheduler(1))
				healthy := newFakeStream(ctx, 4)
				healthy.send(nodeRequest(model.ClusterType))
				healthyDone := server.start(healthy)
				synctest.Wait()
				ack := &discoveryv3.DeltaDiscoveryRequest{
					TypeUrl:       model.ClusterType,
					ResponseNonce: healthy.sent()[0].Nonce,
				}
				if confirmation == "NACK" {
					ack.ErrorDetail = &rpcstatus.Status{Code: int32(codes.InvalidArgument), Message: "invalid config"}
				}
				healthy.send(ack)
				synctest.Wait()
				slow := newFakeStream(ctx, 1)
				slow.send(nodeRequest(model.ClusterType))
				slowDone := server.start(slow)
				synctest.Wait()
				if len(slow.sent()) != 1 || len(server.server.flow.initialSlots) != 1 {
					t.Fatal("unconfirmed slow stream did not retain initial capacity")
				}
				server.server.flow.pushSlots <- struct{}{}
				defer func() { <-server.server.flow.pushSlots }()
				healthy.send(request(model.ClusterType))
				synctest.Wait()
				responses := healthy.sent()
				if len(responses) != 2 || len(server.server.flow.requestSlots) != 1 {
					t.Fatal("confirmed stream's new query was blocked by initial or push capacity")
				}
				healthy.send(
					&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResponseNonce: responses[1].Nonce},
				)
				synctest.Wait()
				if len(server.server.flow.requestSlots) != 0 || len(server.server.flow.initialSlots) != 1 {
					t.Fatal("established ACK released the wrong response pool")
				}
				cancel()
				for _, done := range []<-chan error{healthyDone, slowDone} {
					if err := <-done; !errors.Is(err, context.Canceled) {
						t.Fatalf("stream cancellation = %v", err)
					}
				}
				if len(server.server.flow.initialSlots) != 0 {
					t.Fatal("slow stream cancellation did not release initial capacity")
				}
			})
		})
	}
}

func TestBackgroundCapacityWaitPreservesEstablishedStreamProgress(t *testing.T) {
	for _, outcome := range []string{"capacity released", "new request", "SDS completion", "canceled", "half-closed"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				provider := &controlledCertificates{requests: make(chan pendingCertificate, 1), revision: "one"}
				old := gatewayResource(t, "demo/egress", "cluster", "old")
				updated := gatewayResource(t, "demo/egress", "cluster", "new")
				server := newTestServerWithScheduler(
					t,
					gatewayScope(),
					[]model.Resource{old},
					provider,
					NewPushScheduler(1),
				)
				stream := newFakeStream(ctx, 8)
				stream.send(nodeRequest(model.ClusterType))
				done := server.start(stream)
				synctest.Wait()
				initial := stream.sent()[0]
				stream.send(
					&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResponseNonce: initial.Nonce},
				)
				synctest.Wait()
				if len(server.server.flow.requestSlots) != 0 {
					t.Fatal("initial ACK did not release request capacity")
				}
				server.server.flow.pushSlots <- struct{}{}
				occupied := true
				defer func() {
					if occupied {
						<-server.server.flow.pushSlots
					}
				}()
				if err := server.resources.apply([]model.ResourceChange{{Key: old.Key, New: &updated}}); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				time.Sleep(2 * time.Second)
				select {
				case err := <-done:
					t.Fatalf("background capacity wait disconnected an established stream: %v", err)
				default:
				}
				if len(stream.sent()) != 1 {
					t.Fatal("background push bypassed occupied response capacity")
				}
				switch outcome {
				case "capacity released":
					<-server.server.flow.pushSlots
					occupied = false
				case "new request":
					stream.send(request(model.ClusterType))
				case "SDS completion":
					stream.send(request(model.SecretType, "one.example.com"))
					synctest.Wait()
					job := <-provider.requests
					job.result <- testSDSCertificate()
				case "canceled":
					cancel()
				case "half-closed":
					stream.closeRequests()
				}
				synctest.Wait()
				if outcome != "canceled" && outcome != "half-closed" {
					if len(stream.sent()) < 2 {
						t.Fatal("stream could not make progress while background capacity was busy")
					}
					if outcome == "SDS completion" && len(stream.responsesFor(model.SecretType)) != 1 {
						t.Fatal("SDS result was blocked behind background capacity")
					}
					latest := make(map[string]string)
					for _, response := range stream.sent() {
						latest[response.TypeUrl] = response.Nonce
					}
					for typ, nonce := range latest {
						stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: typ, ResponseNonce: nonce})
					}
					synctest.Wait()
					if len(server.server.flow.requestSlots) != 0 {
						t.Fatal("ACK processing stalled after making progress during background wait")
					}
					cancel()
				}
				err := <-done
				if outcome == "half-closed" {
					if err != nil {
						t.Fatalf("half-closed stream = %v, want clean completion", err)
					}
				} else if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled stream = %v", err)
				}
				if len(server.server.pushScheduler.slots) != 0 {
					t.Fatal("background wait leaked its scheduled push")
				}
			})
		})
	}
}

func TestResponseLeaseReusesSlotUntilEveryTypeIsAcknowledged(t *testing.T) {
	server := newTestServerWithScheduler(t, gatewayScope(), []model.Resource{
		gatewayResource(t, "demo/egress", "cluster", "payload"),
	}, nil, NewPushScheduler(1))
	ctx := t.Context()
	stream := newFakeStream(ctx, 1)
	watches := map[string]*watchState{}
	subscription := server.resources.Subscribe(ctx, server.scope)
	lease := &responseLease{ctx: ctx, wait: time.Second, timeout: 5 * time.Second}
	defer lease.release()
	for _, typ := range []string{model.ClusterType, model.ListenerType} {
		if err := server.server.handleClientRequest(
			stream,
			server.scope,
			log,
			watches,
			subscription,
			nodeRequest(typ),
			lease,
		); err != nil {
			t.Fatalf("second type must reuse the first type's lease: %v", err)
		}
	}
	if len(server.server.flow.initialSlots) != 1 || len(stream.sent()) != 2 {
		t.Fatal("two response types did not share one lease")
	}
	responses := stream.sent()
	if err := server.server.handleClientRequest(
		stream,
		server.scope,
		log,
		watches,
		subscription,
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       model.ClusterType,
			ResponseNonce: responses[0].Nonce,
		},
		lease,
	); err != nil {
		t.Fatal(err)
	}
	if len(server.server.flow.initialSlots) != 1 {
		t.Fatal("ACK for one type released another type's unacknowledged response")
	}
	if server.server.flow.requestResponsePool(watches) != server.server.flow.requestSlots ||
		lease.pool != server.server.flow.initialSlots {
		t.Fatal("first ACK must promote future leases without moving the currently held initial lease")
	}
	if err := server.server.handleClientRequest(stream, server.scope, log, watches, subscription,
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       model.ListenerType,
			ResponseNonce: responses[1].Nonce,
			ErrorDetail: &rpcstatus.Status{
				Code:    int32(codes.InvalidArgument),
				Message: "rejected",
			},
		}, lease); err != nil {
		t.Fatal(err)
	}
	if len(server.server.flow.initialSlots) != 0 {
		t.Fatal("ACK plus NACK did not release fully consumed responses")
	}
}

func TestResponseLeaseDeadlineIsNotExtendedByMoreResponses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := make(chan struct{}, 1)
		lease := &responseLease{ctx: t.Context(), wait: time.Second, timeout: 5 * time.Second}
		defer lease.release()
		if err := lease.acquire(pool); err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * time.Second)
		if err := lease.acquire(pool); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		if !lease.timedOut() {
			t.Fatal("another response extended the deadline for an unread response")
		}
	})
}

func TestResponseLeaseAllowsContinuousAcknowledgementProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newTestServerWithScheduler(t, gatewayScope(), nil, nil, NewPushScheduler(1))
		ctx := t.Context()
		stream := newFakeStream(ctx, 1)
		watches := map[string]*watchState{}
		subscription := server.resources.Subscribe(ctx, server.scope)
		lease := &responseLease{ctx: ctx, wait: time.Second, timeout: 5 * time.Second}
		defer lease.release()
		types := []string{model.ClusterType, model.ListenerType}
		for _, typ := range types {
			if err := server.server.handleClientRequest(
				stream,
				server.scope,
				log,
				watches,
				subscription,
				nodeRequest(typ),
				lease,
			); err != nil {
				t.Fatal(err)
			}
		}
		// Every response is consumed within two seconds, but alternating types
		// means the stream always has one outstanding response.
		for range 3 {
			time.Sleep(2 * time.Second)
			for _, typ := range types {
				if err := server.server.handleClientRequest(
					stream,
					server.scope,
					log,
					watches,
					subscription,
					&discoveryv3.DeltaDiscoveryRequest{
						TypeUrl:       typ,
						ResponseNonce: watches[typ].nonceSent,
					},
					lease,
				); err != nil {
					t.Fatal(err)
				}
				if err := server.server.handleClientRequest(
					stream,
					server.scope,
					log,
					watches,
					subscription,
					request(typ),
					lease,
				); err != nil {
					t.Fatalf("healthy stream making ACK progress was disconnected: %v", err)
				}
			}
		}
	})
}

func TestResponseLeaseTracksOldACKWithoutMaskingStalledType(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newTestServerWithScheduler(t, gatewayScope(), nil, nil, NewPushScheduler(1))
		ctx := t.Context()
		stream := newFakeStream(ctx, 1)
		watches := map[string]*watchState{}
		subscription := server.resources.Subscribe(ctx, server.scope)
		lease := &responseLease{ctx: ctx, wait: time.Second, timeout: 5 * time.Second}
		defer lease.release()
		send := func(req *discoveryv3.DeltaDiscoveryRequest) {
			t.Helper()
			if err := server.server.handleClientRequest(
				stream,
				server.scope,
				log,
				watches,
				subscription,
				req,
				lease,
			); err != nil {
				t.Fatal(err)
			}
		}
		send(nodeRequest(model.ClusterType))
		older := watches[model.ClusterType].nonceSent
		time.Sleep(2 * time.Second)
		send(request(model.ClusterType))
		time.Sleep(2 * time.Second)
		originalDeadline := lease.deadline
		send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResponseNonce: "not-sent"})
		if !lease.deadline.Equal(originalDeadline) {
			t.Fatal("unknown nonce extended response lifetime")
		}
		if server.server.flow.requestResponsePool(watches) != server.server.flow.initialSlots {
			t.Fatal("unknown nonce promoted an unconfirmed client")
		}
		send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResponseNonce: older})
		if server.server.flow.requestResponsePool(watches) != server.server.flow.requestSlots {
			t.Fatal("older valid ACK did not establish the client")
		}
		if watches[model.ClusterType].nonceAcked != "" {
			t.Fatal("old ACK changed latest-response acknowledgement semantics")
		}
		time.Sleep(2 * time.Second)
		if lease.timedOut() {
			t.Fatal("old but valid ACK failed to advance transport progress")
		}
		send(nodeRequest(model.ListenerType))
		send(
			&discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:       model.ClusterType,
				ResponseNonce: watches[model.ClusterType].nonceSent,
			},
		)
		for range 2 {
			time.Sleep(2 * time.Second)
			send(request(model.ClusterType))
			send(
				&discoveryv3.DeltaDiscoveryRequest{
					TypeUrl:       model.ClusterType,
					ResponseNonce: watches[model.ClusterType].nonceSent,
				},
			)
		}
		time.Sleep(time.Second)
		if !lease.timedOut() {
			t.Fatal("CDS ACK progress masked an unacknowledged LDS response")
		}
	})
}

func TestSDSCompletionAcquiresResponseLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		provider := &controlledCertificates{requests: make(chan pendingCertificate, 1), revision: "one"}
		server := newTestServerWithScheduler(t, gatewayScope(), nil, provider, NewPushScheduler(1))
		stream := newFakeStream(ctx, 4)
		stream.send(nodeRequest(model.SecretType, "one.example.com"))
		done := server.start(stream)
		synctest.Wait()
		if len(server.server.flow.initialSlots) != 0 {
			t.Fatal("pending signing retained a lease without a response")
		}
		server.server.flow.initialSlots <- struct{}{}
		job := <-provider.requests
		job.result <- testSDSCertificate()
		synctest.Wait()
		if len(stream.sent()) != 0 {
			t.Fatal("SDS completion bypassed occupied response capacity")
		}
		<-server.server.flow.initialSlots
		synctest.Wait()
		responses := stream.sent()
		if len(responses) != 1 || len(server.server.flow.initialSlots) != 1 {
			t.Fatalf("SDS responses = %d, leases = %d", len(responses), len(server.server.flow.initialSlots))
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.SecretType, ResponseNonce: responses[0].Nonce})
		synctest.Wait()
		if len(server.server.flow.initialSlots) != 0 {
			t.Fatal("SDS ACK did not release response capacity")
		}
		// An established SDS stream must keep issuing while unconfirmed clients
		// occupy all initial-response capacity.
		server.server.flow.initialSlots <- struct{}{}
		defer func() { <-server.server.flow.initialSlots }()
		stream.send(request(model.SecretType, "two.example.com"))
		synctest.Wait()
		job = <-provider.requests
		job.result <- testSDSCertificate()
		synctest.Wait()
		responses = stream.sent()
		if len(responses) != 2 || len(server.server.flow.requestSlots) != 1 {
			t.Fatal("established SDS completion was blocked by initial response capacity")
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.SecretType, ResponseNonce: responses[1].Nonce})
		synctest.Wait()
		if len(server.server.flow.requestSlots) != 0 {
			t.Fatal("established SDS ACK did not release request capacity")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("SDS stream = %v", err)
		}
	})
}

type observedFlowControlStream struct {
	grpc.ServerStream
	entered chan<- struct{}
	exited  chan<- error
}

func (s *observedFlowControlStream) SendMsg(message any) error {
	s.entered <- struct{}{}
	err := s.ServerStream.SendMsg(message)
	s.exited <- err
	return err
}

func TestSendTimeoutCancelsTransportAndReleasesRequestSlot(t *testing.T) {
	var resources []model.Resource
	for _, typ := range []string{model.ClusterType, model.ListenerType, model.RouteType} {
		resources = append(resources, gatewayResourceOfType(t, typ, "demo/egress", "large", strings.Repeat("x", 2<<20)))
	}
	server := newTestServerWithScheduler(t, gatewayScope(), resources, nil, NewPushScheduler(1))
	server.server.flow.config.sendTimeout = 5 * time.Second
	server.server.flow.config.ackTimeout = 100 * time.Millisecond
	entered, exited, handlers := make(chan struct{}, 8), make(chan error, 8), make(chan error, 8)
	transport := grpc.NewServer(
		grpc.StreamInterceptor(
			func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
				err := handler(srv, &observedFlowControlStream{ServerStream: stream, entered: entered, exited: exited})
				handlers <- err
				return err
			},
		),
	)
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(transport, server.server)
	listener := bufconn.Listen(1 << 20)
	serveDone := make(chan error, 1)
	go func() { serveDone <- transport.Serve(listener) }()
	t.Cleanup(func() {
		transport.Stop()
		if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve gRPC: %v", err)
		}
	})
	connection, err := grpc.NewClient("passthrough:///flowcontrol",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithStaticStreamWindowSize(65535), grpc.WithStaticConnWindowSize(65535),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close gRPC client: %v", err)
		}
	})
	client := discoveryv3.NewAggregatedDiscoveryServiceClient(connection)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	bufferedContext, cancelBuffered := context.WithCancel(ctx)
	defer cancelBuffered()
	buffered, err := client.DeltaAggregatedResources(bufferedContext)
	if err != nil {
		t.Fatal(err)
	}
	if err := buffered.Send(nodeRequest(model.ClusterType)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("first large response failed to enqueue: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first large response did not return from SendMsg")
	}
	<-entered
	select {
	case err := <-handlers:
		if status.Code(err) != codes.DeadlineExceeded || !strings.Contains(err.Error(), "acknowledgement timeout") {
			t.Fatalf("buffered final response RPC = %v, want acknowledgement timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("final buffered response had no ACK deadline")
	}
	if len(server.server.flow.initialSlots) != 0 {
		t.Fatal("unacknowledged final response leaked lease")
	}
	cancelBuffered()
	server.server.flow.config.sendTimeout = 100 * time.Millisecond
	server.server.flow.config.ackTimeout = 5 * time.Second
	slow, err := client.DeltaAggregatedResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The first Send may only queue bytes; later responses exhaust transport
	// write quota. The client deliberately never calls Recv on this stream.
	for _, typ := range []string{model.ClusterType, model.ListenerType, model.RouteType} {
		if err := slow.Send(nodeRequest(typ)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-handlers:
		if status.Code(err) != codes.DeadlineExceeded || !strings.Contains(err.Error(), "send timeout") {
			t.Fatalf("slow stream handler returned %v, want send timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow stream RPC did not finish within the send budget")
	}
	sends := len(entered)
	if sends == 0 {
		t.Fatal("no transport SendMsg observed")
	}
	failedSends := 0
	for range sends {
		select {
		case err := <-exited:
			if err != nil {
				failedSends++
			}
		case <-time.After(time.Second):
			t.Fatal("underlying SendMsg remained blocked after RPC returned")
		}
	}
	if failedSends == 0 {
		t.Fatal("timeout did not cancel a blocked underlying SendMsg")
	}
	if len(server.server.flow.initialSlots) != 0 {
		t.Fatal("slow stream leaked its request slot")
	}
	healthy, err := client.DeltaAggregatedResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := healthy.Send(nodeRequest("type.example/empty")); err != nil {
		t.Fatal(err)
	}
	if _, err := healthy.Recv(); err != nil {
		t.Fatalf("healthy stream could not reuse released capacity: %v", err)
	}
	if err := healthy.CloseSend(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-handlers:
		if err != nil {
			t.Fatalf("healthy handler: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("healthy handler did not finish")
	}
}

func TestAuthenticationFailureStatus(t *testing.T) {
	for _, tc := range []struct {
		name         string
		err          error
		code         codes.Code
		cancelCaller bool
	}{
		{name: "API failure", err: fmt.Errorf("%w: offline", attestation.ErrTokenReviewUnavailable), code: codes.Unavailable},
		{name: "API timeout", err: fmt.Errorf("%w: %w", attestation.ErrTokenReviewUnavailable, context.DeadlineExceeded), code: codes.Unavailable},
		{name: "credential rejection", err: errors.New("token rejected"), code: codes.Unauthenticated},
		{name: "caller cancellation", err: context.Canceled, code: codes.Canceled},
		{name: "caller deadline", err: context.DeadlineExceeded, code: codes.DeadlineExceeded},
		{name: "canceled caller wins API timeout", err: fmt.Errorf("%w: %w", attestation.ErrTokenReviewUnavailable, context.DeadlineExceeded), code: codes.Canceled, cancelCaller: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(t, ztunnelScope(), nil, nil)
			server.server.authenticator = fakeAuthenticator{err: tc.err}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelCaller {
				cancel()
			}
			if err := server.server.serveDelta(newFakeStream(ctx, 1)); status.Code(err) != tc.code {
				t.Fatalf("serveDelta = %v, want %v", err, tc.code)
			}
		})
	}
}
