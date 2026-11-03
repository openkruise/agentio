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

func TestSessionInitialCapacityPreservesEstablishedRequestsAndPushes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		old := addressResource(t, "cluster//Pod/demo/a", "old")
		server := newTestServerWithScheduler(t, ztunnelScope(), []model.Resource{old}, nil, NewPushScheduler(1))
		ready := newFakeStream(ctx, 4)
		ready.send(nodeRequest(model.AddressType))
		readyDone := server.start(ready)
		synctest.Wait()
		ready.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: ready.sent()[0].Nonce})
		synctest.Wait()

		// This unconfirmed stream holds initial capacity without subscribing to updates.
		blockedCtx, cancelBlocked := context.WithCancel(ctx)
		defer cancelBlocked()
		blocked := newFakeStream(blockedCtx, 1)
		blocked.send(nodeRequest("type.example/hold"))
		blockedDone := server.start(blocked)
		synctest.Wait()
		if len(blocked.sent()) != 1 {
			t.Fatal("unconfirmed stream did not receive its initial response")
		}
		second := newFakeStream(ctx, 1)
		second.send(nodeRequest(model.AddressType))
		secondDone := server.start(second)
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case err := <-secondDone:
			if status.Code(err) != codes.ResourceExhausted || len(second.sent()) != 0 {
				t.Fatalf("second initial request = %v, responses = %d", err, len(second.sent()))
			}
		default:
			t.Fatal("initial capacity wait exceeded one second")
		}

		ready.send(request(model.AddressType))
		synctest.Wait()
		if len(ready.sent()) != 2 {
			t.Fatal("established demand was blocked by occupied initial capacity")
		}
		ready.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: ready.sent()[1].Nonce})
		synctest.Wait()
		updated := addressResource(t, old.Key.Name, "updated")
		if err := server.resources.apply([]model.ResourceChange{{Key: old.Key, New: &updated}}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if len(ready.sent()) != 3 || ready.sent()[2].Resources[0].Version == ready.sent()[0].Resources[0].Version {
			t.Fatal("background update was blocked by occupied initial capacity")
		}
		ready.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.AddressType, ResponseNonce: ready.sent()[2].Nonce})
		synctest.Wait()
		ready.closeRequests()
		if err := <-readyDone; err != nil {
			t.Fatalf("established stream = %v", err)
		}
		cancelBlocked()
		if err := <-blockedDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("unconfirmed stream cancellation = %v", err)
		}
		recovered := newFakeStream(ctx, 1)
		recovered.send(nodeRequest(model.AddressType))
		recoveredDone := server.start(recovered)
		synctest.Wait()
		if len(recovered.sent()) != 1 {
			t.Fatal("new stream could not reuse released initial capacity")
		}
		recovered.closeRequests()
		if err := <-recoveredDone; err != nil {
			t.Fatal(err)
		}
	})
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

func TestSessionSharesResponseCapacityAcrossTypes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		server := newTestServerWithScheduler(t, gatewayScope(), []model.Resource{
			gatewayResource(t, "demo/egress", "cluster", "payload"),
		}, nil, NewPushScheduler(1))
		stream := newFakeStream(ctx, 4)
		stream.send(nodeRequest(model.ClusterType))
		stream.send(request(model.ListenerType))
		done := server.start(stream)
		synctest.Wait()
		responses := stream.sent()
		if len(responses) != 2 {
			t.Fatalf("two response types must share one lease: responses = %d", len(responses))
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResponseNonce: responses[0].Nonce})
		synctest.Wait()

		probe := newFakeStream(ctx, 1)
		probe.send(nodeRequest(model.ClusterType))
		probeDone := server.start(probe)
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case err := <-probeDone:
			if status.Code(err) != codes.ResourceExhausted || len(probe.sent()) != 0 {
				t.Fatalf(
					"ACK for one type released initial capacity: error = %v, responses = %d",
					err,
					len(probe.sent()),
				)
			}
		default:
			t.Fatal("initial capacity wait exceeded one second")
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       model.ListenerType,
			ResponseNonce: responses[1].Nonce,
			ErrorDetail:   &rpcstatus.Status{Code: int32(codes.InvalidArgument), Message: "rejected"},
		})
		synctest.Wait()
		recovered := newFakeStream(ctx, 1)
		recovered.send(nodeRequest(model.ClusterType))
		recoveredDone := server.start(recovered)
		synctest.Wait()
		if len(recovered.sent()) != 1 {
			t.Fatal("ACK plus NACK did not release fully consumed initial capacity")
		}
		for _, current := range []*fakeStream{stream, recovered} {
			current.closeRequests()
		}
		for _, result := range []<-chan error{done, recoveredDone} {
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		}
	})
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

func TestSessionContinuousAcknowledgementsKeepStreamAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		server := newTestServerWithScheduler(t, gatewayScope(), nil, nil, NewPushScheduler(1))
		stream := newFakeStream(ctx, 4)
		types := []string{model.ClusterType, model.ListenerType}
		stream.send(nodeRequest(types[0]))
		stream.send(request(types[1]))
		done := server.start(stream)
		synctest.Wait()
		// Each response is consumed within two seconds while another type stays outstanding.
		for round := range 3 {
			time.Sleep(2 * time.Second)
			for _, typ := range types {
				responses := stream.responsesFor(typ)
				if len(responses) != round+1 {
					t.Fatalf("%s responses = %d, want %d", typ, len(responses), round+1)
				}
				stream.send(
					&discoveryv3.DeltaDiscoveryRequest{TypeUrl: typ, ResponseNonce: responses[len(responses)-1].Nonce},
				)
				stream.send(request(typ))
				synctest.Wait()
			}
			select {
			case err := <-done:
				t.Fatalf("healthy stream making ACK progress was disconnected: %v", err)
			default:
			}
		}
		for _, typ := range types {
			responses := stream.responsesFor(typ)
			if len(responses) != 4 {
				t.Fatalf("%s responses = %d, want 4", typ, len(responses))
			}
			stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: typ, ResponseNonce: responses[3].Nonce})
		}
		stream.closeRequests()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestSessionAcknowledgementProgressUsesSentNonces(t *testing.T) {
	for _, confirmation := range []string{"unknown nonce", "older valid ACK"} {
		t.Run(confirmation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				server := newTestServerWithScheduler(t, gatewayScope(), nil, nil, NewPushScheduler(1))
				stream := newFakeStream(ctx, 4)
				stream.send(nodeRequest(model.ClusterType))
				done := server.start(stream)
				synctest.Wait()
				older := stream.sent()[0].Nonce
				time.Sleep(2 * time.Second)
				stream.send(request(model.ClusterType))
				synctest.Wait()
				time.Sleep(2 * time.Second)
				stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResponseNonce: "not-sent"})
				synctest.Wait()
				if confirmation == "older valid ACK" {
					stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResponseNonce: older})
					synctest.Wait()
					time.Sleep(2 * time.Second)
					select {
					case err := <-done:
						t.Fatalf("old valid ACK failed to advance transport progress: %v", err)
					default:
					}
					stream.send(request(model.ListenerType))
					stream.send(
						&discoveryv3.DeltaDiscoveryRequest{
							TypeUrl:       model.ClusterType,
							ResponseNonce: stream.responsesFor(model.ClusterType)[1].Nonce,
						},
					)
					synctest.Wait()
					if len(stream.responsesFor(model.ListenerType)) != 1 {
						t.Fatal("stream could not send another type after old ACK progress")
					}
					for range 2 {
						time.Sleep(2 * time.Second)
						stream.send(request(model.ClusterType))
						synctest.Wait()
						responses := stream.responsesFor(model.ClusterType)
						stream.send(
							&discoveryv3.DeltaDiscoveryRequest{
								TypeUrl:       model.ClusterType,
								ResponseNonce: responses[len(responses)-1].Nonce,
							},
						)
						synctest.Wait()
					}
				}
				time.Sleep(time.Second)
				synctest.Wait()
				select {
				case err := <-done:
					if status.Code(err) != codes.DeadlineExceeded ||
						!strings.Contains(err.Error(), "acknowledgement timeout") {
						t.Fatalf("%s: stream = %v, want acknowledgement timeout", confirmation, err)
					}
				default:
					t.Fatalf("%s extended the oldest unacknowledged response deadline", confirmation)
				}
				recovered := newFakeStream(ctx, 1)
				recovered.send(nodeRequest(model.ClusterType))
				recoveredDone := server.start(recovered)
				synctest.Wait()
				if len(recovered.sent()) != 1 {
					t.Fatal("timed-out stream did not release initial capacity")
				}
				recovered.closeRequests()
				if err := <-recoveredDone; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
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
