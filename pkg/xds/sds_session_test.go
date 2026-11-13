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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

type pendingCertificate struct {
	name   string
	ctx    context.Context
	result chan mitm.SignedCertificate
	err    chan error
}

type controlledCertificates struct {
	requests           chan pendingCertificate
	calls              atomic.Int32
	ignoreCancellation bool
	mu                 sync.Mutex
	revision           string
	generation         uint64
	authErr            error
}

func (p *controlledCertificates) Get(
	ctx context.Context,
	_ model.ClientScope,
	name string,
) (mitm.SignedCertificate, error) {
	p.calls.Add(1)
	request := pendingCertificate{
		name:   name,
		ctx:    ctx,
		result: make(chan mitm.SignedCertificate, 1),
		err:    make(chan error, 1),
	}
	p.requests <- request
	if p.ignoreCancellation {
		return <-request.result, nil
	}
	select {
	case certificate := <-request.result:
		return certificate, nil
	case err := <-request.err:
		return mitm.SignedCertificate{}, err
	case <-ctx.Done():
		return mitm.SignedCertificate{}, ctx.Err()
	}
}
func (p *controlledCertificates) Authorize(model.ClientScope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.authErr
}
func (p *controlledCertificates) SignerRevision() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revision
}

func TestSDSColdReplayKeepsADSResponsiveAndPrioritizesFreshDemand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		provider := &controlledCertificates{requests: make(chan pendingCertificate, 128), revision: "one"}
		server := newTestServer(t, gatewayScope(), []model.Resource{
			gatewayResource(t, "demo/egress", "main_internal", "mine"),
		}, provider)
		stream := newFakeStream(ctx, 8)
		names := make([]string, 100)
		for idx := range names {
			names[idx] = fmt.Sprintf("replay-%d.example.com", idx)
		}
		stream.send(nodeRequest(model.SecretType, names...))
		done := make(chan error, 1)
		go func() { done <- server.server.serveDelta(stream) }()
		synctest.Wait()
		if got := provider.calls.Load(); got != sdsStreamConcurrency {
			t.Fatalf("active requests = %d", got)
		}
		stream.send(request(model.ClusterType))
		stream.send(request(model.SecretType, "fresh.example.com"))
		synctest.Wait()
		if len(stream.responsesFor(model.ClusterType)) != 1 {
			t.Fatal("cold SDS replay blocked CDS")
		}
		if len(stream.responsesFor(model.SecretType)) != 0 {
			t.Fatal("blocked signer produced a response")
		}
		first := <-provider.requests
		for range sdsStreamConcurrency - 1 {
			<-provider.requests
		}
		first.result <- testSDSCertificate()
		synctest.Wait()
		responses := stream.responsesFor(model.SecretType)
		if len(responses) != 1 || !slices.Equal(resourceNames(responses[0]), []string{first.name}) {
			t.Fatal("ready certificate waited for replay batch")
		}
		fresh := <-provider.requests
		if fresh.name != "fresh.example.com" {
			t.Fatalf("next issuance = %s, want fresh demand", fresh.name)
		}
		fresh.result <- testSDSCertificate()
		synctest.Wait()
		responses = stream.responsesFor(model.SecretType)
		if len(responses) != 2 || !slices.Equal(resourceNames(responses[1]), []string{fresh.name}) {
			t.Fatal("fresh demand did not complete")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("disconnect = %v", err)
		}
	})
}

func TestSDSUnsubscribeDiscardsLateResultAfterResubscribe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider := &controlledCertificates{
			requests:           make(chan pendingCertificate, 2),
			revision:           "one",
			ignoreCancellation: true,
		}
		server := newTestServer(t, gatewayScope(), nil, provider)
		stream := newFakeStream(t.Context(), 4)
		done := make(chan error, 1)
		go func() { done <- server.server.serveDelta(stream) }()
		const name = "api.example.com"
		stream.send(nodeRequest(model.SecretType, name))
		synctest.Wait()
		old := <-provider.requests
		unsubscribe := request(model.SecretType)
		unsubscribe.ResourceNamesUnsubscribe = []string{name}
		stream.send(unsubscribe)
		stream.send(request(model.SecretType, name))
		synctest.Wait()
		if !errors.Is(old.ctx.Err(), context.Canceled) {
			t.Fatal("unsubscribe did not cancel issuance")
		}
		current := <-provider.requests
		current.result <- testSDSCertificate()
		synctest.Wait()
		late := testSDSCertificate()
		late.CertificateChain = []byte("stale certificate")
		old.result <- late
		synctest.Wait()
		responses := stream.responsesFor(model.SecretType)
		if len(responses) != 1 || !slices.Equal(resourceNames(responses[0]), []string{name}) ||
			len(responses[0].RemovedResources) != 0 {
			t.Fatalf("late result affected replacement: %v", responses)
		}
		stream.closeRequests()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestSDSCompletionRevalidatesBeforeSend(t *testing.T) {
	for _, change := range []string{"rotation", "expiry", "authorization"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := &controlledCertificates{requests: make(chan pendingCertificate, 2), revision: "one"}
				server := newTestServer(t, gatewayScope(), nil, provider)
				generator := newTestSDSGenerator(t, provider)
				q := newSDSSession(t.Context(), generator, gatewayScope())
				defer q.cancel()
				const name = "api.example.com"
				watch := &watchState{names: sets.New(name), sent: make(map[string]string), sds: q}
				stream := newFakeStream(t.Context(), 1)
				q.subscribe([]string{name})
				q.start(server.resources.Snapshot())
				pending := <-provider.requests
				pending.result <- testSDSCertificate()
				ready := <-q.ready
				switch change {
				case "rotation":
					provider.revision = "two"
				case "expiry":
					time.Sleep(time.Hour)
				case "authorization":
					provider.authErr = errors.New("gateway deleted")
				}
				if err := server.server.sendSDSCompletions(stream, log, watch, ready); err != nil {
					t.Fatal(err)
				}
				if change == "authorization" {
					responses := stream.sent()
					if len(responses) != 1 || len(responses[0].Resources) != 0 ||
						!slices.Equal(responses[0].RemovedResources, []string{name}) {
						t.Fatal("revoked gateway received certificate")
					}
					return
				}
				if len(stream.sent()) != 0 || len(watch.sent) != 0 {
					t.Fatal("stale completion sent or committed")
				}
				retry := <-provider.requests
				cert := testSDSCertificate()
				cert.SignerRevision = provider.revision
				retry.result <- cert
				if err := server.server.sendSDSCompletions(stream, log, watch, <-q.ready); err != nil {
					t.Fatal(err)
				}
				if len(stream.sent()) != 1 ||
					!strings.HasPrefix(watch.sent[name], sdsVersionPrefix(provider.revision)) {
					t.Fatal("fresh generation not committed")
				}
			})
		})
	}
}

func TestSDSUnsubscribeWinsWithinOneRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider := &controlledCertificates{requests: make(chan pendingCertificate, 1), revision: "one"}
		server := newTestServer(t, gatewayScope(), nil, provider)
		stream := newFakeStream(t.Context(), 1)
		initial := nodeRequest(model.SecretType, "api.example.com")
		initial.ResourceNamesUnsubscribe = []string{"api.example.com"}
		stream.send(initial)
		if err := server.run(t, stream); err != nil {
			t.Fatal(err)
		}
		if provider.calls.Load() != 0 {
			t.Fatal("unsubscribed name was issued")
		}
	})
}

func TestSDSReconnectInvalidatesOldCAWithoutIssuance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		provider := &controlledCertificates{requests: make(chan pendingCertificate, 1), revision: "two"}
		server := newTestServer(t, gatewayScope(), nil, provider)
		stream := newFakeStream(ctx, 1)
		initial := nodeRequest(model.SecretType, "api.example.com")
		initial.InitialResourceVersions = map[string]string{
			"api.example.com": sdsResourceVersion("one", time.Now().Add(time.Hour), "old-cert"),
		}
		stream.send(initial)
		done := make(chan error, 1)
		go func() { done <- server.server.serveDelta(stream) }()
		defer func() {
			cancel()
			<-done
		}()
		synctest.Wait()
		if provider.calls.Load() != 0 {
			t.Fatal("old history caused issuance")
		}
		for _, r := range stream.sent() {
			if slices.Contains(r.RemovedResources, "api.example.com") {
				return
			}
		}
		t.Fatal("old CA version was not invalidated; replacement is blocked and no future CA event is guaranteed")
	})
}

type reconnectTestSigner struct {
	calls   atomic.Int32
	started chan context.Context
	release chan struct{}
}

func (s *reconnectTestSigner) SignDNS(
	ctx context.Context,
	_ string,
	lifetime time.Duration,
) (mitm.SignedCertificate, error) {
	serial := s.calls.Add(1)
	if s.started != nil {
		s.started <- ctx
	}
	if s.release != nil {
		<-s.release
	}
	now := time.Now()
	return mitm.SignedCertificate{
		CertificateChain: []byte(fmt.Sprintf("certificate-%d", serial)),
		PrivateKey:       []byte("key"),
		SignedAt:         now,
		NotAfter:         now.Add(lifetime),
		SignerRevision:   "one",
	}, nil
}
func (*reconnectTestSigner) Authorize(model.ClientScope) error { return nil }

func TestSDSExpiryCoincidingWithReconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		signer := &reconnectTestSigner{}
		state := krt.NewStatic(&mitm.SignerState{Revision: "one"}, true)
		issuer, err := mitm.NewOnDemandIssuer(ctx, mitm.DomainSignerSource{Signer: signer, State: state}, signer,
			mitm.OnDemandOptions{LeafLifetime: 15 * time.Minute, RenewBefore: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cancel()
			<-issuer.Done()
		}()
		server := newTestServer(t, gatewayScope(), nil, issuer)
		first := newFakeStream(ctx, 1)
		first.send(nodeRequest(model.SecretType, "api.example.com"))
		if err := server.run(t, first); err != nil {
			t.Fatal(err)
		}
		old := first.sent()[0].Resources[0]
		time.Sleep(14 * time.Minute)
		second := newFakeStream(ctx, 1)
		req := nodeRequest(model.SecretType, "api.example.com")
		req.InitialResourceVersions = map[string]string{"api.example.com": old.Version}
		second.send(req)
		if err := server.run(t, second); err != nil {
			t.Fatal(err)
		}
		response := second.sent()[0]
		if signer.calls.Load() != 1 || len(response.Resources) != 0 ||
			!slices.Equal(response.RemovedResources, []string{"api.example.com"}) {
			t.Fatalf("expired history was reissued: calls=%d response=%v", signer.calls.Load(), response)
		}
		third := newFakeStream(ctx, 1)
		third.send(nodeRequest(model.SecretType, "api.example.com"))
		if err := server.run(t, third); err != nil {
			t.Fatal(err)
		}
		newer := third.sent()[0].Resources[0]
		if signer.calls.Load() != 2 || old.Version == newer.Version || newer.Ttl.AsDuration() != 14*time.Minute {
			t.Fatalf("new demand did not renew: calls=%d old=%s new=%v", signer.calls.Load(), old.Version, newer)
		}
	})
}

func TestSDSNewStreamSurvivesOldStreamCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		signer := &reconnectTestSigner{started: make(chan context.Context, 2), release: make(chan struct{})}
		state := krt.NewStatic(&mitm.SignerState{Revision: "one"}, true)
		issuer, err := mitm.NewOnDemandIssuer(ctx, mitm.DomainSignerSource{Signer: signer, State: state}, signer,
			mitm.OnDemandOptions{LeafLifetime: 15 * time.Minute, RenewBefore: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cancel()
			<-issuer.Done()
		}()
		server := newTestServer(t, gatewayScope(), nil, issuer)
		oldCtx, cancelOld := context.WithCancel(ctx)
		old := newFakeStream(oldCtx, 1)
		old.send(nodeRequest(model.SecretType, "api.example.com"))
		oldDone := server.start(old)
		synctest.Wait()
		flightCtx := <-signer.started
		current := newFakeStream(ctx, 1)
		current.send(nodeRequest(model.SecretType, "api.example.com"))
		newDone := server.start(current)
		synctest.Wait()
		cancelOld()
		<-oldDone
		synctest.Wait()
		if flightCtx.Err() != nil {
			t.Fatal("old stream canceled flight still needed by new stream")
		}
		close(signer.release)
		synctest.Wait()
		if signer.calls.Load() != 1 || len(current.sent()) != 1 {
			t.Fatalf(
				"new stream did not receive shared result: calls=%d responses=%d",
				signer.calls.Load(),
				len(current.sent()),
			)
		}
		current.closeRequests()
		if err := <-newDone; err != nil {
			t.Fatal(err)
		}
	})
}

func (p *controlledCertificates) SignerGeneration() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation
}

func TestSDSReconnectThirtyThousandVersionsOnlySignsNewDemand(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed=%t", mixed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := &controlledCertificates{requests: make(chan pendingCertificate, 2), revision: "one"}
				server := newTestServer(t, gatewayScope(), nil, provider)
				ctx, cancel := context.WithCancel(t.Context())
				stream := newFakeStream(ctx, 4)
				names := make([]string, 30000)
				versions := make(map[string]string, len(names))
				deadline := time.Now().Add(14 * time.Minute)
				for index := range names {
					names[index] = fmt.Sprintf("history-%d.example.com", index)
					versions[names[index]] = sdsResourceVersion("one", deadline, fmt.Sprintf("cert-%d", index))
				}
				if mixed {
					names = append(names, "new.example.com")
				}
				initial := nodeRequest(model.SecretType, names...)
				initial.InitialResourceVersions = versions
				stream.send(initial)
				done := make(chan error, 1)
				go func() { done <- server.server.serveDelta(stream) }()
				defer func() {
					cancel()
					<-done
				}()
				synctest.Wait()
				wantCalls := int32(0)
				if mixed {
					wantCalls = 1
				}
				if got := provider.calls.Load(); got != wantCalls {
					t.Fatalf("issuance calls = %d, want %d", got, wantCalls)
				}
				for _, response := range stream.sent() {
					if len(response.Resources) != 0 || len(response.RemovedResources) != 0 {
						t.Fatal("restored certificates were resent or removed")
					}
				}
				if !mixed {
					stream.send(request(model.SecretType, "new.example.com"))
					synctest.Wait()
				}
				pending := <-provider.requests
				if pending.name != "new.example.com" {
					t.Fatalf("signed %q", pending.name)
				}
				pending.result <- testSDSCertificate()
				synctest.Wait()
				// A subsequent same-name subscribe is fresh demand even with a stale nonce.
				repeated := request(model.SecretType, names[0])
				repeated.ResponseNonce = "stale"
				stream.send(repeated)
				synctest.Wait()
				pending = <-provider.requests
				if pending.name != names[0] {
					t.Fatalf("resubscription signed %q", pending.name)
				}
				pending.result <- testSDSCertificate()
				synctest.Wait()
				if provider.calls.Load() != 2 {
					t.Fatalf("total calls = %d", provider.calls.Load())
				}
				var emitted []string
				for _, response := range stream.sent() {
					if len(response.RemovedResources) != 0 {
						t.Fatalf("unexpected removals: %v", response.RemovedResources)
					}
					emitted = append(emitted, resourceNames(response)...)
				}
				if !slices.Equal(emitted, []string{"new.example.com", names[0]}) {
					t.Fatalf("emitted %v", emitted)
				}
			})
		})
	}
}

func TestSDSFailedCompletionRetriesOnlyAfterSignerChanges(t *testing.T) {
	for _, change := range []string{"unchanged", "recovered", "ABA"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := &controlledCertificates{requests: make(chan pendingCertificate, 2), revision: "one"}
				if change == "recovered" {
					provider.revision = ""
				}
				server := newTestServer(t, gatewayScope(), nil, provider)
				q := newSDSSession(t.Context(), newTestSDSGenerator(t, provider), gatewayScope())
				defer q.cancel()
				const name = "api.example.com"
				watch := &watchState{names: sets.New(name), sent: make(map[string]string), sds: q}
				stream := newFakeStream(t.Context(), 2)
				q.subscribe([]string{name})
				q.start(server.resources.Snapshot())
				pending := <-provider.requests
				pending.err <- errors.New("old signer failure")
				failed := <-q.ready
				if change != "unchanged" {
					provider.mu.Lock()
					provider.revision = "one"
					provider.generation += 2
					provider.mu.Unlock()
				}
				if err := server.server.sendSDSCompletions(stream, log, watch, failed); err != nil {
					t.Fatal(err)
				}
				if change == "unchanged" {
					responses := stream.sent()
					if len(responses) != 1 || !slices.Equal(responses[0].RemovedResources, []string{name}) ||
						provider.calls.Load() != 1 {
						t.Fatalf("stable failure did not terminate: %v", responses)
					}
					return
				}
				if len(stream.sent()) != 0 {
					t.Fatal("old failure removed current demand")
				}
				pending = <-provider.requests
				pending.result <- testSDSCertificate()
				if err := server.server.sendSDSCompletions(stream, log, watch, <-q.ready); err != nil {
					t.Fatal(err)
				}
				responses := stream.sent()
				if len(responses) != 1 || !slices.Equal(resourceNames(responses[0]), []string{name}) ||
					len(responses[0].RemovedResources) != 0 {
					t.Fatalf("recovery response = %v", responses)
				}
			})
		})
	}
}

func TestSDSRotationPreservesPendingDemand(t *testing.T) {
	for _, change := range []string{"rotation", "unavailable", "authorization"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := &controlledCertificates{requests: make(chan pendingCertificate, 2), revision: "one"}
				server := newTestServer(t, gatewayScope(), nil, provider)
				q := newSDSSession(t.Context(), newTestSDSGenerator(t, provider), gatewayScope())
				defer q.cancel()
				const active, history = "active.example.com", "history.example.com"
				version := sdsResourceVersion("one", time.Now().Add(time.Hour), "old-cert")
				watch := &watchState{
					names: sets.New(active, history),
					sent:  map[string]string{active: version, history: version},
					sds:   q,
				}
				stream := newFakeStream(t.Context(), 2)
				q.subscribe([]string{active})
				q.start(server.resources.Snapshot())
				pending := <-provider.requests
				provider.mu.Lock()
				provider.revision = "two"
				provider.generation++
				if change == "unavailable" {
					provider.revision = ""
				}
				if change == "authorization" {
					provider.authErr = errors.New("gateway revoked")
				}
				provider.mu.Unlock()
				if err := server.server.generateAndSend(
					stream,
					log,
					watch,
					GenerationRequest{
						Scope:        gatewayScope(),
						TypeURL:      model.SecretType,
						Subscription: newSubscriptionView(watch),
						Snapshot:     server.resources.Snapshot(),
						Full:         true,
					},
					false,
					nil,
				); err != nil {
					t.Fatal(err)
				}
				responses := stream.sent()
				wantRemoved := []string{history}
				if change != "rotation" {
					wantRemoved = []string{active, history}
				}
				if len(responses) != 1 || !slices.Equal(responses[0].RemovedResources, wantRemoved) {
					t.Fatalf("rotation removal = %v", responses)
				}
				if change != "rotation" {
					return
				}
				pending.result <- testSDSCertificate()
				if err := server.server.sendSDSCompletions(stream, log, watch, <-q.ready); err != nil {
					t.Fatal(err)
				}
				pending = <-provider.requests
				cert := testSDSCertificate()
				cert.SignerRevision = "two"
				pending.result <- cert
				if err := server.server.sendSDSCompletions(stream, log, watch, <-q.ready); err != nil {
					t.Fatal(err)
				}
				responses = stream.sent()
				if len(responses) != 2 || !slices.Equal(resourceNames(responses[1]), []string{active}) ||
					len(responses[1].RemovedResources) != 0 {
					t.Fatalf("replacement response = %v", responses)
				}
			})
		})
	}
}

func TestSDSReconnectStillRespondsToStaticSecretSubscription(t *testing.T) {
	const name = "gateway-cert"
	value, err := anypb.New(&tlsv3.Secret{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.SecretType, Name: "demo/egress|" + name},
		name,
		testResourceContents(value),
		nil,
		model.ResourceFacts{GatewayOwner: "demo/egress"},
	)
	if err != nil {
		t.Fatal(err)
	}
	provider := &controlledCertificates{revision: "one", authErr: errors.New("on-demand authorization denied")}
	server := newTestServer(t, gatewayScope(), []model.Resource{resource}, provider)
	stream := newFakeStream(t.Context(), 1)
	initial := nodeRequest(model.SecretType, name)
	initial.InitialResourceVersions = map[string]string{name: resource.Hash}
	stream.send(initial)
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}
	responses := stream.responsesFor(model.SecretType)
	if len(responses) != 1 || len(responses[0].Resources) != 1 || len(responses[0].RemovedResources) != 0 {
		t.Fatalf("static response = %v", responses)
	}
	wire := responses[0].Resources[0]
	if wire.Name != name || wire.Version != resource.Hash || wire.Ttl != nil || provider.calls.Load() != 0 {
		t.Fatalf("static subscription entered on-demand lifecycle: %v", wire)
	}
}

func TestSDSStaticSecretUpdatesWhileSigningBlocked(t *testing.T) {
	for _, mixedInitial := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed_initial=%t", mixedInitial), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const name = "gateway-cert"
				makeResource := func(marker string) model.Resource {
					value, err := anypb.New(&tlsv3.Secret{
						Name: name,
						Type: &tlsv3.Secret_TlsCertificate{
							TlsCertificate: &tlsv3.TlsCertificate{CertificateChain: inlineDataSource([]byte(marker))},
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					resource, err := model.NewResource(
						model.ResourceKey{TypeURL: model.SecretType, Name: "demo/egress|" + name},
						name,
						testResourceContents(value),
						nil,
						model.ResourceFacts{GatewayOwner: "demo/egress"},
					)
					if err != nil {
						t.Fatal(err)
					}
					return resource
				}
				old, current := makeResource("old"), makeResource("current")
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				provider := &controlledCertificates{
					requests: make(chan pendingCertificate, sdsStreamConcurrency),
					revision: "one",
				}
				server := newTestServer(t, gatewayScope(), []model.Resource{old}, provider)
				stream := newFakeStream(ctx, 4)
				done := make(chan error, 1)
				go func() { done <- server.server.serveDelta(stream) }()
				names := make([]string, sdsStreamConcurrency)
				for i := range names {
					names[i] = fmt.Sprintf("cold-%d.example.com", i)
				}
				if mixedInitial {
					names = append(names, name)
				}
				stream.send(nodeRequest(model.SecretType, names...))
				synctest.Wait()
				if !mixedInitial {
					stream.send(request(model.SecretType, name))
					synctest.Wait()
				}
				responses := stream.responsesFor(model.SecretType)
				if len(responses) != 1 || len(responses[0].Resources) != 1 ||
					responses[0].Resources[0].Version != old.Hash {
					t.Fatalf("static Secret blocked by on-demand issuance: %v", responses)
				}
				// An explicit subscription must resend an unchanged ordinary Secret.
				stream.send(request(model.SecretType, name))
				synctest.Wait()
				if got := len(stream.responsesFor(model.SecretType)); got != 2 {
					t.Fatalf("static resubscribe responses = %d", got)
				}
				next, err := model.NewResourceSet([]model.Resource{current})
				if err != nil {
					t.Fatal(err)
				}
				server.resources.publish(next)
				synctest.Wait()
				responses = stream.responsesFor(model.SecretType)
				if len(responses) != 3 || len(responses[2].Resources) != 1 ||
					responses[2].Resources[0].Version != current.Hash {
					t.Fatalf("static update = %v", responses)
				}
				empty, err := model.NewResourceSet(nil)
				if err != nil {
					t.Fatal(err)
				}
				server.resources.publish(empty)
				synctest.Wait()
				responses = stream.responsesFor(model.SecretType)
				if len(responses) != 4 || !slices.Equal(responses[3].RemovedResources, []string{name}) {
					t.Fatalf("static removal = %v", responses)
				}
				// Draining the signing queue must not resurrect an old static snapshot.
				for range sdsStreamConcurrency {
					pending := <-provider.requests
					pending.result <- testSDSCertificate()
				}
				synctest.Wait()
				for _, response := range stream.responsesFor(model.SecretType)[4:] {
					for _, resource := range response.Resources {
						if resource.Name == name {
							t.Fatal("late completion resurrected static Secret")
						}
					}
				}
				if got := provider.calls.Load(); got != sdsStreamConcurrency {
					t.Fatalf("sign calls = %d", got)
				}
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestSDSStaticSecretSupersedesPendingIssuance(t *testing.T) {
	for _, outcome := range []string{"success", "failure", "deleted"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const name = "api.example.com"
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				provider := &controlledCertificates{
					requests:           make(chan pendingCertificate, 1),
					revision:           "one",
					ignoreCancellation: outcome != "failure",
				}
				server := newTestServer(t, gatewayScope(), nil, provider)
				stream := newFakeStream(ctx, 1)
				done := make(chan error, 1)
				go func() { done <- server.server.serveDelta(stream) }()
				stream.send(nodeRequest(model.SecretType, name))
				synctest.Wait()
				pending := <-provider.requests
				// Publish the static resource before the old issuance finishes.
				// Both successes and failures must become stale.
				value, err := anypb.New(&tlsv3.Secret{
					Name: name,
					Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
						CertificateChain: inlineDataSource([]byte("static-current")),
					}},
				})
				if err != nil {
					t.Fatal(err)
				}
				resource, err := model.NewResource(
					model.ResourceKey{TypeURL: model.SecretType, Name: "demo/egress|" + name},
					name, testResourceContents(value), nil, model.ResourceFacts{GatewayOwner: "demo/egress"},
				)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := model.NewResourceSet([]model.Resource{resource})
				if err != nil {
					t.Fatal(err)
				}
				server.resources.publish(snapshot)
				synctest.Wait()
				responses := stream.responsesFor(model.SecretType)
				if len(responses) != 1 || len(responses[0].Resources) != 1 ||
					responses[0].Resources[0].Version != resource.Hash || responses[0].Resources[0].Ttl != nil {
					t.Fatalf("static publication = %v", responses)
				}
				if outcome == "deleted" {
					empty, err := model.NewResourceSet(nil)
					if err != nil {
						t.Fatal(err)
					}
					server.resources.publish(empty)
					synctest.Wait()
					responses = stream.responsesFor(model.SecretType)
					if len(responses) != 2 || !slices.Equal(responses[1].RemovedResources, []string{name}) {
						t.Fatalf("static removal = %v", responses)
					}
				}
				before := len(responses)
				if outcome == "failure" {
					pending.err <- errors.New("old issuance failed")
				} else {
					pending.result <- testSDSCertificate()
				}
				synctest.Wait()
				if responses = stream.responsesFor(model.SecretType); len(responses) != before {
					t.Fatalf("late issuance changed the static resource: %v", responses[before:])
				}
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestSDSStaticSnapshotSupersedesQueuedAndCompletedDemand(t *testing.T) {
	const name = "api.example.com"
	value, err := anypb.New(&tlsv3.Secret{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.SecretType, Name: "demo/egress|" + name},
		name, testResourceContents(value), nil, model.ResourceFacts{GatewayOwner: "demo/egress"},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := model.NewResourceSet([]model.Resource{resource})
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"queued", "completed", "failed"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := &controlledCertificates{
					requests: make(chan pendingCertificate, 1),
					revision: "one",
				}
				server := newTestServer(t, gatewayScope(), nil, provider)
				q := newSDSSession(t.Context(), newTestSDSGenerator(t, provider), gatewayScope())
				defer q.cancel()
				watch := &watchState{names: sets.New(name), sent: make(map[string]string), sds: q}
				stream := newFakeStream(t.Context(), 1)
				q.subscribe([]string{name})
				if phase != "queued" {
					q.start(server.resources.Snapshot())
					pending := <-provider.requests
					if phase == "failed" {
						pending.err <- errors.New("old issuance failed")
					} else {
						pending.result <- testSDSCertificate()
					}
					synctest.Wait()
				}
				// The snapshot is current before its publication notice reaches ADS.
				server.resources.publish(snapshot)
				if phase == "queued" {
					q.start(snapshot)
					synctest.Wait()
					// Queued demand must not capture a static resource and later
					// resurrect it after the snapshot removes it.
					empty, err := model.NewResourceSet(nil)
					if err != nil {
						t.Fatal(err)
					}
					server.resources.publish(empty)
				}
				select {
				case ready := <-q.ready:
					if err := server.server.sendSDSCompletions(stream, log, watch, ready); err != nil {
						t.Fatal(err)
					}
				default:
				}
				if responses := stream.sent(); len(responses) != 0 {
					t.Fatalf("async demand sent a resource owned by the static snapshot: %v", responses)
				}
			})
		})
	}
}
