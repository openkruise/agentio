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

package mitm

import (
	"container/heap"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/pki"
	"istio.io/istio/pkg/util/sets"
)

type fakeGatewayAuthorizer struct {
	mu    sync.Mutex
	calls int
	scope model.ClientScope
	err   error
}

func serviceAccountPrincipal(namespace, serviceAccount string) model.Principal {
	return model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      namespace,
			ServiceAccount: serviceAccount,
		},
	}
}

func (f *fakeGatewayAuthorizer) Authorize(scope model.ClientScope) error {
	f.mu.Lock()
	f.calls++
	f.scope = scope
	f.mu.Unlock()
	return f.err
}

func (f *fakeGatewayAuthorizer) recordedCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeGatewayAuthorizer) recordedScope() model.ClientScope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scope
}

type fakeDomainSigner struct {
	mu       sync.Mutex
	revision string
	calls    int
	result   SignedCertificate
	state    krt.StaticSingleton[SignerState]
}

func (f *fakeDomainSigner) SignDNS(context.Context, string, time.Duration) (SignedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.result, nil
}

func (f *fakeDomainSigner) source() DomainSignerSource {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == nil {
		f.state = krt.NewStatic(&SignerState{Revision: f.revision}, true)
	}
	return DomainSignerSource{Signer: f, State: f.state}
}

func (f *fakeDomainSigner) rotate(revision string) {
	f.mu.Lock()
	f.revision = revision
	f.result = testSignedCertificate(revision)
	state := f.state
	f.mu.Unlock()
	state.Set(&SignerState{Revision: revision})
}

type rotationDomainSigner struct {
	fakeDomainSigner
}

type blockingRotationDomainSigner struct {
	mu       sync.Mutex
	revision string
	result   SignedCertificate
	calls    int
	started  chan int
	blocks   map[int]chan struct{}
	onReturn func()
	state    krt.StaticSingleton[SignerState]
}

type failingDomainSigner struct {
	mu       sync.Mutex
	revision string
	result   SignedCertificate
	err      error
	state    krt.StaticSingleton[SignerState]
}

func (f *failingDomainSigner) SignDNS(context.Context, string, time.Duration) (SignedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result, f.err
}

func (f *failingDomainSigner) source() DomainSignerSource {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == nil {
		f.state = krt.NewStatic(&SignerState{Revision: f.revision}, true)
	}
	return DomainSignerSource{Signer: f, State: f.state}
}

func (f *blockingRotationDomainSigner) SignDNS(context.Context, string, time.Duration) (SignedCertificate, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	result := f.result
	block := f.blocks[call]
	f.mu.Unlock()
	if f.started != nil {
		f.started <- call
	}
	if block != nil {
		<-block
	}
	if f.onReturn != nil {
		f.onReturn()
	}
	return result, nil
}

func (f *blockingRotationDomainSigner) source() DomainSignerSource {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == nil {
		f.state = krt.NewStatic(&SignerState{Revision: f.revision}, true)
	}
	return DomainSignerSource{Signer: f, State: f.state}
}

func (f *blockingRotationDomainSigner) rotate(revision string) {
	f.mu.Lock()
	f.revision = revision
	f.result = testSignedCertificate(revision)
	state := f.state
	f.mu.Unlock()
	state.Set(&SignerState{Revision: revision})
}

func testSignedCertificate(revision string) SignedCertificate {
	return SignedCertificate{
		CertificateChain: []byte("certificate-chain-" + revision),
		PrivateKey:       []byte("private-key-" + revision),
		NotAfter:         time.Now().Add(time.Hour),
		SignedAt:         time.Now(),
		SignerRevision:   revision,
	}
}

func (f *rotationDomainSigner) rotate() {
	f.fakeDomainSigner.rotate("two")
}

func TestOnDemandIssuerRotationUpdatesCacheGaugeSynchronously(t *testing.T) {
	previousMetrics := metrics.Default
	registry := metrics.NewRegistry()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = previousMetrics })

	now := time.Now()
	signer := &rotationDomainSigner{
		fakeDomainSigner: fakeDomainSigner{revision: "one", result: SignedCertificate{
			CertificateChain: []byte("certificate-chain"), PrivateKey: []byte("private-key"),
			NotAfter: now.Add(time.Hour), SignedAt: now, SignerRevision: "one",
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	issuer, err := NewOnDemandIssuer(ctx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		<-issuer.Done()
	})
	if _, err := issuer.certificate(context.Background(), "api.example.com"); err != nil {
		t.Fatal(err)
	}

	signer.rotate()
	recorder := httptest.NewRecorder()
	registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if body := recorder.Body.String(); !strings.Contains(body, "agentio_on_demand_certificates 0\n") {
		t.Fatalf("certificate cache gauge was not cleared synchronously:\n%s", body)
	}
}

func TestShortCertificateIsReusedUntilExpiry(t *testing.T) {
	now := time.Now()
	signer := &fakeDomainSigner{revision: "one", result: SignedCertificate{
		CertificateChain: []byte("certificate-chain"), PrivateKey: []byte("private-key"),
		SignedAt: now, NotAfter: now.Add(2 * time.Minute), SignerRevision: "one",
	}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	issuer, err := NewOnDemandIssuer(ctx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := issuer.certificate(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := issuer.certificate(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(second.CertificateChain), string(first.CertificateChain); got != want {
		t.Fatalf("second certificate chain = %q, want reused %q", got, want)
	}
	signer.mu.Lock()
	signCalls := signer.calls
	signer.mu.Unlock()
	if got, want := signCalls, 1; got != want {
		t.Fatalf("SignDNS calls = %d, want %d", got, want)
	}

	tests := []struct {
		name        string
		certificate SignedCertificate
		wantValid   bool
	}{
		{
			name: "expired short certificate",
			certificate: SignedCertificate{
				SignedAt: now.Add(-3 * time.Minute), NotAfter: now.Add(-time.Minute), SignerRevision: "one",
			},
		},
		{
			name: "ordinary certificate inside renewal window",
			certificate: SignedCertificate{
				SignedAt: now.Add(-30 * time.Minute), NotAfter: now.Add(5 * time.Minute), SignerRevision: "one",
			},
		},
		{
			name: "ordinary certificate outside renewal window",
			certificate: SignedCertificate{
				SignedAt: now.Add(-30 * time.Minute), NotAfter: now.Add(20 * time.Minute), SignerRevision: "one",
			},
			wantValid: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := issuer.cacheEntryValid(test.certificate, "one"); got != test.wantValid {
				t.Fatalf("cacheEntryValid() = %t, want %t", got, test.wantValid)
			}
		})
	}
}

func TestCertificateHeapOrdersAndUpdatesThreeEntries(t *testing.T) {
	now := time.Now()
	options := OnDemandOptions{RenewBefore: 10 * time.Minute, CacheMaxAge: time.Hour}
	early := newCertificateCacheEntry("early.example.com", testSignedCertificateAt(now.Add(3*time.Hour), now), now.Add(-3*time.Minute), options)
	middle := newCertificateCacheEntry("middle.example.com", testSignedCertificateAt(now.Add(3*time.Hour), now), now.Add(-2*time.Minute), options)
	late := newCertificateCacheEntry("late.example.com", testSignedCertificateAt(now.Add(3*time.Hour), now), now.Add(-time.Minute), options)
	entries := certHeap{}
	for _, entry := range []*certificateCacheEntry{late, early, middle} {
		heap.Push(&entries, entry)
	}

	if got := heap.Pop(&entries).(*certificateCacheEntry); got != early {
		t.Fatalf("first heap entry = %q, want %q", got.domain, early.domain)
	}
	late.deadline = now.Add(-4 * time.Minute)
	heap.Fix(&entries, late.index)
	if got := heap.Pop(&entries).(*certificateCacheEntry); got != late {
		t.Fatalf("updated heap entry = %q, want %q", got.domain, late.domain)
	}
	if got := heap.Pop(&entries).(*certificateCacheEntry); got != middle {
		t.Fatalf("last heap entry = %q, want %q", got.domain, middle.domain)
	}
	for _, entry := range []*certificateCacheEntry{early, middle, late} {
		if entry.index != -1 {
			t.Errorf("popped entry %q index = %d, want -1", entry.domain, entry.index)
		}
	}
}

func TestCertificateDeadlineReaperNotifiesAtRenewal(t *testing.T) {
	now := time.Now()
	issuer := newDeadlineTestIssuer(OnDemandOptions{RenewBefore: 10 * time.Minute, CacheMaxAge: time.Hour})
	entry := addDeadlineTestCertificate(issuer, "normal.example.com",
		testSignedCertificateAt(now.Add(10*time.Minute), now.Add(-30*time.Minute)), now)
	notifications := 0
	registration := watchCertificateChanges(issuer, func() { notifications++ })
	t.Cleanup(registration.UnregisterHandler)

	if _, scheduled := issuer.reap(now); scheduled {
		t.Fatal("reaper scheduled another wake after evicting the only certificate")
	}
	if _, found := issuer.cache[entry.domain]; found {
		t.Fatal("ordinary certificate remained cached at its renewal threshold")
	}
	if notifications != 1 {
		t.Fatalf("renewal notifications = %d, want 1", notifications)
	}
}

func TestOnDemandIssuerKeepsEvictionUntilSuccessfulResign(t *testing.T) {
	now := time.Now()
	signer := &failingDomainSigner{revision: "one", result: testSignedCertificate("one")}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	issuer, err := NewOnDemandIssuer(ctx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour, RenewBefore: 10 * time.Minute, CacheMaxAge: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ClientScope{Class: model.ClientEgressGateway, GatewayKey: "demo/egress"}
	if _, err := issuer.Get(context.Background(), scope, "old.example.com"); err != nil {
		t.Fatal(err)
	}
	issuer.mu.Lock()
	entry := issuer.cache["old.example.com"]
	entry.deadline = now.Add(-time.Second)
	heap.Fix(&issuer.heap, entry.index)
	issuer.mu.Unlock()
	issuer.reap(now)

	evicted := issuer.Evicted()
	if len(evicted) != 1 || evicted[0] != "old.example.com" {
		t.Fatalf("evicted domains = %v, want old.example.com", evicted)
	}
	evicted[0] = "mutated.example.com"
	if got := issuer.Evicted(); len(got) != 1 || got[0] != "old.example.com" {
		t.Fatalf("mutating eviction snapshot changed issuer state: %v", got)
	}
	if _, err := issuer.GetForSDS(context.Background(), scope, "old.example.com", false); !errors.Is(err, ErrDomainCertificateEvicted) {
		t.Fatalf("non-retry SDS lookup error = %v, want evicted sentinel", err)
	}
	if got := issuer.Evicted(); len(got) != 1 || got[0] != "old.example.com" {
		t.Fatalf("non-retry SDS lookup cleared eviction: %v", got)
	}

	signer.mu.Lock()
	signer.err = errors.New("sign failed")
	signer.mu.Unlock()
	if _, err := issuer.Get(context.Background(), scope, "old.example.com"); err == nil {
		t.Fatal("failed re-sign returned no error")
	}
	if got := issuer.Evicted(); len(got) != 1 || got[0] != "old.example.com" {
		t.Fatalf("failed re-sign cleared eviction: %v", got)
	}

	signer.mu.Lock()
	signer.err = nil
	signer.mu.Unlock()
	if _, err := issuer.Get(context.Background(), scope, "old.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := issuer.Evicted(); len(got) != 0 {
		t.Fatalf("successful re-sign left eviction state: %v", got)
	}
}

func TestOnDemandIssuerEvictedSnapshotIsImmutableAndUnordered(t *testing.T) {
	issuer := &OnDemandIssuer{evicted: sets.New(
		"z.example.com",
		"a.example.com",
	)}
	snapshot := issuer.Evicted()
	if len(snapshot) != 2 || !slices.Contains(snapshot, "a.example.com") || !slices.Contains(snapshot, "z.example.com") {
		t.Fatalf("evicted snapshot = %v, want both domains in any order", snapshot)
	}
	snapshot[0] = "mutated.example.com"
	second := issuer.Evicted()
	if len(second) != 2 || !slices.Contains(second, "a.example.com") || !slices.Contains(second, "z.example.com") {
		t.Fatalf("mutating snapshot changed issuer state: %v", second)
	}
}

func TestNonRetryFlightCannotCommitAcrossEviction(t *testing.T) {
	release := make(chan struct{})
	signer := &blockingRotationDomainSigner{
		revision: "one", result: testSignedCertificate("one"), started: make(chan int, 2),
		blocks: map[int]chan struct{}{2: release},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	source := signer.source()
	issuer := &OnDemandIssuer{
		ctx: ctx, signer: signer, signerState: source.State, authorizer: &fakeGatewayAuthorizer{},
		options: OnDemandOptions{
			LeafLifetime: time.Hour, RenewBefore: 10 * time.Minute, CacheMaxAge: time.Hour,
			CacheMaxEntries: defaultCacheMaxEntries, SignConcurrency: defaultSignConcurrency,
		},
		cache: make(map[string]*certificateCacheEntry), heap: make(certHeap, 0), evicted: sets.New[string](),
		cacheUpdated: make(chan struct{}, 1), flights: make(map[string]*certificateFlight),
		signSlots: make(chan struct{}, defaultSignConcurrency),
		changes:   krt.NewStatic(&CertificateGeneration{}, true),
	}
	scope := model.ClientScope{Class: model.ClientEgressGateway, GatewayKey: "demo/egress"}
	if _, err := issuer.Get(context.Background(), scope, "old.example.com"); err != nil {
		t.Fatal(err)
	}
	if call := waitForSignCall(t, signer.started); call != 1 {
		t.Fatalf("initial signing call = %d, want 1", call)
	}
	now := time.Now()
	issuer.mu.Lock()
	entry := issuer.cache["old.example.com"]
	entry.certificate.NotAfter = now.Add(-time.Second)
	entry.deadline = now.Add(-time.Second)
	heap.Fix(&issuer.heap, entry.index)
	issuer.mu.Unlock()

	result := make(chan error, 1)
	go func() {
		_, getErr := issuer.GetForSDS(context.Background(), scope, "old.example.com", false)
		result <- getErr
	}()
	if call := waitForSignCall(t, signer.started); call != 2 {
		t.Fatalf("replacement signing call = %d, want 2", call)
	}
	issuer.reap(now)
	close(release)
	if err := <-result; !errors.Is(err, ErrDomainCertificateEvicted) {
		t.Fatalf("raced non-retry lookup error = %v, want evicted sentinel", err)
	}
	if got := issuer.Evicted(); len(got) != 1 || got[0] != "old.example.com" {
		t.Fatalf("raced signing flight cleared eviction: %v", got)
	}
}

func TestCertificateDeadlineReaperNotifiesAtShortExpiry(t *testing.T) {
	now := time.Now()
	issuer := newDeadlineTestIssuer(OnDemandOptions{RenewBefore: 10 * time.Minute, CacheMaxAge: time.Hour})
	entry := addDeadlineTestCertificate(issuer, "short.example.com",
		testSignedCertificateAt(now, now.Add(-5*time.Minute)), now)
	notifications := 0
	registration := watchCertificateChanges(issuer, func() { notifications++ })
	t.Cleanup(registration.UnregisterHandler)

	issuer.reap(now)
	if _, found := issuer.cache[entry.domain]; found {
		t.Fatal("short certificate remained cached at its actual expiry")
	}
	if notifications != 1 {
		t.Fatalf("expiry notifications = %d, want 1", notifications)
	}
}

func TestCertificateMaxAgeUsesLocalInsertionTime(t *testing.T) {
	now := time.Now()
	issuer := newDeadlineTestIssuer(OnDemandOptions{RenewBefore: 10 * time.Minute, CacheMaxAge: 30 * time.Minute})
	entry := addDeadlineTestCertificate(issuer, "skewed.example.com",
		testSignedCertificateAt(now.Add(time.Hour), now.Add(-24*time.Hour)), now)

	wait, scheduled := issuer.reap(now)
	if !scheduled || wait != 30*time.Minute {
		t.Fatalf("next max-age wake = (%v, %t), want (30m, true)", wait, scheduled)
	}
	if issuer.cache[entry.domain] != entry {
		t.Fatal("locally fresh certificate was evicted using signer-provided SignedAt")
	}
	issuer.reap(now.Add(30 * time.Minute))
	if _, found := issuer.cache[entry.domain]; found {
		t.Fatal("certificate remained cached after local insertion max age")
	}
}

func TestCertificateMaxAgeBatchingDoesNotDelayRenewal(t *testing.T) {
	now := time.Now()
	issuer := newDeadlineTestIssuer(OnDemandOptions{RenewBefore: 10 * time.Minute, CacheMaxAge: time.Hour})
	longCertificate := testSignedCertificateAt(now.Add(5*time.Hour), now)
	addDeadlineTestCertificate(issuer, "max-due.example.com", longCertificate, now.Add(-time.Hour))
	closeOne := addDeadlineTestCertificate(issuer, "max-five.example.com", longCertificate, now.Add(-time.Hour+5*time.Second))
	closeTwo := addDeadlineTestCertificate(issuer, "max-ten.example.com", longCertificate, now.Add(-time.Hour+10*time.Second))
	renewal := addDeadlineTestCertificate(issuer, "renewal.example.com",
		testSignedCertificateAt(now.Add(10*time.Minute+12*time.Second), now.Add(-50*time.Minute)),
		now.Add(-time.Hour+7*time.Second))
	notifications := 0
	registration := watchCertificateChanges(issuer, func() { notifications++ })
	t.Cleanup(registration.UnregisterHandler)

	wait, scheduled := issuer.reap(now)
	if !scheduled || wait != 12*time.Second {
		t.Fatalf("wake after first max-age eviction = (%v, %t), want renewal in 12s", wait, scheduled)
	}
	if closeOne.deadline != now.Add(minCertificateEvictionInterval) || closeTwo.deadline != closeOne.deadline {
		t.Fatalf("batched max-age deadlines = (%v, %v), want %v", closeOne.deadline, closeTwo.deadline,
			now.Add(minCertificateEvictionInterval))
	}
	if renewal.deadline != now.Add(12*time.Second) || renewal.reason != certificateEvictionRenewal {
		t.Fatalf("max-age-capped renewal deadline = (%v, %d), want renewal at %v",
			renewal.deadline, renewal.reason, now.Add(12*time.Second))
	}
	if notifications != 1 {
		t.Fatalf("notifications after first max-age eviction = %d, want 1", notifications)
	}

	wait, scheduled = issuer.reap(now.Add(12 * time.Second))
	if !scheduled || wait != 18*time.Second {
		t.Fatalf("wake after renewal eviction = (%v, %t), want batched max-age wake in 18s", wait, scheduled)
	}
	if _, found := issuer.cache[renewal.domain]; found {
		t.Fatal("renewal certificate was delayed by max-age batching")
	}
	if notifications != 2 {
		t.Fatalf("notifications after renewal eviction = %d, want 2", notifications)
	}

	if _, scheduled = issuer.reap(now.Add(minCertificateEvictionInterval)); scheduled {
		t.Fatal("reaper scheduled another wake after evicting the max-age batch")
	}
	if _, found := issuer.cache[closeOne.domain]; found {
		t.Fatal("first close-spaced max-age certificate remained cached")
	}
	if _, found := issuer.cache[closeTwo.domain]; found {
		t.Fatal("second close-spaced max-age certificate remained cached")
	}
	if notifications != 3 {
		t.Fatalf("notifications after max-age batch = %d, want 3", notifications)
	}
}

func newDeadlineTestIssuer(options OnDemandOptions) *OnDemandIssuer {
	if options.CacheMaxEntries <= 0 {
		options.CacheMaxEntries = defaultCacheMaxEntries
	}
	return &OnDemandIssuer{
		options: options, cache: make(map[string]*certificateCacheEntry), heap: make(certHeap, 0),
		evicted: sets.New[string](), changes: krt.NewStatic(&CertificateGeneration{}, true),
	}
}

func watchCertificateChanges(issuer *OnDemandIssuer, callback func()) krt.HandlerRegistration {
	initial := issuer.Changes().Get().Generation
	return issuer.Changes().Register(func(event krt.Event[CertificateGeneration]) {
		if event.New != nil && event.New.Generation > initial {
			callback()
		}
	})
}

func addDeadlineTestCertificate(
	issuer *OnDemandIssuer,
	domain string,
	certificate SignedCertificate,
	insertedAt time.Time,
) *certificateCacheEntry {
	entry := newCertificateCacheEntry(domain, certificate, insertedAt, issuer.options)
	issuer.cache[domain] = entry
	heap.Push(&issuer.heap, entry)
	return entry
}

func testSignedCertificateAt(notAfter, signedAt time.Time) SignedCertificate {
	return SignedCertificate{NotAfter: notAfter, SignedAt: signedAt, SignerRevision: "one"}
}

func TestCanceledSigningIsNeverCachedOrReturned(t *testing.T) {
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	signer := &blockingRotationDomainSigner{
		revision: "one", result: testSignedCertificate("one"), onReturn: cancelRequest,
	}
	issuerCtx, stopIssuer := context.WithCancel(context.Background())
	t.Cleanup(stopIssuer)
	issuer, err := NewOnDemandIssuer(issuerCtx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := issuer.certificate(requestCtx, "api.example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("certificate error = %v, want context canceled", err)
	}
	if len(certificate.CertificateChain) != 0 || len(certificate.PrivateKey) != 0 {
		t.Fatalf("canceled signing returned certificate %#v", certificate)
	}
	if cached := issuer.cachedCertificate("api.example.com"); cached != nil {
		t.Fatalf("canceled signing cached certificate %q", cached)
	}
}

func TestOnDemandIssuerUsesGatewayAuthorizer(t *testing.T) {
	denied := errors.New("gateway denied")
	authorizer := &fakeGatewayAuthorizer{err: denied}
	signer := &fakeDomainSigner{revision: "one", result: testSignedCertificate("one")}
	issuer, err := NewOnDemandIssuer(context.Background(), signer.source(), authorizer, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ClientScope{
		Class:      model.ClientEgressGateway,
		GatewayKey: "agentio-system/egress",
		Principal:  serviceAccountPrincipal("agentio-system", "egress"),
	}

	_, err = issuer.Get(context.Background(), scope, "api.example.com")
	if !errors.Is(err, denied) {
		t.Fatalf("Get error = %v, want %v", err, denied)
	}
	if calls := authorizer.recordedCalls(); calls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", calls)
	}
	if recorded := authorizer.recordedScope(); recorded != scope {
		t.Fatalf("authorizer scope = %#v, want %#v", recorded, scope)
	}
}

func TestOnDemandIssuerGetReturnsIndependentCertificateValue(t *testing.T) {
	signer := &fakeDomainSigner{revision: "one", result: testSignedCertificate("one")}
	issuer, err := NewOnDemandIssuer(context.Background(), signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ClientScope{
		Class:      model.ClientEgressGateway,
		GatewayKey: "agentio-system/egress",
		Principal:  serviceAccountPrincipal("agentio-system", "egress"),
	}
	first, err := issuer.Get(context.Background(), scope, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	first.CertificateChain[0] = 'X'
	first.PrivateKey[0] = 'X'
	second, err := issuer.Get(context.Background(), scope, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(second.CertificateChain), "certificate-chain-one"; got != want {
		t.Fatalf("cached certificate chain = %q, want %q", got, want)
	}
	if got, want := string(second.PrivateKey), "private-key-one"; got != want {
		t.Fatalf("cached private key = %q, want %q", got, want)
	}
}

func TestOnDemandIssuerCanceledLoneWaiterDiscardsSignerResult(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSigner := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	t.Cleanup(releaseSigner)
	signer := &blockingRotationDomainSigner{
		revision: "one",
		result:   testSignedCertificate("one"),
		started:  make(chan int, 1),
		blocks:   map[int]chan struct{}{1: release},
	}
	issuerCtx, stopIssuer := context.WithCancel(context.Background())
	t.Cleanup(stopIssuer)
	issuer, err := NewOnDemandIssuer(issuerCtx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ClientScope{
		Class:      model.ClientEgressGateway,
		GatewayKey: "agentio-system/egress",
		Principal:  serviceAccountPrincipal("agentio-system", "egress"),
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, getErr := issuer.Get(requestCtx, scope, "api.example.com")
		result <- getErr
	}()
	if call := waitForSignCall(t, signer.started); call != 1 {
		t.Fatalf("first signing call = %d, want 1", call)
	}
	flight := requireCertificateFlight(t, issuer, "api.example.com")
	cancelRequest()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled certificate error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("certificate request kept waiting after its context was canceled")
	}
	waitForFlightWaiters(t, issuer, flight, 0)

	releaseSigner()
	waitForCertificateFlightDone(t, flight)
	if cached := issuer.cachedCertificate("api.example.com"); cached != nil {
		t.Fatalf("canceled flight cached certificate %q", cached)
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if signer.calls != 1 {
		t.Fatalf("SignDNS calls = %d, want 1", signer.calls)
	}
}

func TestOnDemandIssuerCancelingOneOfTwoWaitersPreservesSharedFlight(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSigner := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	t.Cleanup(releaseSigner)
	signer := &blockingRotationDomainSigner{
		revision: "one",
		result:   testSignedCertificate("one"),
		started:  make(chan int, 1),
		blocks:   map[int]chan struct{}{1: release},
	}
	issuerCtx, stopIssuer := context.WithCancel(context.Background())
	t.Cleanup(stopIssuer)
	issuer, err := NewOnDemandIssuer(issuerCtx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, certificateErr := issuer.certificate(firstCtx, "api.example.com")
		first <- certificateErr
	}()
	if call := waitForSignCall(t, signer.started); call != 1 {
		t.Fatalf("first signing call = %d, want 1", call)
	}
	flight := requireCertificateFlight(t, issuer, "api.example.com")
	second := make(chan struct {
		certificate SignedCertificate
		err         error
	}, 1)
	go func() {
		certificate, certificateErr := issuer.certificate(context.Background(), "api.example.com")
		second <- struct {
			certificate SignedCertificate
			err         error
		}{certificate: certificate, err: certificateErr}
	}()
	waitForFlightWaiters(t, issuer, flight, 2)
	cancelFirst()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled certificate error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first waiter kept waiting after cancellation")
	}
	waitForFlightWaiters(t, issuer, flight, 1)
	releaseSigner()
	select {
	case completed := <-second:
		if completed.err != nil {
			t.Fatalf("active waiter certificate error = %v", completed.err)
		}
		if got, want := completed.certificate.SignerRevision, "one"; got != want {
			t.Fatalf("active waiter signer revision = %q, want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("active waiter did not receive shared signing result")
	}
	waitForCertificateFlightDone(t, flight)
	signer.mu.Lock()
	if got, want := signer.calls, 1; got != want {
		t.Errorf("SignDNS calls = %d, want %d", got, want)
	}
	signer.mu.Unlock()
	issuer.mu.RLock()
	cacheEntries := len(issuer.cache)
	cached := issuer.cache["api.example.com"]
	issuer.mu.RUnlock()
	if got, want := cacheEntries, 1; got != want {
		t.Fatalf("cache entries = %d, want %d", got, want)
	}
	if got, want := string(cached.certificate.CertificateChain), "certificate-chain-one"; got != want {
		t.Fatalf("cached certificate = %q, want %q", got, want)
	}
}

func TestOnDemandIssuerCancellationDiscardsBlockedSignerResult(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSigner := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	t.Cleanup(releaseSigner)
	signer := &blockingRotationDomainSigner{
		revision: "one",
		result:   testSignedCertificate("one"),
		started:  make(chan int, 1),
		blocks:   map[int]chan struct{}{1: release},
	}
	issuerCtx, stopIssuer := context.WithCancel(context.Background())
	issuer, err := NewOnDemandIssuer(issuerCtx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ClientScope{
		Class:      model.ClientEgressGateway,
		GatewayKey: "agentio-system/egress",
		Principal:  serviceAccountPrincipal("agentio-system", "egress"),
	}
	result := make(chan error, 1)
	go func() {
		_, certificateErr := issuer.Get(context.Background(), scope, "api.example.com")
		result <- certificateErr
	}()
	if call := waitForSignCall(t, signer.started); call != 1 {
		t.Fatalf("first signing call = %d, want 1", call)
	}
	flight := requireCertificateFlight(t, issuer, "api.example.com")
	stopIssuer()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("certificate error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("certificate request kept waiting after issuer cancellation")
	}
	waitForFlightWaiters(t, issuer, flight, 0)
	releaseSigner()
	waitForCertificateFlightDone(t, flight)
	if cached := issuer.cachedCertificate("api.example.com"); cached != nil {
		t.Fatalf("issuer-canceled flight cached certificate %q", cached)
	}
}

func TestOnDemandIssuerAuthorizesGatewayAndCachesCertificate(t *testing.T) {
	now := time.Now()
	secret := newMITMSecret(t, "agentio-system", "mitm", 24*time.Hour, now)
	ca, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	signer := newInstalledMITMSigner(ca, secret.UID, time.Hour)
	issuer, err := NewOnDemandIssuer(context.Background(), DomainSignerSource{Signer: signer, State: signer.State()}, &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ClientScope{
		Class:      model.ClientEgressGateway,
		GatewayKey: "agentio-system/egress",
		Principal:  serviceAccountPrincipal("agentio-system", "egress"),
	}
	first, err := issuer.Get(context.Background(), scope, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := issuer.Get(context.Background(), scope, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if string(first.CertificateChain) != string(second.CertificateChain) || string(first.PrivateKey) != string(second.PrivateKey) {
		t.Fatal("certificate was not cached")
	}
	leafPEM := issuer.cachedCertificate("api.example.com")
	block, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("api.example.com"); err != nil {
		t.Fatal(err)
	}

	if _, err := issuer.Get(context.Background(), scope, "*.example.com"); err == nil {
		t.Fatal("wildcard on-demand certificate request was accepted")
	}
}

func TestOnDemandIssuerMarksCachedDomainsEvictedOnRotation(t *testing.T) {
	now := time.Now()
	signer := &rotationDomainSigner{
		fakeDomainSigner: fakeDomainSigner{revision: "one", result: SignedCertificate{
			CertificateChain: []byte("certificate-chain"), PrivateKey: []byte("private-key"),
			NotAfter: now.Add(time.Hour), SignedAt: now, SignerRevision: "one",
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	issuer, err := NewOnDemandIssuer(ctx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.certificate(context.Background(), "api.example.com"); err != nil {
		t.Fatal(err)
	}
	issuer.mu.Lock()
	issuer.evicted.Insert("old.example.com")
	issuer.mu.Unlock()
	notified := make(chan struct{})
	changes := watchCertificateChanges(issuer, func() {
		if cached := issuer.cachedCertificate("api.example.com"); cached != nil {
			t.Errorf("cached certificate was visible during rotation callback: %q", cached)
		}
		close(notified)
	})
	t.Cleanup(changes.UnregisterHandler)
	signer.rotate()
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("issuer rotation callback did not complete outside issuer lock")
	}
	if cached := issuer.cachedCertificate("api.example.com"); cached != nil {
		t.Fatalf("cached certificate after rotation = %q, want nil", cached)
	}
	evicted := issuer.Evicted()
	slices.Sort(evicted)
	if want := []string{"api.example.com", "old.example.com"}; !slices.Equal(evicted, want) {
		t.Fatalf("evicted domains after rotation = %v, want %v", evicted, want)
	}
	if _, err := issuer.GetForSDS(context.Background(), model.ClientScope{}, "api.example.com", false); !errors.Is(err, ErrDomainCertificateEvicted) {
		t.Fatalf("non-explicit SDS refresh after rotation = %v, want ErrDomainCertificateEvicted", err)
	}
	issuer.mu.RLock()
	heapEntries := issuer.heap.Len()
	issuer.mu.RUnlock()
	if heapEntries != 0 {
		t.Fatalf("heap entries after rotation = %d, want 0", heapEntries)
	}

	cancel()
}

func TestOnDemandIssuerBoundsRotationEvictions(t *testing.T) {
	signer := &fakeDomainSigner{
		revision: "one",
		result:   testSignedCertificate("one"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	issuer, err := NewOnDemandIssuer(ctx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime:    time.Hour,
		RenewBefore:     10 * time.Minute,
		CacheMaxAge:     time.Hour,
		CacheMaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated := make(chan struct{}, 2)
	changes := watchCertificateChanges(issuer, func() {
		rotated <- struct{}{}
	})
	t.Cleanup(changes.UnregisterHandler)
	waitForRotation := func() {
		t.Helper()
		select {
		case <-rotated:
		case <-time.After(time.Second):
			t.Fatal("issuer rotation callback did not notify certificate changes")
		}
	}

	for _, domain := range []string{"a.example.com", "b.example.com"} {
		if _, err := issuer.certificate(context.Background(), domain); err != nil {
			t.Fatal(err)
		}
	}
	signer.rotate("two")
	waitForRotation()

	for _, domain := range []string{"c.example.com", "d.example.com"} {
		if _, err := issuer.certificate(context.Background(), domain); err != nil {
			t.Fatal(err)
		}
	}
	signer.rotate("three")
	waitForRotation()

	evicted := issuer.Evicted()
	slices.Sort(evicted)
	if want := []string{"c.example.com", "d.example.com"}; !slices.Equal(evicted, want) {
		t.Fatalf("evicted domains after repeated rotations = %v, want current rotation domains %v", evicted, want)
	}
	for _, domain := range evicted {
		if _, err := issuer.GetForSDS(context.Background(), model.ClientScope{}, domain, false); !errors.Is(err, ErrDomainCertificateEvicted) {
			t.Fatalf("non-explicit SDS refresh for %q after rotation = %v, want ErrDomainCertificateEvicted", domain, err)
		}
	}
}

func TestOnDemandIssuerDiscardsInFlightCertificatesAcrossRotations(t *testing.T) {
	firstRelease := make(chan struct{})
	secondRelease := make(chan struct{})
	signer := &blockingRotationDomainSigner{
		revision: "one",
		result:   testSignedCertificate("one"),
		started:  make(chan int, 3),
		blocks: map[int]chan struct{}{
			1: firstRelease,
			2: secondRelease,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	issuer, err := NewOnDemandIssuer(ctx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 8
	start := make(chan struct{})
	results := make(chan SignedCertificate, callers)
	errors := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			certificate, certificateErr := issuer.certificate(context.Background(), "api.example.com")
			results <- certificate
			errors <- certificateErr
		}()
	}
	close(start)

	if call := waitForSignCall(t, signer.started); call != 1 {
		t.Fatalf("first signing call = %d, want 1", call)
	}
	signer.rotate("two")
	close(firstRelease)
	if call := waitForSignCall(t, signer.started); call != 2 {
		t.Fatalf("second signing call = %d, want 2", call)
	}
	signer.rotate("three")
	close(secondRelease)
	if call := waitForSignCall(t, signer.started); call != 3 {
		t.Fatalf("third signing call = %d, want 3", call)
	}

	for range callers {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
		certificate := <-results
		if got, want := certificate.SignerRevision, "three"; got != want {
			t.Errorf("waiter received signer revision %q, want %q", got, want)
		}
		if got, want := string(certificate.CertificateChain), "certificate-chain-three"; got != want {
			t.Errorf("waiter received certificate chain %q, want %q", got, want)
		}
	}

	signer.mu.Lock()
	if got, want := signer.calls, 3; got != want {
		t.Errorf("SignDNS calls = %d, want %d", got, want)
	}
	signer.mu.Unlock()
	issuer.mu.RLock()
	cached := issuer.cache["api.example.com"]
	issuer.mu.RUnlock()
	if got, want := cached.certificate.SignerRevision, "three"; got != want {
		t.Errorf("cached signer revision = %q, want %q", got, want)
	}
	if got, want := string(cached.certificate.CertificateChain), "certificate-chain-three"; got != want {
		t.Errorf("cached certificate chain = %q, want %q", got, want)
	}
}

func TestOnDemandIssuerStopsRotationRetryWhenContextIsCanceled(t *testing.T) {
	firstRelease := make(chan struct{})
	signer := &blockingRotationDomainSigner{
		revision: "one",
		result:   testSignedCertificate("one"),
		started:  make(chan int, 1),
		blocks:   map[int]chan struct{}{1: firstRelease},
	}
	ctx, cancel := context.WithCancel(context.Background())
	issuer, err := NewOnDemandIssuer(ctx, signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, certificateErr := issuer.certificate(ctx, "api.example.com")
		result <- certificateErr
	}()
	if call := waitForSignCall(t, signer.started); call != 1 {
		t.Fatalf("first signing call = %d, want 1", call)
	}
	signer.rotate("two")
	cancel()
	close(firstRelease)

	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatalf("certificate error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("certificate retry did not stop after context cancellation")
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	if got, want := signer.calls, 1; got != want {
		t.Fatalf("SignDNS calls = %d, want %d", got, want)
	}
}

func waitForSignCall(t *testing.T, started <-chan int) int {
	t.Helper()
	select {
	case call := <-started:
		return call
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for certificate signing")
		return 0
	}
}

func requireCertificateFlight(t *testing.T, issuer *OnDemandIssuer, domain string) *certificateFlight {
	t.Helper()
	issuer.mu.RLock()
	defer issuer.mu.RUnlock()
	flight := issuer.flights[domain]
	if flight == nil {
		t.Fatalf("no active certificate flight for %q", domain)
	}
	return flight
}

func waitForFlightWaiters(t *testing.T, issuer *OnDemandIssuer, flight *certificateFlight, want int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		issuer.mu.RLock()
		got := len(flight.waiters)
		issuer.mu.RUnlock()
		if got == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("certificate flight waiters = %d, want %d", got, want)
		case <-ticker.C:
		}
	}
}

func waitForCertificateFlightDone(t *testing.T, flight *certificateFlight) {
	t.Helper()
	select {
	case <-flight.done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for certificate flight completion")
	}
}

type concurrencyTrackingSigner struct {
	mu          sync.Mutex
	revision    string
	state       krt.StaticSingleton[SignerState]
	calls       int
	inFlight    int
	maxInFlight int
	block       chan struct{}
}

func (s *concurrencyTrackingSigner) SignDNS(ctx context.Context, _ string, _ time.Duration) (SignedCertificate, error) {
	s.mu.Lock()
	s.calls++
	s.inFlight++
	if s.inFlight > s.maxInFlight {
		s.maxInFlight = s.inFlight
	}
	s.mu.Unlock()
	select {
	case <-s.block:
	case <-ctx.Done():
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
		return SignedCertificate{}, ctx.Err()
	}
	s.mu.Lock()
	s.inFlight--
	revision := s.revision
	s.mu.Unlock()
	return testSignedCertificate(revision), nil
}

func (s *concurrencyTrackingSigner) source() DomainSignerSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		s.state = krt.NewStatic(&SignerState{Revision: s.revision}, true)
	}
	return DomainSignerSource{Signer: s, State: s.state}
}

func (s *concurrencyTrackingSigner) inFlightCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inFlight
}

func TestOnDemandIssuerAppliesDefaultBounds(t *testing.T) {
	signer := &fakeDomainSigner{revision: "one", result: testSignedCertificate("one")}
	issuer, err := NewOnDemandIssuer(context.Background(), signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime: time.Hour,
		RenewBefore:  10 * time.Minute,
		CacheMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if issuer.options.CacheMaxEntries != defaultCacheMaxEntries {
		t.Fatalf("cache entry limit = %d, want default %d", issuer.options.CacheMaxEntries, defaultCacheMaxEntries)
	}
	if cap(issuer.signSlots) != defaultSignConcurrency {
		t.Fatalf("signing slots = %d, want default %d", cap(issuer.signSlots), defaultSignConcurrency)
	}
}

func TestOnDemandIssuerCapsCacheEntries(t *testing.T) {
	signer := &fakeDomainSigner{revision: "one", result: testSignedCertificate("one")}
	issuer, err := NewOnDemandIssuer(context.Background(), signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime:    time.Hour,
		RenewBefore:     10 * time.Minute,
		CacheMaxAge:     time.Hour,
		CacheMaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ClientScope{
		Class:      model.ClientEgressGateway,
		GatewayKey: "agentio-system/egress",
		Principal:  serviceAccountPrincipal("agentio-system", "egress"),
	}
	for _, domain := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if _, err := issuer.Get(context.Background(), scope, domain); err != nil {
			t.Fatalf("get certificate for %s: %v", domain, err)
		}
	}
	issuer.mu.RLock()
	cacheSize := len(issuer.cache)
	firstEvicted := issuer.evicted.Contains("a.example.com")
	issuer.mu.RUnlock()
	if cacheSize != 2 {
		t.Fatalf("cache holds %d entries, want 2", cacheSize)
	}
	if !firstEvicted {
		t.Fatal("capacity eviction did not record the evicted domain")
	}
	if _, err := issuer.GetForSDS(context.Background(), scope, "a.example.com", false); !errors.Is(err, ErrDomainCertificateEvicted) {
		t.Fatalf("non-retry SDS read of evicted domain = %v, want ErrDomainCertificateEvicted", err)
	}
	if _, err := issuer.GetForSDS(context.Background(), scope, "a.example.com", true); err != nil {
		t.Fatalf("retry SDS read of evicted domain: %v", err)
	}
	issuer.mu.RLock()
	cacheSize = len(issuer.cache)
	issuer.mu.RUnlock()
	if cacheSize != 2 {
		t.Fatalf("cache holds %d entries after re-signing, want 2", cacheSize)
	}
}

func TestOnDemandIssuerLimitsSignConcurrency(t *testing.T) {
	signer := &concurrencyTrackingSigner{revision: "one", block: make(chan struct{})}
	issuer, err := NewOnDemandIssuer(context.Background(), signer.source(), &fakeGatewayAuthorizer{}, OnDemandOptions{
		LeafLifetime:    time.Hour,
		RenewBefore:     10 * time.Minute,
		CacheMaxAge:     time.Hour,
		SignConcurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := model.ClientScope{
		Class:      model.ClientEgressGateway,
		GatewayKey: "agentio-system/egress",
		Principal:  serviceAccountPrincipal("agentio-system", "egress"),
	}
	results := make(chan error, 2)
	for _, domain := range []string{"one.example.com", "two.example.com"} {
		go func(domain string) {
			_, err := issuer.Get(context.Background(), scope, domain)
			results <- err
		}(domain)
	}
	waitForSignInFlight(t, signer, 1)
	waitForCertificateFlights(t, issuer, "one.example.com", "two.example.com")
	assertSignInFlightNeverExceeds(t, signer, 1, 100*time.Millisecond)
	close(signer.block)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("get certificate: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for certificates")
		}
	}
	signer.mu.Lock()
	maxInFlight, calls := signer.maxInFlight, signer.calls
	signer.mu.Unlock()
	if maxInFlight != 1 {
		t.Fatalf("peak concurrent SignDNS calls = %d, want 1", maxInFlight)
	}
	if calls != 2 {
		t.Fatalf("SignDNS calls = %d, want 2", calls)
	}
}

func waitForSignInFlight(t *testing.T, signer *concurrencyTrackingSigner, want int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if got := signer.inFlightCount(); got == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("SignDNS calls in flight = %d, want %d", signer.inFlightCount(), want)
		case <-ticker.C:
		}
	}
}

func waitForCertificateFlights(t *testing.T, issuer *OnDemandIssuer, domains ...string) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		issuer.mu.RLock()
		all := true
		for _, domain := range domains {
			if _, found := issuer.flights[domain]; !found {
				all = false
				break
			}
		}
		issuer.mu.RUnlock()
		if all {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("certificate flights for %v were not registered", domains)
		case <-ticker.C:
		}
	}
}

// assertSignInFlightNeverExceeds observes the signer for the whole window and
// fails the moment more than limit signings overlap. The window gives a broken
// limiter ample time to start the queued signing while the first one blocks.
func assertSignInFlightNeverExceeds(t *testing.T, signer *concurrencyTrackingSigner, limit int, window time.Duration) {
	t.Helper()
	windowEnd := time.NewTimer(window)
	defer windowEnd.Stop()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-windowEnd.C:
			return
		case <-ticker.C:
			if got := signer.inFlightCount(); got > limit {
				t.Fatalf("SignDNS calls in flight = %d, want at most %d", got, limit)
			}
		}
	}
}
