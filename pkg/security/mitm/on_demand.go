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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/util/nilutil"
)

type GatewayCertificateAuthorizer interface {
	Authorize(model.ClientScope) error
}

const (
	// Built-in bounds applied when OnDemandOptions leaves them non-positive.
	defaultCacheMaxEntries = 10000
	defaultSignConcurrency = 8
)

type certificateWaiter struct {
	ctx context.Context
}

type certificateFlight struct {
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	waiters     sets.Set[*certificateWaiter]
	certificate SignedCertificate
	err         error
	completed   bool
}

type OnDemandIssuer struct {
	ctx         context.Context
	signer      DomainCertificateSigner
	signerState krt.Singleton[SignerState]
	authorizer  GatewayCertificateAuthorizer
	options     OnDemandOptions
	rotation    krt.HandlerRegistration

	mu               sync.RWMutex
	cache            map[string]*certificateCacheEntry
	heap             certHeap
	cacheUpdated     chan struct{}
	rotationEpoch    uint64
	changes          krt.StaticSingleton[CertificateGeneration]
	changeGeneration atomic.Uint64
	flights          map[string]*certificateFlight
	signSlots        chan struct{}
	done             chan struct{}
}

func NewOnDemandIssuer(
	ctx context.Context,
	source DomainSignerSource,
	authorizer GatewayCertificateAuthorizer,
	options OnDemandOptions,
) (*OnDemandIssuer, error) {
	if nilutil.IsNilInterface(ctx) || nilutil.IsNilInterface(source.Signer) || nilutil.IsNilInterface(source.State) ||
		nilutil.IsNilInterface(authorizer) {
		return nil, fmt.Errorf("context, signer, signer state, and gateway certificate authorizer are required")
	}
	if options.LeafLifetime <= 0 {
		return nil, fmt.Errorf("on-demand certificate leaf lifetime must be positive")
	}
	if options.RenewBefore < 0 || options.RenewBefore >= options.LeafLifetime {
		return nil, fmt.Errorf("on-demand certificate renew-before must be non-negative and less than leaf lifetime")
	}
	if options.ResourceTTL < 0 {
		return nil, fmt.Errorf("on-demand certificate resource TTL must be non-negative")
	}
	if options.ResourceTTL == 0 {
		options.ResourceTTL = 15 * time.Minute
	}
	if options.CacheMaxAge < 0 {
		return nil, fmt.Errorf("on-demand certificate cache max age must be non-negative")
	}
	if options.CacheMaxEntries <= 0 {
		options.CacheMaxEntries = defaultCacheMaxEntries
	}
	if options.SignConcurrency <= 0 {
		options.SignConcurrency = defaultSignConcurrency
	}
	if options.KrtOptions.Stop() == nil {
		options.KrtOptions = krt.NewOptionsBuilder(ctx.Done(), "", nil)
	}
	issuer := &OnDemandIssuer{
		ctx:          ctx,
		signer:       source.Signer,
		signerState:  source.State,
		authorizer:   authorizer,
		options:      options,
		cache:        make(map[string]*certificateCacheEntry),
		heap:         make(certHeap, 0),
		cacheUpdated: make(chan struct{}, 1),
		flights:      make(map[string]*certificateFlight),
		signSlots:    make(chan struct{}, options.SignConcurrency),
		done:         make(chan struct{}),
	}
	issuer.changes = krt.NewStatic(
		&CertificateGeneration{}, true, options.KrtOptions.WithName("OnDemand_Certificate_Generation")...)
	issuer.rotation = source.State.Register(func(krt.Event[SignerState]) {
		issuer.mu.Lock()
		issuer.rotationEpoch++
		issuer.cache = make(map[string]*certificateCacheEntry)
		clear(issuer.heap)
		issuer.heap = issuer.heap[:0]
		issuer.mu.Unlock()
		metrics.Default.SetOnDemandCerts(0)
		issuer.scheduleCacheEviction()
		// Rotation invalidates certificates already sent even when the local cache is empty.
		issuer.notifyChanges()
	})
	go func() {
		defer close(issuer.done)
		issuer.run(ctx)
	}()
	return issuer, nil
}

// Done is closed after the issuer's background worker and rotation handler stop.
func (i *OnDemandIssuer) Done() <-chan struct{} {
	return i.done
}

// Changes reports signer transitions only; local cache expiry and capacity eviction are silent.
func (i *OnDemandIssuer) Changes() krt.Singleton[CertificateGeneration] {
	return i.changes
}

func (i *OnDemandIssuer) notifyChanges() {
	generation := i.changeGeneration.Add(1)
	i.changes.Set(&CertificateGeneration{Generation: generation})
}

// SignerRevision identifies the committed signer; empty means signing is unavailable.
func (i *OnDemandIssuer) SignerRevision() string {
	state := i.signerState.Get()
	if state == nil {
		return ""
	}
	return state.Revision
}

// SignerGeneration is local to this issuer and never appears in wire versions.
func (i *OnDemandIssuer) SignerGeneration() uint64 {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.rotationEpoch
}

// Authorize checks current gateway eligibility without touching the certificate cache.
func (i *OnDemandIssuer) Authorize(scope model.ClientScope) error {
	return i.authorizer.Authorize(scope)
}

// Get signs only in response to explicit demand. Cache eviction is local housekeeping;
// it does not revoke certificates already delivered to a gateway.
func (i *OnDemandIssuer) Get(ctx context.Context, scope model.ClientScope, name string) (SignedCertificate, error) {
	if nilutil.IsNilInterface(ctx) {
		return SignedCertificate{}, fmt.Errorf("on-demand certificate request context is required")
	}
	if err := ctx.Err(); err != nil {
		return SignedCertificate{}, fmt.Errorf("request on-demand certificate: %w", err)
	}
	if !IsValidDomain(name) {
		return SignedCertificate{}, fmt.Errorf("invalid on-demand certificate domain %q", name)
	}
	name = CanonicalDomain(name)
	if err := i.authorizer.Authorize(scope); err != nil {
		return SignedCertificate{}, fmt.Errorf("authorize on-demand certificate for %s: %w", scope.GatewayKey, err)
	}
	certificate, err := i.certificate(ctx, name)
	if err != nil {
		return SignedCertificate{}, err
	}
	return cloneSignedCertificate(certificate), nil
}

func cloneSignedCertificate(certificate SignedCertificate) SignedCertificate {
	certificate.CertificateChain = append([]byte(nil), certificate.CertificateChain...)
	certificate.PrivateKey = append([]byte(nil), certificate.PrivateKey...)
	return certificate
}

func (i *OnDemandIssuer) certificate(ctx context.Context, domain string) (SignedCertificate, error) {
	if err := i.requestCancellationError(ctx); err != nil {
		return SignedCertificate{}, err
	}
	signerRevision := i.SignerRevision()
	i.mu.RLock()
	cached, found := i.cache[domain]
	if found && i.cacheEntryValid(cached.certificate, signerRevision) && i.SignerRevision() == signerRevision {
		i.mu.RUnlock()
		if err := i.requestCancellationError(ctx); err != nil {
			return SignedCertificate{}, err
		}
		return cached.certificate, nil
	}
	i.mu.RUnlock()

	waiter := &certificateWaiter{ctx: ctx}
	i.mu.Lock()
	if err := i.requestCancellationError(ctx); err != nil {
		i.mu.Unlock()
		return SignedCertificate{}, err
	}
	if cached, found = i.cache[domain]; found && i.cacheEntryValid(cached.certificate, signerRevision) &&
		i.SignerRevision() == signerRevision {
		i.mu.Unlock()
		if err := i.requestCancellationError(ctx); err != nil {
			return SignedCertificate{}, err
		}
		return cached.certificate, nil
	}
	flight := i.flights[domain]
	if flight == nil {
		flightCtx, cancelFlight := context.WithCancel(i.ctx)
		flight = &certificateFlight{
			ctx:     flightCtx,
			cancel:  cancelFlight,
			done:    make(chan struct{}),
			waiters: sets.New[*certificateWaiter](),
		}
		i.flights[domain] = flight
	}
	flight.waiters.Insert(waiter)
	startFlight := len(flight.waiters) == 1
	i.mu.Unlock()
	if startFlight {
		go i.runCertificateFlight(domain, flight)
	}
	defer i.releaseCertificateWaiter(domain, flight, waiter)

	select {
	case <-ctx.Done():
		return SignedCertificate{}, ctx.Err()
	case <-i.ctx.Done():
		return SignedCertificate{}, i.ctx.Err()
	case <-flight.done:
		if err := i.requestCancellationError(ctx); err != nil {
			return SignedCertificate{}, err
		}
		return flight.certificate, flight.err
	}
}

func (i *OnDemandIssuer) requestCancellationError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return i.ctx.Err()
}

func (i *OnDemandIssuer) cacheEntryValid(certificate SignedCertificate, signerRevision string) bool {
	if signerRevision == "" || certificate.SignerRevision != signerRevision {
		return false
	}
	return time.Now().Before(certificate.UsableUntil)
}

func (i *OnDemandIssuer) runCertificateFlight(domain string, flight *certificateFlight) {
	var certificate SignedCertificate
	var resultErr error
	defer func() {
		i.completeCertificateFlight(domain, flight, certificate, resultErr)
	}()

	for {
		if resultErr = i.flightCancellationError(domain, flight); resultErr != nil {
			return
		}
		signerRevision := i.SignerRevision()
		if signerRevision == "" {
			resultErr = fmt.Errorf("domain certificate signer is unavailable")
			return
		}
		i.mu.RLock()
		epoch := i.rotationEpoch
		cached, found := i.cache[domain]
		validCached := found && i.cacheEntryValid(cached.certificate, signerRevision)
		i.mu.RUnlock()
		if validCached {
			if resultErr = i.flightCancellationError(domain, flight); resultErr != nil {
				return
			}
			certificate = cached.certificate
			return
		}

		// SignDNS runs outside issuer locks, after a cancellation check, limited by signSlots.
		if resultErr = i.flightCancellationError(domain, flight); resultErr != nil {
			return
		}
		select {
		case i.signSlots <- struct{}{}:
		case <-flight.ctx.Done():
			resultErr = flight.ctx.Err()
			return
		case <-i.ctx.Done():
			resultErr = i.ctx.Err()
			return
		}
		generated, err := i.signer.SignDNS(flight.ctx, domain, i.options.LeafLifetime)
		<-i.signSlots
		if resultErr = i.flightCancellationError(domain, flight); resultErr != nil {
			return
		}
		i.mu.Lock()
		// This is the final cancellation check immediately before the epoch-validated cache commit.
		if resultErr = i.flightCancellationErrorLocked(domain, flight); resultErr != nil {
			i.mu.Unlock()
			return
		}
		if i.rotationEpoch != epoch {
			i.mu.Unlock()
			continue
		}
		if currentRevision := i.SignerRevision(); currentRevision != signerRevision {
			i.mu.Unlock()
			continue
		}
		// A failure from a superseded CA must not fail demand for the current CA.
		if err != nil {
			resultErr = err
			i.mu.Unlock()
			return
		}
		if generated.SignerRevision != signerRevision {
			resultErr = fmt.Errorf("domain signer returned revision %q while state revision is %q",
				generated.SignerRevision, signerRevision)
			i.mu.Unlock()
			return
		}
		generated.UsableUntil = generated.NotAfter.Add(-i.options.RenewBefore)
		if deadline := generated.SignedAt.Add(i.options.ResourceTTL); deadline.Before(generated.UsableUntil) {
			generated.UsableUntil = deadline
		}
		if !time.Now().Before(generated.UsableUntil) {
			resultErr = fmt.Errorf("domain certificate for %q has no lifetime outside the renewal window", domain)
			i.mu.Unlock()
			return
		}
		if old := i.cache[domain]; old != nil && old.index >= 0 {
			heap.Remove(&i.heap, old.index)
		}
		if _, exists := i.cache[domain]; !exists {
			// Evict entries closest to their deadline to stay under CacheMaxEntries.
			for len(i.cache) >= i.options.CacheMaxEntries && i.heap.Len() > 0 {
				victim := heap.Pop(&i.heap).(*certificateCacheEntry)
				delete(i.cache, victim.domain)
			}
		}
		entry := newCertificateCacheEntry(domain, generated, time.Now(), i.options)
		i.cache[domain] = entry
		heap.Push(&i.heap, entry)
		metrics.Default.SetOnDemandCerts(len(i.cache))
		i.mu.Unlock()
		i.scheduleCacheEviction()
		certificate = generated
		return
	}
}

func (i *OnDemandIssuer) flightCancellationError(domain string, flight *certificateFlight) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.flightCancellationErrorLocked(domain, flight)
}

func (i *OnDemandIssuer) flightCancellationErrorLocked(domain string, flight *certificateFlight) error {
	if err := i.ctx.Err(); err != nil {
		return err
	}
	if err := flight.ctx.Err(); err != nil {
		return err
	}
	for waiter := range flight.waiters {
		if waiter.ctx.Err() == nil {
			return nil
		}
	}
	if i.flights[domain] == flight {
		delete(i.flights, domain)
	}
	flight.cancel()
	return context.Canceled
}

func (i *OnDemandIssuer) releaseCertificateWaiter(domain string, flight *certificateFlight, waiter *certificateWaiter) {
	i.mu.Lock()
	defer i.mu.Unlock()
	flight.waiters.Delete(waiter)
	if len(flight.waiters) != 0 || flight.completed {
		return
	}
	if i.flights[domain] == flight {
		delete(i.flights, domain)
	}
	flight.cancel()
}

func (i *OnDemandIssuer) completeCertificateFlight(
	domain string,
	flight *certificateFlight,
	certificate SignedCertificate,
	err error,
) {
	i.mu.Lock()
	flight.certificate = certificate
	flight.err = err
	flight.completed = true
	if i.flights[domain] == flight {
		delete(i.flights, domain)
	}
	close(flight.done)
	i.mu.Unlock()
	flight.cancel()
}

func (i *OnDemandIssuer) run(ctx context.Context) {
	defer i.rotation.UnregisterHandler()
	timer := time.NewTimer(time.Hour)
	stopAndDrainTimer(timer)
	defer timer.Stop()
	for {
		wait, scheduled := i.reap(time.Now())
		var timerC <-chan time.Time
		if scheduled {
			stopAndDrainTimer(timer)
			timer.Reset(wait)
			timerC = timer.C
		} else {
			stopAndDrainTimer(timer)
		}
		select {
		case <-ctx.Done():
			return
		case <-timerC:
		case <-i.cacheUpdated:
		}
	}
}

func stopAndDrainTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (i *OnDemandIssuer) reap(now time.Time) (time.Duration, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	defer func() { metrics.Default.SetOnDemandCerts(len(i.cache)) }()
	for i.heap.Len() > 0 {
		next := i.heap[0]
		if wait := next.deadline.Sub(now); wait > 0 {
			return wait, true
		}
		heap.Pop(&i.heap)
		delete(i.cache, next.domain)
	}
	return 0, false
}

func (i *OnDemandIssuer) scheduleCacheEviction() {
	select {
	case i.cacheUpdated <- struct{}{}:
	default:
	}
}

func (i *OnDemandIssuer) cachedCertificate(domain string) []byte {
	i.mu.RLock()
	defer i.mu.RUnlock()
	entry, found := i.cache[domain]
	if !found {
		return nil
	}
	return append([]byte(nil), entry.certificate.CertificateChain...)
}
