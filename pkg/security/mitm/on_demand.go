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
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
)

type GatewayCertificateAuthorizer interface {
	Authorize(model.ClientScope) error
}

// ErrDomainCertificateEvicted reports that SDS must remove the watched secret
// unless the current Delta request explicitly retries this exact domain.
var ErrDomainCertificateEvicted = errors.New("on-demand domain certificate is evicted")

const (
	// Built-in bounds applied when OnDemandOptions leaves them non-positive.
	defaultCacheMaxEntries = 10000
	defaultSignConcurrency = 8
)

type certificateWaiter struct {
	ctx          context.Context
	retryEvicted bool
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
	evicted          sets.Set[string]
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
	if isNilDependency(ctx) || isNilDependency(source.Signer) || isNilDependency(source.State) || isNilDependency(authorizer) {
		return nil, fmt.Errorf("context, signer, signer state, and gateway certificate authorizer are required")
	}
	if options.LeafLifetime <= 0 {
		return nil, fmt.Errorf("on-demand certificate leaf lifetime must be positive")
	}
	if options.RenewBefore < 0 || options.RenewBefore >= options.LeafLifetime {
		return nil, fmt.Errorf("on-demand certificate renew-before must be non-negative and less than leaf lifetime")
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
		evicted:      sets.New[string](),
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
		issuer.markRotatedCacheEvictedLocked()
		evictedCount := len(issuer.evicted)
		issuer.cache = make(map[string]*certificateCacheEntry)
		clear(issuer.heap)
		issuer.heap = issuer.heap[:0]
		issuer.mu.Unlock()
		metrics.Default.SetOnDemandCerts(0)
		issuer.scheduleCacheEviction()
		if evictedCount > 0 {
			issuer.notifyChanges()
		}
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

func isNilDependency(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}

func (i *OnDemandIssuer) Changes() krt.Singleton[CertificateGeneration] {
	return i.changes
}

func (i *OnDemandIssuer) notifyChanges() {
	generation := i.changeGeneration.Add(1)
	i.changes.Set(&CertificateGeneration{Generation: generation})
}

func (i *OnDemandIssuer) signerRevision() string {
	state := i.signerState.Get()
	if state == nil {
		return ""
	}
	return state.Revision
}

// Evicted returns an immutable, unordered snapshot of certificate domains
// removed by the deadline reaper and not successfully re-signed since.
func (i *OnDemandIssuer) Evicted() []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if len(i.evicted) == 0 {
		return nil
	}
	result := make([]string, 0, len(i.evicted))
	for domain := range i.evicted {
		result = append(result, domain)
	}
	return result
}

func (i *OnDemandIssuer) Get(ctx context.Context, scope model.ClientScope, name string) (SignedCertificate, error) {
	return i.get(ctx, scope, name, true)
}

// GetForSDS returns a domain certificate while atomically respecting current
// eviction state. Only an explicit retry for this exact name may re-sign an
// evicted certificate.
func (i *OnDemandIssuer) GetForSDS(
	ctx context.Context,
	scope model.ClientScope,
	name string,
	retryEvicted bool,
) (SignedCertificate, error) {
	return i.get(ctx, scope, name, retryEvicted)
}

func (i *OnDemandIssuer) get(
	ctx context.Context,
	scope model.ClientScope,
	name string,
	retryEvicted bool,
) (SignedCertificate, error) {
	if isNilDependency(ctx) {
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
	certificate, err := i.certificateWithEviction(ctx, name, retryEvicted)
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
	return i.certificateWithEviction(ctx, domain, true)
}

func (i *OnDemandIssuer) certificateWithEviction(
	ctx context.Context,
	domain string,
	retryEvicted bool,
) (SignedCertificate, error) {
	if err := i.requestCancellationError(ctx); err != nil {
		return SignedCertificate{}, err
	}
	signerRevision := i.signerRevision()
	i.mu.RLock()
	if i.evicted.Contains(domain) && !retryEvicted {
		i.mu.RUnlock()
		return SignedCertificate{}, domainCertificateEvictedError(domain)
	}
	cached, found := i.cache[domain]
	if found && i.cacheEntryValid(cached.certificate, signerRevision) && i.signerRevision() == signerRevision {
		i.mu.RUnlock()
		if err := i.requestCancellationError(ctx); err != nil {
			return SignedCertificate{}, err
		}
		return cached.certificate, nil
	}
	i.mu.RUnlock()

	waiter := &certificateWaiter{ctx: ctx, retryEvicted: retryEvicted}
	i.mu.Lock()
	if err := i.requestCancellationError(ctx); err != nil {
		i.mu.Unlock()
		return SignedCertificate{}, err
	}
	if i.evicted.Contains(domain) && !retryEvicted {
		i.mu.Unlock()
		return SignedCertificate{}, domainCertificateEvictedError(domain)
	}
	if cached, found = i.cache[domain]; found && i.cacheEntryValid(cached.certificate, signerRevision) &&
		i.signerRevision() == signerRevision {
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
	deadline, _ := certificateEvictionDeadline(certificate, i.options.RenewBefore)
	return time.Now().Before(deadline)
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
		signerRevision := i.signerRevision()
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
		if err != nil {
			resultErr = err
			return
		}

		i.mu.Lock()
		// This is the final cancellation check immediately before the epoch-validated cache commit.
		if resultErr = i.flightCancellationErrorLocked(domain, flight); resultErr != nil {
			i.mu.Unlock()
			return
		}
		if i.evicted.Contains(domain) && !flightAllowsEvictedCommitLocked(flight) {
			if i.flights[domain] == flight {
				delete(i.flights, domain)
			}
			resultErr = domainCertificateEvictedError(domain)
			i.mu.Unlock()
			return
		}
		if i.rotationEpoch != epoch {
			i.mu.Unlock()
			continue
		}
		if currentRevision := i.signerRevision(); currentRevision != signerRevision {
			i.mu.Unlock()
			continue
		}
		if generated.SignerRevision != signerRevision {
			resultErr = fmt.Errorf("domain signer returned revision %q while state revision is %q",
				generated.SignerRevision, signerRevision)
			i.mu.Unlock()
			return
		}
		if old := i.cache[domain]; old != nil && old.index >= 0 {
			heap.Remove(&i.heap, old.index)
		}
		var capacityEvicted bool
		if _, exists := i.cache[domain]; !exists {
			// Evict entries closest to their deadline to stay under CacheMaxEntries.
			for len(i.cache) >= i.options.CacheMaxEntries && i.heap.Len() > 0 {
				victim := heap.Pop(&i.heap).(*certificateCacheEntry)
				delete(i.cache, victim.domain)
				i.markEvictedLocked(victim.domain)
				capacityEvicted = true
			}
		}
		entry := newCertificateCacheEntry(domain, generated, time.Now(), i.options)
		i.cache[domain] = entry
		i.evicted.Delete(domain)
		heap.Push(&i.heap, entry)
		metrics.Default.SetOnDemandCerts(len(i.cache))
		i.mu.Unlock()
		if capacityEvicted {
			i.notifyChanges()
		}
		i.scheduleCacheEviction()
		certificate = generated
		return
	}
}

func domainCertificateEvictedError(domain string) error {
	return fmt.Errorf("domain %q: %w", domain, ErrDomainCertificateEvicted)
}

func flightAllowsEvictedCommitLocked(flight *certificateFlight) bool {
	for waiter := range flight.waiters {
		if waiter.retryEvicted && waiter.ctx.Err() == nil {
			return true
		}
	}
	return false
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
	wait, scheduled, changed := i.evictDue(now)
	if changed {
		i.notifyChanges()
	}
	return wait, scheduled
}

func (i *OnDemandIssuer) evictDue(now time.Time) (time.Duration, bool, bool) {
	i.mu.Lock()
	changed := false
	for i.heap.Len() > 0 {
		next := i.heap[0]
		wait := next.deadline.Sub(now)
		if wait <= 0 {
			heap.Pop(&i.heap)
			delete(i.cache, next.domain)
			i.markEvictedLocked(next.domain)
			changed = true
			continue
		}
		if next.reason == certificateEvictionMaxAge && !next.maxAgeDeferred && wait < minCertificateEvictionInterval {
			next.deadline = now.Add(minCertificateEvictionInterval)
			if !next.certificateDeadline.After(next.deadline) {
				next.deadline = next.certificateDeadline
				next.reason = next.certificateReason
			} else {
				next.maxAgeDeferred = true
			}
			heap.Fix(&i.heap, next.index)
			continue
		}
		metrics.Default.SetOnDemandCerts(len(i.cache))
		i.mu.Unlock()
		return wait, true, changed
	}
	metrics.Default.SetOnDemandCerts(len(i.cache))
	i.mu.Unlock()
	return 0, false, changed
}

func (i *OnDemandIssuer) scheduleCacheEviction() {
	select {
	case i.cacheUpdated <- struct{}{}:
	default:
	}
}

// markEvictedLocked records an eviction so SDS removes the secret; the set is kept bounded.
func (i *OnDemandIssuer) markEvictedLocked(domain string) {
	if len(i.evicted) >= i.options.CacheMaxEntries {
		for stale := range i.evicted {
			i.evicted.Delete(stale)
			break
		}
	}
	i.evicted.Insert(domain)
}

// markRotatedCacheEvictedLocked prioritizes every certificate invalidated by
// the current rotation, then retains older removals only while capacity remains.
func (i *OnDemandIssuer) markRotatedCacheEvictedLocked() {
	rotated := sets.New[string]()
	for domain, entry := range i.cache {
		rotated.Insert(domain)
		entry.index = -1
	}
	for domain := range i.evicted {
		if len(rotated) >= i.options.CacheMaxEntries {
			break
		}
		rotated.Insert(domain)
	}
	i.evicted = rotated
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
