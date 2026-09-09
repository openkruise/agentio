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

package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/krt"
	"istio.io/istio/pkg/util/sets"
)

func refreshDelay(host string, ttl, fallback time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = fallback
	}
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	base := ttl - 5*time.Second
	jitterLimit := min(base/5, 3*time.Second)
	if jitterLimit <= 0 {
		return base
	}
	sum := sha256.Sum256([]byte(host))
	var value uint64
	for i := range 8 {
		value = value<<8 | uint64(sum[i])
	}
	return base + time.Duration(value%uint64(jitterLimit))
}

type Options struct {
	RefreshInterval time.Duration
	LookupTimeout   time.Duration
	MaxConcurrent   int
	DNSServers      []string
}

type Lookup func(context.Context, string) (dns.LookupResult, error)

// Result is the cached DNS answer published into the krt graph, keyed by hostname.
type Result struct {
	Hostname  string
	Addresses []netip.Addr
}

func (r Result) ResourceName() string { return r.Hostname }

func (r Result) Equals(other Result) bool {
	return r.Hostname == other.Hostname && slices.Equal(r.Addresses, other.Addresses)
}

type entry struct {
	hostname  string
	addresses []netip.Addr
	next      time.Time
	resolving bool
	published bool
	refs      int
	index     int
	inHeap    bool
}

type Resolver struct {
	ctx     context.Context
	options Options
	lookup  Lookup
	results krt.StaticCollection[Result]
	jobs    chan string
	wake    chan struct{}

	mu       sync.RWMutex
	entries  map[string]*entry
	schedule entryHeap
}

func New(ctx context.Context, options Options, lookup Lookup, collectionOptions ...krt.CollectionOption) (*Resolver, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = 30 * time.Second
	}
	if options.LookupTimeout <= 0 {
		options.LookupTimeout = 5 * time.Second
	}
	if options.MaxConcurrent <= 0 {
		options.MaxConcurrent = 32
	}
	if lookup == nil {
		lookup = newProtocolLookup(options.DNSServers, options.LookupTimeout)
	}
	resolver := &Resolver{
		ctx:     ctx,
		options: options,
		lookup:  lookup,
		entries: make(map[string]*entry),
		results: krt.NewStaticCollection[Result](nil, nil, collectionOptions...),
		jobs:    make(chan string, options.MaxConcurrent),
		wake:    make(chan struct{}, 1),
	}
	for range options.MaxConcurrent {
		go resolver.worker()
	}
	go resolver.run()
	return resolver, nil
}

// Results exposes the hostname-keyed DNS cache for diagnostics and composition.
func (r *Resolver) Results() krt.Collection[Result] {
	return r.results
}

// HandleAdd retains a hostname while at least one policy/config object refers to
// it. Repeated references are counted so deleting one policy does not stop
// refreshes needed by another.
func (r *Resolver) HandleAdd(host string) {
	host = normalizeHostname(host)
	if host == "" {
		return
	}
	r.mu.Lock()
	item := r.entries[host]
	if item == nil {
		item = &entry{hostname: host, next: time.Now(), index: -1}
		r.entries[host] = item
	}
	item.refs++
	if !item.resolving {
		r.scheduleLocked(item)
	}
	r.mu.Unlock()
	r.signalScheduler()
}

// HandleDelete releases one policy/config reference to a hostname.
func (r *Resolver) HandleDelete(host string) {
	host = normalizeHostname(host)
	if host == "" {
		return
	}
	r.mu.Lock()
	item := r.entries[host]
	if item == nil {
		r.mu.Unlock()
		return
	}
	item.refs--
	if item.refs > 0 {
		r.mu.Unlock()
		return
	}
	r.removeScheduledLocked(item)
	delete(r.entries, host)
	r.mu.Unlock()
	r.results.DeleteObject(host)
	r.signalScheduler()
}

// Resolve fetches one hostname from the krt collection and starts an
// asynchronous lookup on a cold miss. FetchOne registers a key-scoped reverse
// dependency even when the result is not present yet.
func (r *Resolver) Resolve(ctx krt.HandlerContext, host string) []netip.Addr {
	host = normalizeHostname(host)
	if host == "" {
		return nil
	}
	resolved := krt.FetchOne(ctx, r.results, krt.FilterKey(host))

	r.mu.Lock()
	item := r.entries[host]
	if item == nil {
		// Reference tracking and krt transforms run asynchronously. Make a cold
		// lookup self-starting even if the reference event has not arrived yet.
		item = &entry{hostname: host, next: time.Now(), index: -1}
		r.entries[host] = item
		r.scheduleLocked(item)
	}
	r.mu.Unlock()
	r.signalScheduler()
	if resolved == nil {
		return nil
	}
	return append([]netip.Addr(nil), resolved.Addresses...)
}

func (r *Resolver) refresh(host string) {
	ctx, cancel := context.WithTimeout(r.ctx, r.options.LookupTimeout)
	result, err := r.lookup(ctx, host)
	cancel()
	now := time.Now()
	addresses := normalizeAddresses(result.Addresses)
	r.mu.Lock()
	item := r.entries[host]
	if item == nil {
		r.mu.Unlock()
		return
	}
	item.resolving = false
	if err != nil {
		if item.refs == 0 {
			delete(r.entries, host)
			if item.published {
				r.results.DeleteObject(host)
			}
			r.mu.Unlock()
			return
		}
		item.next = now.Add(refreshDelay(host, time.Minute, r.options.RefreshInterval))
		r.scheduleLocked(item)
		r.mu.Unlock()
		r.signalScheduler()
		return
	}
	item.next = now.Add(refreshDelay(host, result.TTL, r.options.RefreshInterval))
	updated := !item.published || !slices.Equal(item.addresses, addresses)
	item.addresses = addresses
	item.published = true
	r.scheduleLocked(item)
	r.mu.Unlock()
	r.signalScheduler()
	if updated {
		r.results.ConditionalUpdateObject(Result{Hostname: host, Addresses: append([]netip.Addr(nil), addresses...)})
	}
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func normalizeAddresses(addresses []netip.Addr) []netip.Addr {
	seen := sets.NewWithLength[netip.Addr](len(addresses))
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() {
			continue
		}
		if seen.Contains(address) {
			continue
		}
		seen.Insert(address)
		result = append(result, address)
	}
	slices.SortFunc(result, func(a, b netip.Addr) int { return a.Compare(b) })
	return result
}

func newProtocolLookup(servers []string, timeout time.Duration) Lookup {
	transport := dns.NewTransport(servers, timeout)
	return func(ctx context.Context, host string) (dns.LookupResult, error) {
		return transport.Lookup(ctx, host, dns.DualStack)
	}
}
