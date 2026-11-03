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

// Package demandcache bounds retained, on-demand subscriptions without owning
// their values or knowing their discovery protocol.
package demandcache

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

// Lease is an independently owned subscription. Release must be a nonblocking
// local operation and must not call back into Cache. Done closes
// when the source ends the subscription. Demand must finish on context
// cancellation or release of its lease.
type Lease[V any] interface {
	Demand(context.Context) (V, error)
	Done() <-chan struct{}
	Release()
}

// Source acquires independently owned subscriptions. Acquire must be a
// nonblocking local operation and must not call back into Cache.
type Source[V any] interface {
	Acquire(typ, name string) (Lease[V], error)
}

// Config applies uniformly across resource types within one Cache.
type Config struct {
	IdleTTL    time.Duration // Zero disables expiration. Idle time starts when the last Demand completes.
	MaxEntries int           // Zero disables capacity eviction. In-flight demands may temporarily exceed this target.
}

// Validate checks externally supplied retention settings.
func (c Config) Validate() error {
	if c.IdleTTL < 0 || c.MaxEntries < 0 {
		return errors.New("cache idle TTL and maximum entries must not be negative")
	}
	return nil
}

type key struct {
	typ  string
	name string
}
type entry[V any] struct {
	key        key
	lease      Lease[V]
	users      int
	lastAccess time.Time
	idle       *list.Element
}

// Cache retains leases in one LRU across types. Resource values remain owned by
// the source. Route all managed accesses through this Cache. The source must not
// retain an independent wildcard or persistent interest if eviction is to free values.
type Cache[V any] struct {
	source  Source[V]
	config  Config
	mu      sync.Mutex
	entries map[key]*entry[V]
	idle    list.List // Only entries with no in-flight Demand; newest first.
	wake    chan struct{}
	closed  bool
}

// ErrClosed indicates that the retention wrapper has shut down.
var ErrClosed = errors.New("demand cache closed")

// New creates a retention wrapper. Run owns its expiration loop; Close releases
// all retained leases. Neither method owns the underlying discovery connection.
func New[V any](source Source[V], config Config) (*Cache[V], error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Cache[V]{source: source, config: config, entries: map[key]*entry[V]{}, wake: make(chan struct{}, 1)}, nil
}

// Demand keeps a lease pinned until the lookup finishes. Cache hits still read
// the source so policy updates are immediately visible and do not refresh TTL
// unless a consumer actually requests the resource.
func (c *Cache[V]) Demand(ctx context.Context, typ, name string) (V, error) {
	value, release, err := c.Get(ctx, typ, name)
	if release != nil {
		release()
	}
	return value, err
}

// Get pins the subscription through the consumer's use of the value. A successful
// caller must call release once, including when subsequent dependency loading fails.
func (c *Cache[V]) Get(ctx context.Context, typ, name string) (V, func(), error) {
	var zero V
	if err := ctx.Err(); err != nil {
		return zero, nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return zero, nil, ErrClosed
	}
	c.prune(time.Now())
	k := key{typ: typ, name: name}
	e := c.entries[k]
	if e != nil {
		select {
		case <-e.lease.Done():
			c.remove(e)
			e = nil
		default:
		}
	}
	if e == nil {
		lease, err := c.source.Acquire(typ, name)
		if err != nil {
			c.mu.Unlock()
			return zero, nil, err
		}
		e = &entry[V]{key: k, lease: lease}
		c.entries[k] = e
	}
	if e.idle != nil {
		c.idle.Remove(e.idle)
		e.idle = nil
	}
	e.users++
	c.prune(time.Now())
	c.mu.Unlock()

	value, err := e.lease.Demand(ctx)
	release := func() { c.release(e, err) }
	if err != nil {
		release()
		return zero, nil, err
	}
	return value, release, nil
}

func (c *Cache[V]) release(e *entry[V], err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.users--
	if e.users == 0 && c.entries[e.key] == e {
		if err != nil {
			c.remove(e)
		} else {
			e.lastAccess = time.Now()
			e.idle = c.idle.PushFront(e)
			c.prune(e.lastAccess)
		}
	}
	c.signal()
}

// Len returns the number of retained leases, including in-flight lookups.
func (c *Cache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Run expires idle entries using one timer. Call it once per Cache. Capacity
// eviction also runs synchronously in Demand and does not depend on the timer.
func (c *Cache[V]) Run(ctx context.Context) error {
	defer c.Close()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		c.mu.Lock()
		c.prune(time.Now())
		var tick <-chan time.Time
		if tail := c.idle.Back(); c.config.IdleTTL > 0 && tail != nil {
			timer.Reset(time.Until(tail.Value.(*entry[V]).lastAccess.Add(c.config.IdleTTL)))
			tick = timer.C
		}
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-c.wake:
		case <-tick:
		}
		timer.Stop()
	}
}

// Close releases all leases, including pending lookups, and stops Run.
func (c *Cache[V]) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for _, e := range c.entries {
		c.remove(e)
	}
	c.signal()
}

func (c *Cache[V]) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// prune and remove run under mu. No network waits or source callbacks may run here.
func (c *Cache[V]) prune(now time.Time) {
	for tail := c.idle.Back(); tail != nil; tail = c.idle.Back() {
		e := tail.Value.(*entry[V])
		overCapacity := c.config.MaxEntries > 0 && len(c.entries) > c.config.MaxEntries
		expired := c.config.IdleTTL > 0 && !now.Before(e.lastAccess.Add(c.config.IdleTTL))
		if !overCapacity && !expired {
			return
		}
		c.remove(e)
	}
}

func (c *Cache[V]) remove(e *entry[V]) {
	delete(c.entries, e.key)
	if e.idle != nil {
		c.idle.Remove(e.idle)
		e.idle = nil
	}
	e.lease.Release()
}
