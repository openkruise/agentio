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

package krt

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

type pollingSyncer struct {
	name         string
	pollFunc     func(ctx context.Context) bool
	pollInterval time.Duration
	synced       *atomic.Bool
}

func (p *pollingSyncer) WaitUntilSynced(stop <-chan struct{}) bool {
	ctx := wait.ContextForChannel(stop)
	err := wait.PollUntilContextCancel(ctx, p.pollInterval, true, func(ctx context.Context) (bool, error) {
		if p.pollFunc(ctx) {
			p.synced.Store(true)
			return true, nil
		}
		log.Debug("waiting for collection to sync", "collection", p.name)
		return false, nil
	})
	if err == nil {
		log.Info("collection synced", "collection", p.name)
		return true
	}
	return false
}

func (p *pollingSyncer) HasSynced() bool {
	return p.synced.Load()
}

func NewPollingSyncer(name string, pollFunc func(ctx context.Context) bool, pollInterval time.Duration) Syncer {
	return &pollingSyncer{
		name:         name,
		pollFunc:     pollFunc,
		pollInterval: pollInterval,
		synced:       &atomic.Bool{},
	}
}

// delayedSingleton returns zero values until the syncer reports synced, then delegates to the singleton built by the callback; pending handlers are replayed.
type delayedSingleton[T any] struct {
	id       collectionUID
	mu       sync.RWMutex
	inner    Singleton[T]
	syncer   Syncer
	callback func() Singleton[T]
	stop     <-chan struct{}
	ready    chan struct{}

	// handlers registered before inner is ready
	pendingHandlersMu sync.Mutex
	pendingHandlers   []*pendingEntry[T]
}

func (d *delayedSingleton[T]) getInner() Singleton[T] {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.inner
}

// Get implements [Singleton].
func (d *delayedSingleton[T]) Get() *T {
	if inner := d.getInner(); inner != nil {
		return inner.Get()
	}
	return nil
}

// Register implements [Singleton].
func (d *delayedSingleton[T]) Register(f func(o Event[T])) HandlerRegistration {
	return d.registerPending(f)
}

// registerPending atomically either registers f on the inner singleton or
// queues it for replay. Holding pendingHandlersMu across the check and the
// append closes the window where run() sets inner and drains the queue in
// between, which silently dropped the handler.
func (d *delayedSingleton[T]) registerPending(f func(o Event[T])) HandlerRegistration {
	d.pendingHandlersMu.Lock()
	defer d.pendingHandlersMu.Unlock()
	if inner := d.getInner(); inner != nil {
		return inner.Register(f)
	}
	e := &pendingEntry[T]{f: f}
	d.pendingHandlers = append(d.pendingHandlers, e)
	return &pendingRegistration[T]{d: d, entry: e}
}

// AsCollection implements [Singleton].
func (d *delayedSingleton[T]) AsCollection() Collection[T] {
	return newCollection[T](&delayedCollection[T]{d})
}

// Metadata implements [Singleton].
func (d *delayedSingleton[T]) Metadata() Metadata {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().Metadata()
	}
	return nil
}

func (d *delayedSingleton[T]) run() {
	go func() {
		if !d.syncer.WaitUntilSynced(d.stop) {
			return
		}
		inner := d.callback()

		// Set inner and drain the pending entries under one lock, so a
		// concurrent registerPending either sees inner or lands in the
		// drained list — never neither. ready is closed after the drain so
		// a waiter woken by it observes a fully replayed state.
		d.pendingHandlersMu.Lock()
		d.mu.Lock()
		d.inner = inner
		d.mu.Unlock()
		entries := d.pendingHandlers
		d.pendingHandlers = nil
		d.pendingHandlersMu.Unlock()
		close(d.ready)

		for _, e := range entries {
			e.set(inner.Register(e.f))
		}
	}()
}

// NewDelayedSingleton defers building a singleton until the syncer reports synced; until then it reports empty.
func NewDelayedSingleton[T any](syncer Syncer, callback func() Singleton[T], stop <-chan struct{}) Singleton[T] {
	s := &delayedSingleton[T]{
		id:       nextUID(),
		callback: callback,
		syncer:   syncer,
		stop:     stop,
		ready:    make(chan struct{}),
	}
	s.run()
	return s
}

// delayedCollection adapts delayedSingleton to the Collection interface.
type delayedCollection[T any] struct {
	*delayedSingleton[T]
}

func (d *delayedCollection[T]) GetKey(k string) *T {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().GetKey(k)
	}
	return nil
}

func (d *delayedCollection[T]) ListFiltered(filter func(T) bool) []T {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().ListFiltered(filter)
	}
	return nil
}

func (d *delayedCollection[T]) Register(f func(o Event[T])) HandlerRegistration {
	return d.delayedSingleton.Register(f)
}

func (d *delayedCollection[T]) RegisterBatch(f func(o []Event[T]), runExistingState bool) HandlerRegistration {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().RegisterBatch(f, runExistingState)
	}
	return d.registerPending(func(o Event[T]) {
		f([]Event[T]{o})
	})
}

func (d *delayedCollection[T]) Metadata() Metadata {
	return d.delayedSingleton.Metadata()
}

// HasSynced returns true only after the inner singleton is created and synced.
func (d *delayedCollection[T]) HasSynced() bool {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().HasSynced()
	}
	return false
}

// WaitUntilSynced blocks until the inner singleton is ready and synced.
func (d *delayedCollection[T]) WaitUntilSynced(stop <-chan struct{}) bool {
	select {
	case <-d.ready:
	case <-stop:
		return false
	}
	return d.getInner().AsCollection().WaitUntilSynced(stop)
}

// pendingEntry is one handler registered before the inner singleton exists.
type pendingEntry[T any] struct {
	f func(o Event[T])

	mu           sync.Mutex
	inner        HandlerRegistration
	unregistered bool
}

// set stores the replayed registration, or drops it when the entry was
// withdrawn while still pending.
func (e *pendingEntry[T]) set(reg HandlerRegistration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.unregistered {
		reg.UnregisterHandler()
		return
	}
	e.inner = reg
}

// pendingRegistration is the HandlerRegistration handed back for a handler
// that is still pending replay. Withdrawal works in both phases, and the
// syncer methods follow the replayed registration once it exists.
type pendingRegistration[T any] struct {
	d     *delayedSingleton[T]
	entry *pendingEntry[T]
}

func (r *pendingRegistration[T]) WaitUntilSynced(stop <-chan struct{}) bool {
	select {
	case <-r.d.ready:
	case <-stop:
		return false
	}
	r.entry.mu.Lock()
	inner := r.entry.inner
	r.entry.mu.Unlock()
	if inner == nil {
		// Withdrawn while pending; nothing will ever flow through it.
		return true
	}
	return inner.WaitUntilSynced(stop)
}

func (r *pendingRegistration[T]) HasSynced() bool {
	r.entry.mu.Lock()
	inner := r.entry.inner
	r.entry.mu.Unlock()
	return inner != nil && inner.HasSynced()
}

func (r *pendingRegistration[T]) UnregisterHandler() {
	r.entry.mu.Lock()
	defer r.entry.mu.Unlock()
	r.entry.unregistered = true
	if r.entry.inner != nil {
		r.entry.inner.UnregisterHandler()
		r.entry.inner = nil
	}
}

var _ Singleton[any] = &delayedSingleton[any]{}
var _ internalCollection[any] = &delayedCollection[any]{}

func (d *delayedCollection[T]) uid() collectionUID { return d.id }
func (d *delayedCollection[T]) name() string       { return fmt.Sprintf("DelayedSingleton[%v]", d.id) }
func (d *delayedCollection[T]) augment(o any) any {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().augment(o)
	}
	return o
}
func (d *delayedCollection[T]) dump() CollectionDump {
	if inner := d.getInner(); inner != nil {
		return inner.AsCollection().dump()
	}
	return CollectionDump{}
}
func (d *delayedCollection[T]) index(_ string, extract func(T) []string) indexer[T] {
	return delayedIndex[T]{d, extract}
}

// Indexes can be created before the inner singleton exists.
type delayedIndex[T any] struct {
	collection *delayedCollection[T]
	extract    func(T) []string
}

func (i delayedIndex[T]) LookupFiltered(key string, filter func(T) bool) []T {
	return i.collection.ListFiltered(func(o T) bool {
		return slices.Contains(i.extract(o), key) && (filter == nil || filter(o))
	})
}
