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

package kclient

import (
	"sync"
	"sync/atomic"

	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pkg/ptr"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// StartableInformer is an informer whose backing factory can be started after
// event handlers and indexes have been registered.
type StartableInformer[T controllers.ComparableObject] interface {
	Informer[T]
	Start(stop <-chan struct{})
}

type activeInformer[T controllers.ComparableObject] struct {
	Informer[T]
	start     func(stop <-chan struct{})
	startOnce sync.Once
}

func (a *activeInformer[T]) Start(stop <-chan struct{}) {
	a.startOnce.Do(func() { a.start(stop) })
}

// delayedInformer starts as an empty, synced-after-CRD-discovery informer and
// atomically installs the typed informer if the CRD is present now or appears
// later.
type delayedInformer[T controllers.ComparableObject] struct {
	active  atomic.Pointer[activeInformer[T]]
	watcher kube.CrdWatcher

	mu       sync.Mutex
	handlers []delayedHandler
	indexes  []*delayedIndex[T]
	lifetime delayedInformerLifetime
}

// Closing started publishes the stop channel to handlers registered before Start.
type delayedInformerLifetime struct {
	started chan struct{}
	stop    <-chan struct{}
}

func (l *delayedInformerLifetime) stopChannel() <-chan struct{} {
	select {
	case <-l.started:
		return l.stop
	default:
		return nil
	}
}

type delayedHandler struct {
	handler      cache.ResourceEventHandler
	registration *delayedHandlerRegistration
}

type delayedHandlerRegistration struct {
	mu            sync.Mutex
	inner         cache.ResourceEventHandlerRegistration
	attached      chan struct{}
	watcherSynced <-chan struct{}
	lifetime      *delayedInformerLifetime

	checkerOnce sync.Once
	checkerDone chan struct{}
}

func (r *delayedHandlerRegistration) HasSynced() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hasSyncedLocked()
}

func (r *delayedHandlerRegistration) hasSyncedLocked() bool {
	if r.inner != nil {
		return r.inner.HasSynced()
	}
	select {
	case <-r.watcherSynced:
		return true
	default:
		return false
	}
}

func (r *delayedHandlerRegistration) attach(inner cache.ResourceEventHandlerRegistration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inner = inner
	close(r.attached)
}

func (r *delayedHandlerRegistration) registration() cache.ResourceEventHandlerRegistration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner
}

// Checkers acquired before attachment retain their one-shot completion.
// Callers after attachment must wait for the actual handler to sync.
func (r *delayedHandlerRegistration) HasSyncedChecker() cache.DoneChecker {
	if inner := r.registration(); inner != nil {
		return inner.HasSyncedChecker()
	}
	return r
}

func (r *delayedHandlerRegistration) Name() string { return "delayed informer registration" }

func (r *delayedHandlerRegistration) Done() <-chan struct{} {
	r.checkerOnce.Do(func() {
		r.checkerDone = make(chan struct{})
		if !r.finishIfSyncedOrStopped() {
			go r.waitForSync()
		}
	})
	return r.checkerDone
}

// A watcher notification can arrive after attachment. Check the current
// registration under the attachment lock before reporting completion.
func (r *delayedHandlerRegistration) finishIfSyncedOrStopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.lifetime.stopChannel():
		return true
	default:
	}
	if !r.hasSyncedLocked() {
		return false
	}
	close(r.checkerDone)
	return true
}

func (r *delayedHandlerRegistration) waitForSync() {
	var started, attached <-chan struct{} = r.lifetime.started, r.attached
	synced := r.watcherSynced
	var stop <-chan struct{}
	for {
		select {
		case <-started:
			started = nil
			stop = r.lifetime.stopChannel()
		case <-stop:
			return
		case <-attached:
			attached = nil
			synced = r.registration().HasSyncedChecker().Done()
		case <-synced:
			if r.finishIfSyncedOrStopped() {
				return
			}
			// A watcher signal raced with attachment. Wait for the handler signal.
			synced = nil
		}
	}
}

type delayedIndex[T any] struct {
	name    string
	inner   atomic.Pointer[RawIndexer]
	extract func(T) []string
}

func (d *delayedIndex[T]) Lookup(key string) []any {
	if index := d.inner.Load(); index != nil {
		return (*index).Lookup(key)
	}
	return nil
}

// NewDelayedInformer installs the typed List/Watch after the CRD is discovered.
func NewDelayedInformer[T controllers.ComparableObject](
	client kube.Client,
	resource schema.GroupVersionResource,
	filter Filter,
) StartableInformer[T] {
	registration := registrationFor[T](client)
	if registration.Resource != resource {
		panic("delayed informer resource does not match its registered type")
	}
	return NewDelayedInformerFor[T](client, registration, filter)
}

// NewDelayedInformerFor is the external-API variant of NewDelayedInformer.
func NewDelayedInformerFor[T controllers.ComparableObject](
	client kube.Client,
	registration kube.InformerRegistration,
	filter Filter,
) StartableInformer[T] {
	if client == nil || client.CrdWatcher() == nil {
		panic("NewDelayedInformer called without a CRD watcher-enabled kube.Client")
	}
	resource := registration.Resource
	delayed := &delayedInformer[T]{
		watcher: client.CrdWatcher(),
		lifetime: delayedInformerLifetime{
			started: make(chan struct{}),
		},
	}
	build := func(<-chan struct{}) {
		delayed.set(newFilteredFor[T](client, registration, filter))
		log.Info("resource is ready; building client", "resource", resource.GroupResource())
	}
	if client.CrdWatcher().KnownOrCallback(resource, build) {
		build(nil)
	} else {
		log.Debug("resource is not ready; building delayed client", "resource", resource.GroupResource())
	}
	return delayed
}

func (d *delayedInformer[T]) set(active *activeInformer[T]) {
	if active == nil {
		return
	}
	d.mu.Lock()
	if d.active.Load() != nil {
		d.mu.Unlock()
		return
	}
	for _, pending := range d.handlers {
		pending.registration.attach(active.AddEventHandler(pending.handler))
	}
	d.handlers = nil
	for _, pending := range d.indexes {
		index := active.Index(pending.name, pending.extract)
		pending.inner.Store(&index)
	}
	d.indexes = nil
	d.active.Store(active)
	stop := d.lifetime.stop
	d.mu.Unlock()
	if stop != nil {
		active.Start(stop)
	}
}

func (d *delayedInformer[T]) Start(stop <-chan struct{}) {
	d.mu.Lock()
	if d.lifetime.stop == nil && stop != nil {
		d.lifetime.stop = stop
		close(d.lifetime.started)
	}
	stop = d.lifetime.stop
	active := d.active.Load()
	d.mu.Unlock()
	if active != nil {
		active.Start(stop)
	}
}

func (d *delayedInformer[T]) Get(name, namespace string) T {
	if active := d.active.Load(); active != nil {
		return active.Get(name, namespace)
	}
	return ptr.Empty[T]()
}

func (d *delayedInformer[T]) List(namespace string, selector klabels.Selector) []T {
	if active := d.active.Load(); active != nil {
		return active.List(namespace, selector)
	}
	return nil
}

func (d *delayedInformer[T]) AddEventHandler(handler cache.ResourceEventHandler) cache.ResourceEventHandlerRegistration {
	if active := d.active.Load(); active != nil {
		return active.AddEventHandler(handler)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if active := d.active.Load(); active != nil {
		return active.AddEventHandler(handler)
	}
	registration := &delayedHandlerRegistration{
		attached:      make(chan struct{}),
		watcherSynced: d.watcher.Synced(),
		lifetime:      &d.lifetime,
	}
	d.handlers = append(d.handlers, delayedHandler{
		handler:      handler,
		registration: registration,
	})
	return registration
}

func (d *delayedInformer[T]) HasSynced() bool {
	if active := d.active.Load(); active != nil {
		return active.HasSynced()
	}
	return d.watcher.HasSynced()
}

func (d *delayedInformer[T]) HasSyncedIgnoringHandlers() bool {
	if active := d.active.Load(); active != nil {
		return active.HasSyncedIgnoringHandlers()
	}
	return d.watcher.HasSynced()
}

func (d *delayedInformer[T]) ShutdownHandler(registration cache.ResourceEventHandlerRegistration) {
	if delayed, ok := registration.(*delayedHandlerRegistration); ok {
		d.mu.Lock()
		if inner := delayed.registration(); inner != nil {
			active := d.active.Load()
			d.mu.Unlock()
			active.ShutdownHandler(inner)
			return
		}
		defer d.mu.Unlock()
		for i, pending := range d.handlers {
			if pending.registration == delayed {
				d.handlers = append(d.handlers[:i], d.handlers[i+1:]...)
				return
			}
		}
		return
	}
	if active := d.active.Load(); active != nil {
		active.ShutdownHandler(registration)
	}
}

func (d *delayedInformer[T]) ShutdownHandlers() {
	d.mu.Lock()
	d.handlers = nil
	active := d.active.Load()
	d.mu.Unlock()
	if active != nil {
		active.ShutdownHandlers()
	}
}

func (d *delayedInformer[T]) Index(name string, extract func(T) []string) RawIndexer {
	if active := d.active.Load(); active != nil {
		return active.Index(name, extract)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if active := d.active.Load(); active != nil {
		return active.Index(name, extract)
	}
	index := &delayedIndex[T]{
		name:    name,
		extract: extract,
	}
	d.indexes = append(d.indexes, index)
	return index
}
