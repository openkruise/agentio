// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

// Package kclient provides the Informer contract consumed by krt.
package kclient

import (
	"sync"

	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// RawIndexer is an index whose values have not been cast back to their concrete
// type. krt wraps this in its own typed Index.
type RawIndexer interface {
	Lookup(key string) []any
}

// DynamicObjectFilter controls the logical view exposed by an informer.
// Implementations must update their state before notifying handlers and must be
// safe for concurrent calls to Filter.
type DynamicObjectFilter interface {
	Filter(obj any) bool
	AddHandler(func(added, removed sets.Set[string]))
}

// Filter configures server-side selectors, cache transforms, and optional
// client-side filtering for an informer. ObjectFilter does not reduce the
// objects stored in the underlying cache.
type Filter struct {
	LabelSelector   string
	FieldSelector   string
	Namespace       string
	ObjectFilter    DynamicObjectFilter
	ObjectTransform func(any) (any, error)
}

// Reader provides cached read access to a single resource type.
type Reader[T controllers.Object] interface {
	// Get looks up an object by name and namespace. A zero value is returned
	// when it does not exist.
	//
	// An empty namespace treats name as a pre-joined "namespace/name" cache key.
	Get(name, namespace string) T
	// List looks up objects by namespace and labels. Use metav1.NamespaceAll
	// and klabels.Everything() to select everything.
	List(namespace string, selector klabels.Selector) []T
}

// Informer is the informer surface required by KRT.
type Informer[T controllers.Object] interface {
	Reader[T]
	// AddEventHandler registers a handler for Create/Update/Delete. The
	// returned registration can be passed to ShutdownHandler.
	AddEventHandler(h cache.ResourceEventHandler) cache.ResourceEventHandlerRegistration
	// HasSynced reports whether the informer is populated *and* every handler
	// added through AddEventHandler has been called with the initial state.
	// This differs from a plain informer HasSynced, which ignores handlers.
	HasSynced() bool
	// HasSyncedIgnoringHandlers reports whether the underlying informer is
	// populated, disregarding handler progress.
	HasSyncedIgnoringHandlers() bool
	// ShutdownHandler removes a single handler added by AddEventHandler.
	ShutdownHandler(registration cache.ResourceEventHandlerRegistration)
	// ShutdownHandlers removes every handler added by AddEventHandler. Handlers
	// registered directly on the underlying informer are untouched.
	ShutdownHandlers()
	// Index creates a named index over the collection. The extract function
	// returns every key an object should be found under. Re-requesting an
	// existing name returns the existing index rather than rebuilding it.
	Index(name string, extract func(o T) []string) RawIndexer
}

type handlerRegistration struct {
	registration cache.ResourceEventHandlerRegistration
	handler      cache.ResourceEventHandler
}

type informerClient[T controllers.Object] struct {
	informer cache.SharedIndexInformer
	filter   func(any) bool

	handlerMu          sync.RWMutex
	registeredHandlers []handlerRegistration
}

// New adapts a client-go SharedIndexInformer, typically obtained from a
// SharedInformerFactory, into an Informer krt can wrap with krt.WrapClient.
//
// The informer's lifecycle stays with its factory: New neither starts it nor
// waits for it to sync.
func New[T controllers.Object](informer cache.SharedIndexInformer) Informer[T] {
	return newInformerClient[T](informer, Filter{})
}

// newInformerClient adapts a client-go SharedIndexInformer into an Informer with an
// optional dynamic client-side object filter.
func newInformerClient[T controllers.Object](informer cache.SharedIndexInformer, filter Filter) Informer[T] {
	client := &informerClient[T]{
		informer: informer,
	}
	if filter.ObjectFilter != nil {
		client.filter = filter.ObjectFilter.Filter
		filter.ObjectFilter.AddHandler(client.applyDynamicFilter)
	}
	return client
}

func (n *informerClient[T]) Get(name, namespace string) T {
	obj, exists, err := n.informer.GetIndexer().GetByKey(keyFunc(name, namespace))
	if err != nil || !exists {
		return ptr.Empty[T]()
	}
	cast, ok := obj.(T)
	if !ok || !n.applyFilter(cast) {
		return ptr.Empty[T]()
	}
	return cast
}

func (n *informerClient[T]) List(namespace string, selector klabels.Selector) []T {
	var result []T
	// Errors here can only come from a malformed namespace index, which would
	// be a programming error in this package rather than a runtime condition.
	_ = cache.ListAllByNamespace(n.informer.GetIndexer(), namespace, selector, func(i any) {
		if cast, ok := i.(T); ok && n.applyFilter(cast) {
			result = append(result, cast)
		}
	})
	return result
}

func (n *informerClient[T]) listUnfiltered(namespace string) []T {
	var result []T
	_ = cache.ListAllByNamespace(n.informer.GetIndexer(), namespace, klabels.Everything(), func(i any) {
		if cast, ok := i.(T); ok {
			result = append(result, cast)
		}
	})
	return result
}

func (n *informerClient[T]) applyFilter(obj any) bool {
	return n.filter == nil || n.filter(obj)
}

func (n *informerClient[T]) AddEventHandler(h cache.ResourceEventHandler) cache.ResourceEventHandlerRegistration {
	n.handlerMu.Lock()
	defer n.handlerMu.Unlock()
	// Registering under the lock enqueues the existing items without blocking
	// on their delivery, and keeps a handler from being processed before it is
	// visible in registeredHandlers.
	registeredHandler := h
	if n.filter != nil {
		registeredHandler = cache.FilteringResourceEventHandler{
			FilterFunc: n.filter,
			Handler:    h,
		}
	}
	registration, err := n.informer.AddEventHandler(registeredHandler)
	if err != nil {
		// Only reachable once the informer has stopped.
		return neverSynced{}
	}
	n.registeredHandlers = append(n.registeredHandlers, handlerRegistration{
		registration: registration,
		handler:      h,
	})
	return registration
}

func (n *informerClient[T]) HasSynced() bool {
	if !n.informer.HasSynced() {
		return false
	}
	n.handlerMu.RLock()
	defer n.handlerMu.RUnlock()
	for _, handler := range n.registeredHandlers {
		if !handler.registration.HasSynced() {
			return false
		}
	}
	return true
}

func (n *informerClient[T]) HasSyncedIgnoringHandlers() bool {
	return n.informer.HasSynced()
}

func (n *informerClient[T]) ShutdownHandler(registration cache.ResourceEventHandlerRegistration) {
	n.handlerMu.Lock()
	defer n.handlerMu.Unlock()
	n.registeredHandlers = slices.FilterInPlace(n.registeredHandlers, func(h handlerRegistration) bool {
		return h.registration != registration
	})
	_ = n.informer.RemoveEventHandler(registration)
}

func (n *informerClient[T]) ShutdownHandlers() {
	n.handlerMu.Lock()
	defer n.handlerMu.Unlock()
	for _, handler := range n.registeredHandlers {
		_ = n.informer.RemoveEventHandler(handler.registration)
	}
	n.registeredHandlers = nil
}

func (n *informerClient[T]) applyDynamicFilter(added, removed sets.Set[string]) {
	handlers := n.snapshotHandlers()
	for namespace := range added {
		for _, item := range n.listUnfiltered(namespace) {
			for _, handler := range handlers {
				handler.OnAdd(item, false)
			}
		}
	}
	for namespace := range removed {
		for _, item := range n.listUnfiltered(namespace) {
			for _, handler := range handlers {
				handler.OnDelete(item)
			}
		}
	}
}

func (n *informerClient[T]) snapshotHandlers() []cache.ResourceEventHandler {
	n.handlerMu.RLock()
	defer n.handlerMu.RUnlock()

	handlers := make([]cache.ResourceEventHandler, 0, len(n.registeredHandlers))
	for _, handler := range n.registeredHandlers {
		handlers = append(handlers, handler.handler)
	}
	return handlers
}

func (n *informerClient[T]) Index(name string, extract func(o T) []string) RawIndexer {
	if _, found := n.informer.GetIndexer().GetIndexers()[name]; !found {
		// client-go permits AddIndexers until the informer stops, so an index
		// may be created after startup; existing items are back-filled.
		if err := n.informer.AddIndexers(cache.Indexers{
			name: func(obj any) ([]string, error) {
				return extract(controllers.Extract[T](obj)), nil
			},
		}); err != nil {
			// Only reachable on a name conflict or after stop, neither of which
			// should abort the caller. Lookups then return nothing.
			log.Warn("failed to add indexer", "index", name, "error", err)
			return emptyIndexer{}
		}
	}
	return rawIndexer{
		key:     name,
		indexer: n.informer.GetIndexer(),
		filter:  n.filter,
	}
}

type rawIndexer struct {
	key     string
	indexer cache.Indexer
	filter  func(any) bool
}

func (r rawIndexer) Lookup(key string) []any {
	result, err := r.indexer.ByIndex(r.key, key)
	if err != nil {
		// Only possible when the index does not exist, which Index() guarantees.
		log.Warn("index lookup failed", "index", r.key, "error", err)
		return nil
	}
	if r.filter != nil {
		return slices.FilterInPlace(result, r.filter)
	}
	return result
}

type emptyIndexer struct{}

func (emptyIndexer) Lookup(string) []any { return nil }

// neverSynced stands in for a registration on a stopped informer: it can never
// become synced, which keeps callers from waiting on it forever believing it
// will.
type neverSynced struct{}

func (neverSynced) HasSynced() bool { return false }

func (neverSynced) HasSyncedChecker() cache.DoneChecker { return neverSynced{} }

func (neverSynced) Name() string { return "stopped informer registration" }

func (neverSynced) Done() <-chan struct{} { return nil }

// keyFunc renders the cache key as "namespace/name", or "name" when the
// namespace is empty. An already-joined key passed as name therefore round-trips
// unchanged.
func keyFunc(name, namespace string) string {
	if len(namespace) == 0 {
		return name
	}
	return namespace + "/" + name
}
