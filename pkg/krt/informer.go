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

package krt

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"

	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	agentlog "github.com/openkruise/agentio/pkg/log"
)

type informer[I controllers.ComparableObject] struct {
	inf            kclient.Informer[I]
	log            *agentlog.Logger
	collectionName string
	id             collectionUID

	// eventHandlers is non-nil only when debounce is enabled.
	eventHandlers *handlerSet[I]
	augmentation  func(a any) any
	synced        chan struct{}
	stop          <-chan struct{}
	baseSyncer    Syncer
	metadata      Metadata
}

// nolint: unused // (not true, its to implement an interface)
func (i *informer[I]) augment(a any) any {
	if i.augmentation != nil {
		return i.augmentation(a)
	}
	return a
}

var _ internalCollection[controllers.Object] = &informer[controllers.Object]{}

// nolint: unused // (not true, its to implement an interface)
func (i *informer[I]) _internalHandler() {}

func (i *informer[I]) Synced() Syncer {
	return channelSyncer{
		name:   i.collectionName,
		synced: i.synced,
	}
}

func (i *informer[I]) HasSynced() bool {
	return i.baseSyncer.HasSynced()
}

func (i *informer[I]) WaitUntilSynced(stop <-chan struct{}) bool {
	return i.baseSyncer.WaitUntilSynced(stop)
}

// nolint: unused // (not true, its to implement an interface)
func (i *informer[I]) dump() CollectionDump {
	return CollectionDump{
		Outputs: eraseMap(slices.GroupUnique(i.inf.List(metav1.NamespaceAll, klabels.Everything()), getTypedKey)),
		Synced:  i.HasSynced(),
	}
}

func (i *informer[I]) name() string {
	return i.collectionName
}

// nolint: unused // (not true, its to implement an interface)
func (i *informer[I]) uid() collectionUID {
	return i.id
}

// ListFiltered returns objects accepted by filter. A nil filter returns all objects.
//
// The filter may be evaluated while a collection's read lock is held. It must not access or modify the
// collection, its indexes, or its objects: attempting to acquire the read lock again can deadlock. Filters must be
// short-lived and non-blocking, since they can delay collection updates.
func (i *informer[I]) ListFiltered(filter func(I) bool) []I {
	res := i.inf.List(metav1.NamespaceAll, klabels.Everything())
	if filter == nil {
		return res
	}
	return slices.FilterInPlace(res, filter)
}

func (i *informer[I]) GetKey(k string) *I {
	// Passes the pre-joined "ns/name" key straight through; depends on kclient's keyFunc.
	if got := i.inf.Get(k, ""); !controllers.IsNil(got) {
		return &got
	}
	return nil
}

func (i *informer[I]) Metadata() Metadata {
	return i.metadata
}

func (i *informer[I]) Register(f func(o Event[I])) HandlerRegistration {
	return registerHandlerAsBatched[I](i, f)
}

func (i *informer[I]) RegisterBatch(f func(o []Event[I]), runExistingState bool) HandlerRegistration {
	// Note: runExistingState is NOT respected here.
	// Informer doesn't expose a way to opt-out; Kubernetes always replays cached items to a newly-registered handler.
	_ = runExistingState

	if i.eventHandlers == nil {
		// Debounce off: register directly on the Kubernetes informer. Each handler
		// gets its own per-handler syncTracker via cache.ResourceEventHandlerRegistration.
		synced := i.inf.AddEventHandler(informerEventHandler[I](func(o Event[I], initialSync bool) {
			f([]Event[I]{o})
		}))
		handlerSyncer := pollSyncer{
			name: fmt.Sprintf("%v handler", i.name()),
			f:    synced.HasSynced,
		}
		return informerHandlerRegistration{
			Syncer: multiSyncer{
				syncers: []Syncer{i.baseSyncer, handlerSyncer},
			},
			remove: func() {
				i.inf.ShutdownHandler(synced)
			},
		}
	}

	// Debounce on: replay a cache snapshot; duplicate Adds are possible and absorbed by idempotent consumers.
	existing := i.inf.List(metav1.NamespaceAll, klabels.Everything())
	initial := make([]Event[I], 0, len(existing))
	for _, obj := range existing {
		o := obj
		initial = append(initial, Event[I]{
			New:   &o,
			Event: controllers.EventAdd,
		})
	}

	return i.eventHandlers.Insert(f, i.baseSyncer, initial, i.stop)
}

type informerHandlerRegistration struct {
	Syncer
	remove func()
}

func (i informerHandlerRegistration) UnregisterHandler() {
	i.remove()
}

// nolint: unused // (not true)
type informerIndex[I any] struct {
	idx kclient.RawIndexer
}

// nolint: unused // (not true)
// LookupFiltered returns objects matching the key and filter. A nil filter returns all objects for the key.
//
// The filter may be evaluated while a collection's read lock is held. It must not access or modify the
// collection, its indexes, or its objects: attempting to acquire the read lock again can deadlock. Filters must be
// short-lived and non-blocking, since they can delay collection updates.
func (ii *informerIndex[I]) LookupFiltered(key string, filter func(I) bool) []I {
	objects := ii.idx.Lookup(key)
	var res []I
	if filter == nil {
		res = make([]I, 0, len(objects))
	}
	for _, obj := range objects {
		v := obj.(I)
		if filter == nil || filter(v) {
			res = append(res, v)
		}
	}
	return res
}

// nolint: unused // (not true)
func (i *informer[I]) index(name string, extract func(o I) []string) indexer[I] {
	idx := i.inf.Index(name, extract)
	return &informerIndex[I]{
		idx: idx,
	}
}

func informerEventHandler[I controllers.ComparableObject](
	handler func(o Event[I], initialSync bool),
) cache.ResourceEventHandler {
	return controllers.EventHandler[I]{
		AddExtendedFunc: func(obj I, initialSync bool) {
			handler(Event[I]{
				New:   &obj,
				Event: controllers.EventAdd,
			}, initialSync)
		},
		UpdateFunc: func(oldObj, newObj I) {
			handler(Event[I]{
				Old:   &oldObj,
				New:   &newObj,
				Event: controllers.EventUpdate,
			}, false)
		},
		DeleteFunc: func(obj I) {
			handler(Event[I]{
				Old:   &obj,
				Event: controllers.EventDelete,
			}, false)
		},
	}
}

// WrapClient is the base entrypoint that enables the creation
// of a collection from an API Server client.
//
// Generic types can use kclient.NewDynamic to create an
// informer for a Collection of type controllers.Object
func WrapClient[I controllers.ComparableObject](c kclient.Informer[I], opts ...CollectionOption) Collection[I] {
	o := buildCollectionOptions(opts...)
	if o.name == "" {
		o.name = fmt.Sprintf("Informer[%v]", ptr.TypeName[I]())
	}
	h := &informer[I]{
		inf:            c,
		log:            log.With("owner", o.name),
		collectionName: o.name,
		id:             nextUID(),
		augmentation:   o.augmentation,
		synced:         make(chan struct{}),
		stop:           o.stop,
	}
	h.baseSyncer = channelSyncer{
		name:   h.collectionName,
		synced: h.synced,
	}

	if o.metadata != nil {
		h.metadata = o.metadata
	}

	if o.debounceInterval > 0 {
		// Debounce mode: one shared Kubernetes handler fans events through the debouncer.
		h.eventHandlers = newHandlerSet[I]()
		h.eventHandlers.WithDebounce(o.debounceInterval, o.debounceMaxInterval, o.stop)
		c.AddEventHandler(informerEventHandler[I](func(e Event[I], initialSync bool) {
			h.eventHandlers.Distribute([]Event[I]{e}, initialSync)
		}))
	}

	maybeRegisterCollectionForDebugging(h, o.debugger)
	go func() {
		defer maybeUnregisterCollectionFromDebugger(h, o.debugger)
		defer c.ShutdownHandlers()
		// First, wait for the informer to populate. We ignore handlers which have their own syncing
		if !kube.WaitForCacheSync(o.name, o.stop, c.HasSyncedIgnoringHandlers) {
			return
		}

		// Gate synced on the first debouncer flush; c.HasSynced is unsafe here because
		// SingleFileTracker counts fluctuate during the initial drain.
		if h.eventHandlers != nil {
			if debSynced := h.eventHandlers.DebouncerSynced(); debSynced != nil &&
				len(c.List(metav1.NamespaceAll, klabels.Everything())) > 0 {
				select {
				case <-debSynced:
				case <-o.stop:
					return
				}
			}
		}
		close(h.synced)
		h.log.Info("collection synced", "collection", h.name())

		<-o.stop
	}()
	return newCollection[I](h)
}

// NewInformer creates a collection from the shared informer owned by Client.
func NewInformer[I controllers.ComparableObject](
	client kube.Client,
	options ...CollectionOption,
) Collection[I] {
	return NewFilteredInformer[I](client, kclient.Filter{}, options...)
}

// NewFilteredInformer creates a collection with server- and client-side
// filtering applied by kclient.
func NewFilteredInformer[I controllers.ComparableObject](
	client kube.Client,
	filter kclient.Filter,
	options ...CollectionOption,
) Collection[I] {
	return WrapClient(kclient.NewFiltered[I](client, filter), options...)
}
