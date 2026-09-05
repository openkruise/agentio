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
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

// CompiledResources is the compiler output that the controller publishes.
type CompiledResources interface {
	Snapshot() (model.ResourceSet, error)
	Resources() krt.EventStream[model.Resource]
}

// Publication is the result of atomically committing a snapshot change.
// Snapshot is the exact last-known-good state after the attempted publication.
type Publication struct {
	Changed  bool
	Snapshot model.ResourceSet
}

// ResourcePublisher atomically commits compiled snapshots and dirty changes.
type ResourcePublisher interface {
	Replace(model.ResourceSet) Publication
	Apply([]model.ResourceChange) (Publication, error)
	NotifyType(string)
}

func nilResourcePublisher(publisher ResourcePublisher) bool {
	if publisher == nil {
		return true
	}
	value := reflect.ValueOf(publisher)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}

type Controller struct {
	source   CompiledResources
	store    ResourcePublisher
	quiet    time.Duration
	maximum  time.Duration
	triggers chan struct{}

	mu           sync.Mutex
	pendingFull  bool
	changes      map[model.ResourceKey]model.ResourceChange
	pendingTypes sets.Set[string]
}

func NewController(source CompiledResources, store ResourcePublisher, quiet, maximum time.Duration) (*Controller, error) {
	if source == nil || nilResourcePublisher(store) {
		return nil, fmt.Errorf("snapshot source and store are required")
	}
	if quiet <= 0 || maximum < quiet {
		return nil, fmt.Errorf("invalid push debounce periods")
	}
	return &Controller{
		source:       source,
		store:        store,
		quiet:        quiet,
		maximum:      maximum,
		triggers:     make(chan struct{}, 1),
		changes:      make(map[model.ResourceKey]model.ResourceChange),
		pendingTypes: sets.New[string](),
	}, nil
}

// TriggerType requests a debounced regeneration of one dynamic type whose
// source is not retained in ResourceSet (for example direct Workload
// projections enriched from policy assignments).
func (c *Controller) TriggerType(typeURL string) {
	if typeURL == "" {
		return
	}
	c.mu.Lock()
	c.pendingTypes.Insert(typeURL)
	c.mu.Unlock()
	c.signal()
}

func (c *Controller) Trigger() {
	c.mu.Lock()
	c.pendingFull = true
	c.mu.Unlock()
	c.signal()
}

// Enqueue preserves the compiled KRT delta through the debounce boundary. A
// later event for the same key replaces the desired value while retaining the
// first Old resource, so add/update/delete bursts collapse to their net effect.
func (c *Controller) Enqueue(changes []model.ResourceChange) {
	if len(changes) == 0 {
		return
	}
	c.mu.Lock()
	for _, change := range changes {
		if existing, found := c.changes[change.Key]; found {
			change.Old = existing.Old
		}
		if resourcesEqual(change.Old, change.New) {
			delete(c.changes, change.Key)
		} else {
			c.changes[change.Key] = change
		}
	}
	c.mu.Unlock()
	c.signal()
}

func (c *Controller) signal() {
	select {
	case c.triggers <- struct{}{}:
	default:
	}
}

func (c *Controller) takePending() (bool, []model.ResourceChange, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	full := c.pendingFull
	c.pendingFull = false
	changes := make([]model.ResourceChange, 0, len(c.changes))
	for _, change := range c.changes {
		changes = append(changes, change)
	}
	clear(c.changes)
	types := make([]string, 0, len(c.pendingTypes))
	for typeURL := range c.pendingTypes {
		types = append(types, typeURL)
	}
	clear(c.pendingTypes)
	sort.Strings(types)
	return full, changes, types
}

func (c *Controller) Run(ctx context.Context) error {
	registration := c.source.Resources().RegisterBatch(func(batch []krt.Event[model.Resource]) {
		c.Enqueue(resourceChanges(batch))
	}, true)
	defer registration.UnregisterHandler()
	c.Trigger()
	var quietTimer, maximumTimer *time.Timer
	var quietChannel, maximumChannel <-chan time.Time
	pending := false
	stop := func(timer **time.Timer) {
		if *timer != nil {
			(*timer).Stop()
			*timer = nil
		}
	}
	flush := func() {
		if !pending {
			return
		}
		pending = false
		stop(&quietTimer)
		stop(&maximumTimer)
		quietChannel, maximumChannel = nil, nil
		full, changes, types := c.takePending()
		started := time.Now()
		var publication Publication
		var err error
		publishStarted := time.Now()
		if full {
			var snapshot model.ResourceSet
			snapshot, err = c.source.Snapshot()
			if err == nil {
				publication = c.store.Replace(snapshot)
			}
		} else {
			publication, err = c.store.Apply(changes)
		}
		compileDuration := time.Since(started)
		metrics.Default.RecordCompile(compileDuration, err, publication.Snapshot.Len())
		if err != nil {
			log.Error("configuration compilation failed; preserving last-known-good snapshot",
				"full", full, "changes", len(changes), "types", types,
				"duration", compileDuration, "error", err)
			return
		}
		for _, typeURL := range types {
			c.store.NotifyType(typeURL)
		}
		if publication.Changed {
			metrics.Default.RecordPublish(time.Since(publishStarted))
			metrics.Default.SetSnapshotResourcesByType(publication.Snapshot.CountsByType())
		}
		log.Debug("XDS configuration calculated", "full", full,
			"changes", len(changes), "types", types,
			"resources", publication.Snapshot.Len(), "changed", publication.Changed,
			"duration", time.Since(started))
	}
	for {
		select {
		case <-ctx.Done():
			// Drain an unread trigger before flushing; select may pick ctx.Done()
			// while a trigger is still queued.
			select {
			case <-c.triggers:
				pending = true
			default:
			}
			flush()
			return nil
		case <-c.triggers:
			pending = true
			stop(&quietTimer)
			quietTimer = time.NewTimer(c.quiet)
			quietChannel = quietTimer.C
			if maximumTimer == nil {
				maximumTimer = time.NewTimer(c.maximum)
				maximumChannel = maximumTimer.C
			}
		case <-quietChannel:
			flush()
		case <-maximumChannel:
			flush()
		}
	}
}

func resourceChanges(events []krt.Event[model.Resource]) []model.ResourceChange {
	changes := make([]model.ResourceChange, 0, len(events))
	for _, event := range events {
		if event.Old != nil && event.New != nil && event.Old.Key != event.New.Key {
			oldResource := *event.Old
			changes = append(changes, model.ResourceChange{Key: oldResource.Key, Old: &oldResource})
			newResource := *event.New
			changes = append(changes, model.ResourceChange{Key: newResource.Key, New: &newResource})
			continue
		}
		change := model.ResourceChange{}
		if event.Old != nil {
			oldResource := *event.Old
			change.Key = oldResource.Key
			change.Old = &oldResource
		}
		if event.New != nil {
			newResource := *event.New
			change.Key = newResource.Key
			change.New = &newResource
		}
		changes = append(changes, change)
	}
	return changes
}

func resourcesEqual(left, right *model.Resource) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Hash == right.Hash
}
