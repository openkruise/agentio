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

package store

import (
	"sync"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// Publication is the result of atomically committing a snapshot change.
// Snapshot is the exact last-known-good state after the attempted publication.
type Publication struct {
	Changed  bool
	Snapshot model.ResourceSet
	// SubscriberCount is the total at publication time, including subscribers
	// not affected by this batch. It does not count completed sends or ACKs.
	SubscriberCount int
}

// Store publishes immutable resource snapshots and notifies interested subscribers.
type Store struct {
	mu          sync.RWMutex
	current     model.ResourceSet
	subscribers map[uint64]*subscriber
	// subscribersByType indexes subscribers by watched type.
	subscribersByType            map[string]map[uint64]*subscriber
	sandboxSubscribersByWorkload map[string]map[uint64]*subscriber
	nextID                       uint64
	nextMailboxID                uint64
}

// New creates a store with an initial snapshot and no subscribers.
func New(initial model.ResourceSet) *Store {
	return &Store{
		current:                      initial,
		subscribers:                  make(map[uint64]*subscriber),
		subscribersByType:            make(map[string]map[uint64]*subscriber),
		sandboxSubscribersByWorkload: make(map[string]map[uint64]*subscriber),
	}
}

// Snapshot returns the current immutable publication.
func (s *Store) Snapshot() model.ResourceSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Replace atomically installs a snapshot and notifies subscribers of effective changes.
func (s *Store) Replace(snapshot model.ResourceSet) Publication {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.current
	changes := before.Diff(snapshot)
	if len(changes) == 0 {
		return Publication{Snapshot: s.current, SubscriberCount: len(s.subscribers)}
	}
	s.current = snapshot
	s.notifyLocked(updateBetween(before, snapshot, changes))
	return Publication{Changed: true, Snapshot: snapshot, SubscriberCount: len(s.subscribers)}
}

// Apply publishes a compiled KRT batch without listing or rebuilding the full
// resource graph. Multiple changes for the same key collapse to their final
// value before the immutable snapshot is updated.
func (s *Store) Apply(changes []model.ResourceChange) (Publication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	coalesced := coalesceChanges(changes)
	if len(coalesced) == 0 {
		return Publication{Snapshot: s.current, SubscriberCount: len(s.subscribers)}, nil
	}
	before := s.current
	next, changed, err := before.Apply(coalesced)
	if err != nil || !changed {
		return Publication{Snapshot: before, SubscriberCount: len(s.subscribers)}, err
	}
	effective := make([]model.ResourceChange, 0, len(coalesced))
	for _, requested := range coalesced {
		oldResource, hadOld := before.Get(requested.Key)
		newResource, hasNew := next.Get(requested.Key)
		if hadOld && hasNew && oldResource.Hash == newResource.Hash {
			continue
		}
		change := model.ResourceChange{Key: requested.Key}
		if hadOld {
			oldCopy := oldResource
			change.Old = &oldCopy
		}
		if hasNew {
			newCopy := newResource
			change.New = &newCopy
		}
		effective = append(effective, change)
	}
	if len(effective) == 0 {
		return Publication{Snapshot: before, SubscriberCount: len(s.subscribers)}, nil
	}
	s.current = next
	s.notifyLocked(updateBetween(before, next, effective))
	return Publication{Changed: true, Snapshot: next, SubscriberCount: len(s.subscribers)}, nil
}

// Notify wakes subscribers when a dynamic resource outside the immutable
// snapshot (for example an on-demand SDS certificate) changes.
func (s *Store) Notify() {
	s.mu.Lock()
	s.notifyLocked(Update{
		version: s.current.Version(),
		full:    true,
	})
	s.mu.Unlock()
}

// NotifyType wakes only streams watching a dynamic resource type, such as SDS.
func (s *Store) NotifyType(typeURL string) {
	s.mu.Lock()
	s.notifyLocked(Update{
		version:   s.current.Version(),
		full:      true,
		fullTypes: sets.New(typeURL),
	})
	s.mu.Unlock()
}

// NotifyKeys invalidates source keys even when they have never been published.
// It reuses the type-scoped subscriber mailboxes without changing the snapshot.
func (s *Store) NotifyKeys(keys []model.ResourceKey) {
	if len(keys) == 0 {
		return
	}
	candidates := make(map[model.ResourceKey]Candidate, len(keys))
	for _, key := range keys {
		candidates[key] = Candidate{Key: key}
	}
	s.mu.Lock()
	s.notifyLocked(indexedUpdate(s.current.Version(), candidates))
	s.mu.Unlock()
}

func (s *Store) notifyLocked(update Update) {
	s.nextMailboxID++
	publicationID := s.nextMailboxID
	// Readers at the same backlog boundary share the same immutable notice.
	// Merge that notice with this publication once, not once per connection.
	// Keep this cache local: readers at different boundaries need different unions.
	type notice struct {
		update Update
		id     uint64
	}
	var mergedByPending map[uint64]notice
	for _, subscriber := range s.affectedSubscribersLocked(update) {
		// Capacity-one, type-aware mailbox; the first coalescing boundary.
		// PushScheduler merges later duplicates.
		select {
		case subscriber.updates <- update:
			subscriber.mailboxID = publicationID
		default:
			merged := update
			mergedID := publicationID
			select {
			case pending := <-subscriber.updates:
				cached, found := mergedByPending[subscriber.mailboxID]
				if !found {
					s.nextMailboxID++
					cached = notice{update: Merge(pending, update), id: s.nextMailboxID}
					if mergedByPending == nil {
						mergedByPending = make(map[uint64]notice)
					}
					mergedByPending[subscriber.mailboxID] = cached
				}
				merged, mergedID = cached.update, cached.id
			default:
			}
			select {
			case subscriber.updates <- merged:
				subscriber.mailboxID = mergedID
			default:
			}
		}
	}
}
