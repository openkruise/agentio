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
	"context"
	"maps"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// Subscription receives changes for resource types watched by a stream.
type Subscription interface {
	Watch(string)
	Updates() <-chan Update
}

type subscriber struct {
	updates chan Update
	// Only notifyLocked reads this ID, after receiving the corresponding notice.
	mailboxID       uint64
	types           sets.Set[string]
	sandboxWorkload string
}

// subscription allows an xDS stream to add watched types as requests arrive.
// Store notifications can then skip connections that cannot be affected.
type subscription struct {
	store   *Store
	id      uint64
	updates <-chan Update
}

func (s *subscription) Updates() <-chan Update { return s.updates }

func (s *subscription) Watch(typeURL string) {
	s.store.mu.Lock()
	if sub := s.store.subscribers[s.id]; sub != nil {
		if !sub.types.Contains(typeURL) {
			sub.types.Insert(typeURL)
			byID := s.store.subscribersByType[typeURL]
			if byID == nil {
				byID = make(map[uint64]*subscriber)
				s.store.subscribersByType[typeURL] = byID
			}
			byID[s.id] = sub
			if typeURL == model.SandboxType {
				byWorkload := s.store.sandboxSubscribersByWorkload[sub.sandboxWorkload]
				if byWorkload == nil {
					byWorkload = make(map[uint64]*subscriber)
					s.store.sandboxSubscribersByWorkload[sub.sandboxWorkload] = byWorkload
				}
				byWorkload[s.id] = sub
			}
		}
	}
	s.store.mu.Unlock()
}

// Subscribe registers a watcher that is released when ctx is canceled.
func (s *Store) Subscribe(ctx context.Context, scope model.ClientScope) Subscription {
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	updates := make(chan Update, 1)
	sub := &subscriber{updates: updates, types: sets.New[string]()}
	if scope.Class == model.ClientDedicatedZTunnel {
		sub.sandboxWorkload = scope.WorkloadUID
	}
	s.subscribers[id] = sub
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		if subscriber := s.subscribers[id]; subscriber != nil {
			if subscriber.types.Contains(model.SandboxType) {
				byWorkload := s.sandboxSubscribersByWorkload[subscriber.sandboxWorkload]
				delete(byWorkload, id)
				if len(byWorkload) == 0 {
					delete(s.sandboxSubscribersByWorkload, subscriber.sandboxWorkload)
				}
			}
			for typeURL := range subscriber.types {
				delete(s.subscribersByType[typeURL], id)
				if len(s.subscribersByType[typeURL]) == 0 {
					delete(s.subscribersByType, typeURL)
				}
			}
		}
		delete(s.subscribers, id)
		s.mu.Unlock()
	}()
	return &subscription{store: s, id: id, updates: updates}
}

// The returned map may borrow an index; callers must only read it while holding s.mu.
func (s *Store) affectedSubscribersLocked(update Update) map[uint64]*subscriber {
	if update.full && len(update.fullTypes) == 0 {
		return s.subscribers
	}
	var result map[uint64]*subscriber
	borrowed := false
	affectedTypes := sets.NewWithLength[string](len(update.fullTypes) + len(update.affectedTypes))
	for typeURL := range update.fullTypes {
		affectedTypes.Insert(typeURL)
	}
	for typeURL := range update.affectedTypes {
		affectedTypes.Insert(typeURL)
	}
	for typeURL := range affectedTypes {
		subscribers := s.subscribersByType[typeURL]
		if typeURL == model.SandboxType && !update.FullFor(typeURL) {
			subscribers = s.sandboxSubscribersLocked(update.Candidates(typeURL))
		}
		if len(subscribers) == 0 {
			continue
		}
		if result == nil {
			result = subscribers
			borrowed = true
			continue
		}
		if borrowed {
			result = maps.Clone(result)
			borrowed = false
		}
		maps.Copy(result, subscribers)
	}
	return result
}

// Empty workload keys retain broad subscribers (gateways and node-shared streams).
// The generator still checks current ownership, source identity and visibility.
func (s *Store) sandboxSubscribersLocked(candidates []Candidate) map[uint64]*subscriber {
	result := make(map[uint64]*subscriber)
	maps.Copy(result, s.sandboxSubscribersByWorkload[""])
	for _, candidate := range candidates {
		if len(candidate.Identities) == 0 {
			// Unpublished source invalidations have no ownership evidence.
			return s.subscribersByType[model.SandboxType]
		}
		for _, identity := range candidate.Identities {
			if identity.Facts.Sandbox == nil {
				return s.subscribersByType[model.SandboxType]
			}
			uid := identity.Facts.Sandbox.AttesterWorkloadUID
			if uid != "" {
				maps.Copy(result, s.sandboxSubscribersByWorkload[uid])
			}
		}
	}
	return result
}
