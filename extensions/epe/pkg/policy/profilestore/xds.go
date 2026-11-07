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

package profilestore

import (
	"context"
	"fmt"
	"hash/maphash"
	"maps"
	"sync"
	"sync/atomic"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/model"
)

const profileShardCount = 256

var profileShardSeed = maphash.MakeSeed()

// xdsProfileSnapshot keeps demand publications immutable without copying the full cache.
type xdsProfileSnapshot struct {
	shards [profileShardCount]map[profileKey]*securityprofile.Profile
}

func profileShard(key profileKey) uint64 {
	return maphash.Comparable(profileShardSeed, key) & (profileShardCount - 1)
}

func (s *xdsProfileSnapshot) get(meta securityprofile.Meta) *securityprofile.Profile {
	key := keyFor(meta)
	return s.shards[profileShard(key)][key]
}

// XDSStore reads control-plane bindings from profiles published by the shared collection.
// It owns demand leases and publication readiness, with no selector index or deletion grace.
type XDSStore struct {
	acquire    func(context.Context, subject.Subject) ([]*securityprofile.Meta, func(), error)
	sources    model.SourceReader
	snapshot   atomic.Pointer[xdsProfileSnapshot]
	mu         sync.Mutex
	pending    map[model.ResourceKey]*pendingProfile
	rejections map[profileKey]bool
	degraded   degradedSets
}

// NewXDSStore creates an empty store for demand-loaded profiles.
func NewXDSStore() *XDSStore {
	s := &XDSStore{degraded: newDegradedSets()}
	s.snapshot.Store(&xdsProfileSnapshot{})
	s.degraded.publish()
	return s
}

// RegisterCollection connects the prepared source and its asynchronous input projection.
func (s *XDSStore) RegisterCollection(
	profiles *Collection,
	acquire func(context.Context, subject.Subject) ([]*securityprofile.Meta, func(), error),
) krt.HandlerRegistration {
	s.acquire, s.sources = acquire, profiles.Registry
	return profiles.RegisterBatch(s.applyBatch, true)
}

func (s *XDSStore) applyBatch(events []krt.Event[securityprofile.Profile]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.degraded.publish()
	next := *s.snapshot.Load()
	var copied [profileShardCount]bool
	log := ctrllog.Log.WithName("profile")
	for _, event := range events {
		p := event.Latest()
		key := keyFor(p.Meta)
		shard := profileShard(key)
		if !copied[shard] {
			next.shards[shard] = maps.Clone(next.shards[shard])
			if next.shards[shard] == nil {
				next.shards[shard] = make(map[profileKey]*securityprofile.Profile)
			}
			copied[shard] = true
		}
		values := next.shards[shard]
		if event.Event == controllers.EventDelete {
			delete(values, key)
			s.degraded.removed(key)
			continue
		}
		if previous := values[key]; previous != nil &&
			(previous.Meta.SourceIdentity != p.Meta.SourceIdentity || previous.Meta.SandboxUID != p.Meta.SandboxUID) {
			delete(values, key)
		}
		if p.CompileError != "" {
			profileCompileFailuresTotal.WithLabelValues(key.scope()).Inc()
			s.degraded.rejected(key, values[key] != nil)
			log.Error(nil, "profile publication rejected", "profile", p.ResourceName(), "error", p.CompileError)
			continue
		}
		values[key] = event.New
		s.degraded.installed(key, p.InputsError != "")
		if s.rejections[key] {
			s.degraded.rejected(key, true)
		}
		if p.InputsError != "" {
			log.Error(
				nil,
				"profile installed with unavailable inputs; rules enforce but inputs-dependent evaluations fail per each action's failure strategy",
				"profile",
				p.ResourceName(),
				"error",
				p.InputsError,
			)
		}
	}
	s.snapshot.Store(&next)
	for _, event := range events {
		s.notifyPendingLocked(profileNotificationKey(event.Latest().Meta))
	}
}

// ResolveProfiles waits for the admitted bindings and their input snapshots.
func (s *XDSStore) ResolveProfiles(ctx context.Context, subj subject.Subject) ([]*securityprofile.Profile, error) {
	refs, release, err := s.acquire(ctx, subj)
	if release != nil {
		defer release()
	}
	if err != nil {
		return nil, err
	}
	for {
		snap := s.snapshot.Load()
		profiles := make([]*securityprofile.Profile, 0, len(refs))
		var pending *securityprofile.Meta
		for _, meta := range refs {
			profile := snap.get(*meta)
			if profile == nil || profile.Meta.SourceIdentity != meta.SourceIdentity ||
				profile.Meta.AdmissionRevision < meta.AdmissionRevision ||
				(meta.SandboxUID != "" && profile.Meta.SandboxUID != meta.SandboxUID) {
				identity, present := s.sources.Lookup(profileNotificationKey(*meta))
				if !present || identity != meta.SourceIdentity {
					return nil, fmt.Errorf(
						"profile source %s disappeared or changed",
						profileNotificationKey(*meta).Name,
					)
				}
				pending = meta
				break
			}
			profiles = append(profiles, profile)
		}
		if pending == nil {
			return profiles, nil
		}
		if err := s.waitForProfileChange(ctx, profileNotificationKey(*pending), snap); err != nil {
			return nil, err
		}
	}
}

// NotifyKeys wakes requests when an admitted source disappears before its derived deletion.
func (s *XDSStore) NotifyKeys(keys []model.ResourceKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := *s.snapshot.Load()
	s.snapshot.Store(&next)
	for _, key := range keys {
		s.notifyPendingLocked(key)
	}
}

// Publication and registration share mu, so an unchanged snapshot needs no second source lookup.
func (s *XDSStore) waitForProfileChange(
	ctx context.Context,
	key model.ResourceKey,
	observed *xdsProfileSnapshot,
) error {
	s.mu.Lock()
	if s.snapshot.Load() != observed {
		s.mu.Unlock()
		return ctx.Err()
	}
	pending := s.pending[key]
	if pending == nil {
		pending = &pendingProfile{changed: make(chan struct{})}
		if s.pending == nil {
			s.pending = make(map[model.ResourceKey]*pendingProfile)
		}
		s.pending[key] = pending
	}
	pending.waiters++
	s.mu.Unlock()
	select {
	case <-pending.changed:
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		// A notification may have removed this generation and a new request replaced it.
		if s.pending[key] == pending {
			pending.waiters--
			if pending.waiters == 0 {
				delete(s.pending, key)
			}
		}
		s.mu.Unlock()
		return ctx.Err()
	}
}

// Notifications invalidate pending checks; they do not assert that a policy is ready.
func (s *XDSStore) notifyPendingLocked(key model.ResourceKey) {
	if pending := s.pending[key]; pending != nil {
		delete(s.pending, key)
		close(pending.changed)
	}
}
