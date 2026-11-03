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
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/pkg/demandcache"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

// Watches starts named-only native discovery. Resources are subscribed on Fetch.
func Watches() []xdsclient.Watch {
	return []xdsclient.Watch{
		{
			TypeURL:        model.WorkloadType,
			ReconnectGrace: 5 * time.Second,
			OnDelete:       func(string) xdsclient.DeleteAction { return xdsclient.ReleaseSubscription },
			Transform: func(v *anypb.Any) (any, error) {
				w := &workload.Workload{}
				return w, v.UnmarshalTo(w)
			},
		},
		{
			TypeURL:        model.TrafficPolicyType,
			ReconnectGrace: 5 * time.Second,
			OnDelete:       func(string) xdsclient.DeleteAction { return xdsclient.ReleaseSubscription },
			Transform: func(v *anypb.Any) (any, error) {
				p := &sec.TrafficPolicy{}
				return p, v.UnmarshalTo(p)
			},
		},
	}
}

// Source is the Delta ADS client surface needed by this backend.
type Source interface {
	Snapshot() xdsclient.Snapshot
	Demand(context.Context, string, string) (*xdsclient.Resource, error)
	Observe(...string) (<-chan struct{}, bool)
}

// Store exposes native xDS resources through EPE's resource interface.
type Store struct {
	source    Source
	cache     *demandcache.Cache[*xdsclient.Resource]
	mu        sync.Mutex
	cached    xdsclient.Snapshot
	batch     store.Batch
	published xdsclient.Snapshot
}

var _ store.Store = (*Store)(nil)

// New wraps an xDS source; the caller owns its lifecycle.
func New(source Source) *Store { return &Store{source: source} }

type leaseSource struct{ client *xdsclient.Client }

func (s leaseSource) Acquire(typ, name string) (demandcache.Lease[*xdsclient.Resource], error) {
	return s.client.Acquire(typ, name)
}

// NewCached bounds the Workload and TrafficPolicy subscriptions in one cache.
func NewCached(source *xdsclient.Client, config demandcache.Config) (*Store, error) {
	cache, err := demandcache.New(leaseSource{source}, config)
	if err != nil {
		return nil, err
	}
	return &Store{source: source, cache: cache}, nil
}

// Run owns cache expiration and releases subscriptions on shutdown.
func (s *Store) Run(ctx context.Context) error { return s.cache.Run(ctx) }

// CacheEntries includes active resolutions and idle retained subscriptions.
func (s *Store) CacheEntries() int { return s.cache.Len() }

// Types lists the native models served by this backend.
func (s *Store) Types() []store.Type { return []store.Type{store.Workload, store.TrafficPolicy} }

// Status observes synchronization and changes without copying or decoding resources.
func (s *Store) Status() store.Status {
	changed, ready := s.source.Observe(model.WorkloadType, model.TrafficPolicyType)
	return store.Status{Ready: ready, Changed: changed}
}

// Keep one publication per update. Its immutable values were decoded once by
// the watch Transform and are shared with EPE's snapshots.
func (s *Store) snapshot() xdsclient.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Store) snapshotLocked() xdsclient.Snapshot {
	changed, _ := s.source.Observe(model.WorkloadType, model.TrafficPolicyType)
	if s.cached.Resources == nil || s.cached.Changed != changed {
		s.cached = s.source.Snapshot()
	}
	return s.cached
}

// Read adapts one consistent xDS publication on the aggregate update path.
func (s *Store) Read() store.Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.snapshotLocked()
	batch := store.Batch{
		Status:    store.Status{Ready: true, Changed: snapshot.Changed},
		Snapshots: map[store.Type]store.TypeSnapshot{},
	}
	for _, typ := range s.Types() {
		wire := wireType(typ)
		batch.Ready = batch.Ready && snapshot.Usable(wire)
		batch.Snapshots[typ] = projectType(snapshot, s.published, typ, s.batch.Snapshots[typ])
	}

	s.published, s.batch = snapshot, batch
	return batch
}

// ReadKeys captures a request's pinned resources without copying the entire cache.
func (s *Store) ReadKeys(keys []store.Key) store.Batch {
	var snapshot xdsclient.Snapshot
	if source, ok := s.source.(interface {
		SnapshotFor(map[string][]string) xdsclient.Snapshot
	}); ok {
		names := map[string][]string{}
		for _, key := range keys {
			wire := wireType(key.Type)
			names[wire] = append(names[wire], key.Name)
		}
		snapshot = source.SnapshotFor(names)
	} else {
		snapshot = s.source.Snapshot()
	}
	batch := store.Batch{Status: store.Status{Ready: true, Changed: snapshot.Changed}, Snapshots: map[store.Type]store.TypeSnapshot{}}
	for _, typ := range s.Types() {
		wire := wireType(typ)
		var resources []store.Resource
		var err error
		required := false
		for _, key := range keys {
			if key.Type == typ {
				required = true
				break
			}
		}
		if required && !snapshot.Usable(wire) {
			batch.Ready = false
			err = fmt.Errorf("%s xDS is not synchronized", typ)
		} else {
			for _, key := range keys {
				if key.Type == typ {
					if resource := toResource(key, snapshot.Resources[wire][key.Name]); resource != nil {
						resources = append(resources, *resource)
					}
				}
			}
		}
		batch.Snapshots[typ] = store.NewDefaultSnapshot(resources, err)
	}
	return batch
}

func projectType(snapshot, prior xdsclient.Snapshot, typ store.Type, previous store.TypeSnapshot) store.TypeSnapshot {
	wire := wireType(typ)
	if !snapshot.Usable(wire) {
		if previous != nil && !prior.Usable(wire) {
			return previous
		}
		return store.NewDefaultSnapshot(nil, fmt.Errorf("%s xDS is not synchronized", typ))
	}
	old, _ := previous.(*store.DefaultSnapshot)
	priorValues := prior.Resources[wire]
	if old == nil || !prior.Usable(wire) {
		old, priorValues = store.NewDefaultSnapshot(nil, nil), nil
	}
	var upserts []store.Resource
	for name, value := range snapshot.Resources[wire] {
		if priorValues[name] == value {
			continue
		}
		upserts = append(upserts, *toResource(store.Key{Type: typ, Name: name}, value))
	}
	var removed []string
	for name := range priorValues {
		if _, found := snapshot.Resources[wire][name]; !found {
			removed = append(removed, name)
		}
	}
	return old.WithChanges(upserts, removed)
}

// get retrieves a cached resource without initiating a network request.
func (s *Store) get(key store.Key) (*store.Resource, error) {
	typeURL := wireType(key.Type)
	if typeURL == "" {
		return nil, nil
	}
	snapshot := s.snapshot()
	if !snapshot.Usable(typeURL) {
		return nil, fmt.Errorf("%s xDS is not synchronized", key.Type)
	}
	return toResource(key, snapshot.Resources[typeURL][key.Name]), nil
}

// Fetch explicitly subscribes to a missing resource. Context bounds the wait.
func (s *Store) Fetch(ctx context.Context, key store.Key) (*store.Resource, error) {
	r, release, err := s.Acquire(ctx, key)
	if release != nil {
		release()
	}
	return r, err
}

// Acquire refreshes hot entries too; immutable aggregate snapshots must not
// bypass retention or serve resources whose subscriptions have been evicted.
func (s *Store) Acquire(ctx context.Context, key store.Key) (*store.Resource, func(), error) {
	typeURL := wireType(key.Type)
	if typeURL == "" {
		return nil, nil, nil
	}
	if s.cache != nil {
		value, release, err := s.cache.Get(ctx, typeURL, key.Name)
		if errors.Is(err, xdsclient.ErrNotFound) {
			return nil, release, nil
		}
		return toResource(key, value), release, err
	}
	resource, err := s.get(key)
	if err != nil || resource != nil {
		return resource, func() {}, err
	}
	value, err := s.source.Demand(ctx, typeURL, key.Name)
	if errors.Is(err, xdsclient.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return toResource(key, value), func() {}, nil
}

func wireType(typ store.Type) string {
	switch typ {
	case store.Workload:
		return model.WorkloadType
	case store.TrafficPolicy:
		return model.TrafficPolicyType
	default:
		return ""
	}
}

func toResource(key store.Key, value *xdsclient.Resource) *store.Resource {
	if value == nil {
		return nil
	}
	return &store.Resource{Key: key, Value: value.Value}
}
