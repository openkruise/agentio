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

package trafficpolicy

import (
	"context"
	"errors"
	"fmt"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/model"
)

// NamedPolicy preserves the resource name and binding order for compilation.
type NamedPolicy struct {
	Name   string
	Policy *sec.TrafficPolicy
}

// Resources is the request-side store contract; backend transport is not exposed.
type Resources interface {
	Snapshot() *store.Snapshot
	SnapshotFor([]store.Key) *store.Snapshot
	Acquire(context.Context, store.Key) (*store.Resource, func(), error)
}

type policySnapshot struct {
	Workload        *workload.Workload
	TrafficPolicies []NamedPolicy
	entry           *indexedWorkload
}

func workloadKey(source Resources, subj subject.Subject) (store.Key, error) {
	view := source.Snapshot()
	if !view.Ready() {
		return store.Key{}, fmt.Errorf("resource store is not synchronized")
	}
	if subj.Workload.UID != "" {
		return store.Key{Type: store.Workload, Name: subj.Workload.UID}, nil
	}
	resources, err := view.ResourcesFor(store.Workload, subj)
	if missing, ok := errors.AsType[*store.MissingResource](err); ok {
		return missing.Key, nil
	}
	if err != nil {
		return store.Key{}, err
	}
	return resources[0].Key, nil
}

// Hold the Workload and all referenced policies until the compiled view is read,
// even when one request's dependency set exceeds the cache capacity.
func lookup(ctx context.Context, source Resources, subj subject.Subject) (policySnapshot, error) {
	key, err := workloadKey(source, subj)
	if err != nil {
		return policySnapshot{}, err
	}
	held := map[store.Key]bool{}
	var keys []store.Key
	var currentWorkload *store.Resource
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	acquire := func(key store.Key) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		resource, release, err := source.Acquire(ctx, key)
		if release != nil {
			releases = append(releases, release)
		}
		if err != nil {
			return err
		}
		if resource == nil {
			return &store.MissingResource{Key: key}
		}
		held[key] = true
		keys = append(keys, key)
		if key.Type == store.Workload {
			currentWorkload = resource
		}
		return nil
	}
	if err := acquire(key); err != nil {
		return policySnapshot{}, err
	}
	// Hot dependency sets need only one selected snapshot after all leases are pinned.
	previous := source.Snapshot().Query(store.Workload).(*queryIndex).byUID[key.Name]
	if previous != nil && previous.workload.Value == currentWorkload.Value {
		for _, dependency := range previous.dependencies {
			if err := acquire(dependency.Key); err != nil {
				return policySnapshot{}, err
			}
		}
	}
	for {
		view := source.SnapshotFor(keys)
		result, err := lookupWorkload(view, key, source.Snapshot().Query(store.Workload).(*queryIndex).byUID[key.Name])
		if missing, ok := errors.AsType[*store.MissingResource](err); ok && !held[missing.Key] {
			if err := acquire(missing.Key); err != nil {
				return policySnapshot{}, err
			}
			continue
		}
		if err != nil {
			return policySnapshot{}, err
		}
		refreshed := false
		for _, dependency := range result.entry.dependencies {
			if !held[dependency.Key] {
				if err := acquire(dependency.Key); err != nil {
					return policySnapshot{}, err
				}
				refreshed = true
			}
		}
		if !refreshed {
			return result, nil
		}
	}
}

func lookupWorkload(view *store.Snapshot, key store.Key, previous *indexedWorkload) (policySnapshot, error) {
	if !view.Ready() {
		return policySnapshot{}, fmt.Errorf("egress resources are not synchronized")
	}
	resource, err := view.Get(key)
	if err != nil {
		return policySnapshot{}, err
	}
	if resource == nil {
		return policySnapshot{}, &store.MissingResource{Key: key}
	}
	entry := buildWorkload(view, resource, previous)
	if entry.err != nil {
		return policySnapshot{}, entry.err
	}
	return policySnapshot{Workload: resource.Value.(*workload.Workload), TrafficPolicies: entry.named, entry: entry}, nil
}

func references(w *workload.Workload) ([]string, error) {
	var found *ext.PolicyReference
	for _, e := range w.Extensions {
		if e.Name != "traffic-policy-reference" {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("duplicate TrafficPolicy reference")
		}
		found = &ext.PolicyReference{}
		if e.Config == nil {
			return nil, fmt.Errorf("missing TrafficPolicy reference payload")
		}
		if err := e.Config.UnmarshalTo(found); err != nil {
			return nil, err
		}
		if found.TypeUrl != model.TrafficPolicyType {
			return nil, fmt.Errorf("unexpected TrafficPolicy reference type %q", found.TypeUrl)
		}
	}
	if found == nil {
		return nil, fmt.Errorf("native TrafficPolicy binding missing")
	}
	seen := map[string]bool{}
	for _, name := range found.ResourceNames {
		if name == "" || seen[name] {
			return nil, fmt.Errorf("invalid TrafficPolicy reference %q", name)
		}
		seen[name] = true
	}
	return found.ResourceNames, nil
}
