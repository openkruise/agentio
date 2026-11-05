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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
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
	if subj.Workload.UID != "" {
		return store.Key{Type: store.Workload, Name: subj.Workload.UID}, nil
	}
	view := source.Snapshot()
	if !view.Ready() {
		index := view.Query(store.Workload).(*queryIndex)
		uid := podsource.WorkloadUID(index.clusterID, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: subj.Workload.Namespace, Name: subj.Workload.Name},
		})
		return store.Key{Type: store.Workload, Name: uid}, nil
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

// lookupBinding captures Workload metadata without resolving TrafficPolicy dependencies.
func lookupBinding(ctx context.Context, source Resources, subj subject.Subject) (subject.Workload, error) {
	key, err := workloadKey(source, subj)
	if err != nil {
		return subject.Workload{}, err
	}
	resource, release, err := source.Acquire(ctx, key)
	if release != nil {
		defer release()
	}
	if err != nil {
		return subject.Workload{}, err
	}
	if resource == nil {
		return subject.Workload{}, &store.MissingResource{Key: key}
	}
	view := source.SnapshotFor([]store.Key{key})
	if !view.Ready() {
		return subject.Workload{}, fmt.Errorf("workload resources are not synchronized")
	}
	resource, err = view.Get(key)
	if err != nil {
		return subject.Workload{}, err
	}
	if resource == nil {
		return subject.Workload{}, &store.MissingResource{Key: key}
	}
	previous := source.Snapshot().Query(store.Workload).(*queryIndex).byUID[key.Name]
	if previous != nil && previous.workload.Value == resource.Value {
		return previous.binding, previous.bindingErr
	}
	return workloadBinding(resource.Value.(*workload.Workload))
}

// Build one complete immutable snapshot before any request policy executes.
//
//nolint:gocyclo // Keep lease ownership and snapshot retries in one scope.
func lookup(ctx context.Context, source Resources, subj subject.Subject) (policySnapshot, error) {
	key, err := workloadKey(source, subj)
	if err != nil {
		return policySnapshot{}, err
	}
	acquired := map[store.Key]error{}
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return policySnapshot{}, err
		}
		candidate, release, err := source.Acquire(ctx, key)
		if release != nil {
			releases = append(releases, release)
		}
		if err != nil {
			return policySnapshot{}, err
		}
		if candidate == nil {
			return policySnapshot{}, &store.MissingResource{Key: key}
		}
		previous := source.Snapshot().Query(store.Workload).(*queryIndex).byUID[key.Name]
		keys := []store.Key{key}
		if previous != nil && previous.workload.Value == candidate.Value && previous.err == nil {
			for _, dependency := range previous.dependencies {
				keys = append(keys, dependency.Key)
			}
		} else {
			names, err := references(candidate.Value.(*workload.Workload))
			if err != nil {
				return policySnapshot{}, err
			}
			for _, name := range names {
				keys = append(keys, store.Key{Type: store.TrafficPolicy, Name: name})
			}
		}
		for _, dependency := range keys[1:] {
			if err := ctx.Err(); err != nil {
				return policySnapshot{}, err
			}
			if _, attempted := acquired[dependency]; attempted {
				continue
			}
			resource, release, err := source.Acquire(ctx, dependency)
			if release != nil {
				releases = append(releases, release)
			}
			if err == nil && resource == nil {
				err = &store.MissingResource{Key: dependency}
			}
			acquired[dependency] = err
		}
		if err := ctx.Err(); err != nil {
			return policySnapshot{}, err
		}
		view := source.SnapshotFor(keys)
		current, err := view.Get(key)
		if err != nil {
			return policySnapshot{}, err
		}
		// A changed Workload invalidates the entire candidate, including metadata.
		if current == nil || current.Value != candidate.Value {
			continue
		}
		for _, dependency := range keys[1:] {
			if err := acquired[dependency]; err != nil {
				return policySnapshot{}, err
			}
		}
		return lookupWorkload(view, key, previous)
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
	return policySnapshot{
		Workload:        resource.Value.(*workload.Workload),
		TrafficPolicies: entry.named,
		entry:           entry,
	}, nil
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
	names := make([]string, 0, len(found.Resources))
	for _, reference := range found.Resources {
		name := reference.GetName()
		if name == "" || seen[name] {
			return nil, fmt.Errorf("invalid TrafficPolicy reference %q", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}
