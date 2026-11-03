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
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

type subjectKey struct {
	namespace string
	name      string
}
type compiledConfig struct {
	config egressauthz.Config
	err    error
}
type indexedWorkload struct {
	binding           subject.Workload
	bindingErr        error
	workload          *store.Resource
	workloadResources []store.Resource
	dependencies      []*store.Resource
	policies          []store.Resource
	named             []NamedPolicy
	compiled          compiledConfig
	err               error
}
type queryIndex struct {
	clusterID string
	workloads map[subjectKey]*indexedWorkload
	byUID     map[string]*indexedWorkload
	err       error
}

// RegisterQueries adds Workload identity and ordered TrafficPolicy queries.
// Matching, dependency resolution and compilation stay outside the generic store.
func RegisterQueries(aggregate *store.Aggregate, clusterID string) {
	types := []store.Type{store.Workload, store.TrafficPolicy}
	builder := queryBuilder{clusterID: clusterID}
	aggregate.RegisterQueries(types, types, builder.build)
}

type queryBuilder struct{ clusterID string }

func (b queryBuilder) build(view *store.Snapshot, previous store.Query) store.Query {
	index := &queryIndex{clusterID: b.clusterID}
	resources, err := view.List(store.Workload)
	if err != nil {
		index.err = err
		return index
	}
	index.workloads = make(map[subjectKey]*indexedWorkload, len(resources))
	index.byUID = make(map[string]*indexedWorkload, len(resources))
	old, _ := previous.(*queryIndex)
	for _, resource := range resources {
		w := resource.Value.(*workload.Workload)
		key := subjectKey{w.Namespace, w.Name}
		canonical, err := view.Get(resource.Key)
		if err != nil {
			index.err = err
			return index
		}
		var prior *indexedWorkload
		if old != nil {
			prior = old.byUID[resource.Key.Name]
		}
		entry := buildWorkload(view, canonical, prior)
		index.byUID[resource.Key.Name] = entry
		if _, found := index.workloads[key]; found {
			index.workloads[key] = &indexedWorkload{
				err: fmt.Errorf("ambiguous source Workload %s/%s", w.Namespace, w.Name),
			}
		} else {
			index.workloads[key] = entry
		}
	}
	return index
}

func buildWorkload(view *store.Snapshot, resource *store.Resource, previous *indexedWorkload) *indexedWorkload {
	if previous != nil && previous.workload.Value == resource.Value {
		unchanged := previous.err == nil
		if missing, ok := errors.AsType[*store.MissingResource](previous.err); ok {
			current, err := view.Get(missing.Key)
			unchanged = err == nil && current == nil
		}
		for _, dependency := range previous.dependencies {
			current, err := view.Get(dependency.Key)
			if err != nil || current == nil || current.Value != dependency.Value {
				unchanged = false
				break
			}
		}
		if unchanged {
			return previous
		}
	}
	w := resource.Value.(*workload.Workload)
	entry := &indexedWorkload{workload: resource, workloadResources: []store.Resource{*resource}}
	if previous != nil && previous.workload.Value == resource.Value {
		entry.binding, entry.bindingErr = previous.binding, previous.bindingErr
	} else {
		entry.binding, entry.bindingErr = workloadBinding(w)
	}
	refs, err := references(w)
	if err != nil {
		entry.err = err
		return entry
	}
	for _, name := range refs {
		key := store.Key{Type: store.TrafficPolicy, Name: name}
		policy, err := view.Get(key)
		if err != nil {
			entry.err = err
			return entry
		}
		if policy == nil {
			entry.err = &store.MissingResource{Key: key}
			return entry
		}
		entry.dependencies = append(entry.dependencies, policy)
	}

	for _, policy := range entry.dependencies {
		entry.policies = append(entry.policies, *policy)
		entry.named = append(entry.named, NamedPolicy{Name: policy.Key.Name, Policy: policy.Value.(*sec.TrafficPolicy)})
	}
	config, err := Compile(entry.named)
	entry.compiled = compiledConfig{config: config, err: err}
	return entry
}

func (i *queryIndex) forSubject(subject subject.Subject) (*indexedWorkload, error) {
	if i.err != nil {
		return nil, i.err
	}
	if !subject.Workload.HasIdentity() {
		return nil, fmt.Errorf("traffic policy lookup requires workload identity")
	}
	if subject.Workload.UID != "" {
		entry := i.byUID[subject.Workload.UID]
		if entry == nil {
			return nil, &store.MissingResource{Key: store.Key{Type: store.Workload, Name: subject.Workload.UID}}
		}
		return entry, entry.err
	}
	entry := i.workloads[subjectKey{subject.Workload.Namespace, subject.Workload.Name}]
	if entry == nil {
		// Legacy requests supply Kubernetes namespace/name without a discovery UID.
		// Use the registry mapping to fetch their Workload resource.
		uid := podsource.WorkloadUID(i.clusterID, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: subject.Workload.Namespace, Name: subject.Workload.Name},
		})
		return nil, &store.MissingResource{Key: store.Key{Type: store.Workload, Name: uid}}
	}
	return entry, entry.err
}

func (i *queryIndex) ResourcesFor(typ store.Type, subject subject.Subject) ([]store.Resource, error) {
	entry, err := i.forSubject(subject)
	// Workload lookup does not depend on its TrafficPolicy bindings.
	if typ == store.Workload && entry != nil && entry.workload != nil {
		return entry.workloadResources, nil
	}
	if err != nil {
		return nil, err
	}
	return entry.policies, nil
}
