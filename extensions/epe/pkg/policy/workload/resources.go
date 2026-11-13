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

package workload

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// Resources is the request-side store contract; backend transport is not exposed.
type Resources interface {
	Snapshot() *store.Snapshot
	SnapshotFor([]store.Key) *store.Snapshot
	Acquire(context.Context, store.Key) (*store.Resource, func(), error)
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

// lookupBinding captures one Workload publication for profile selection and inputs.
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
