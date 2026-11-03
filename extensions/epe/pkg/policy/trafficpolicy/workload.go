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
	"fmt"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/model"
)

// NewWorkloadResolver shares the Workload index without demanding TrafficPolicies.
func NewWorkloadResolver(source Resources) subject.WorkloadResolver {
	return func(ctx context.Context, identity subject.Workload) (subject.Workload, error) {
		subj := subject.Subject{Workload: identity}
		key, err := workloadKey(source, subj)
		if err != nil {
			return identity, err
		}
		resource, release, err := source.Acquire(ctx, key)
		if release != nil {
			defer release()
		}
		if err != nil {
			return identity, err
		}
		if resource == nil {
			return identity, &store.MissingResource{Key: key}
		}
		view := source.SnapshotFor([]store.Key{key})
		if !view.Ready() {
			return identity, fmt.Errorf("workload resources are not synchronized")
		}
		resource, err = view.Get(key)
		if err != nil {
			return identity, err
		}
		if resource == nil {
			return identity, &store.MissingResource{Key: key}
		}
		var binding subject.Workload
		prior := source.Snapshot().Query(store.Workload).(*queryIndex).byUID[key.Name]
		if prior != nil && prior.workload.Value == resource.Value {
			binding, err = prior.binding, prior.bindingErr
		} else {
			binding, err = workloadBinding(resource.Value.(*workload.Workload))
		}
		if err != nil {
			return identity, err
		}
		identity.UID, identity.Name, identity.Namespace = binding.UID, binding.Name, binding.Namespace
		identity.Labels, identity.SecurityProfileReferences = binding.Labels, binding.SecurityProfileReferences
		return identity, nil
	}
}

func workloadBinding(w *workload.Workload) (subject.Workload, error) {
	identity := subject.Workload{UID: w.Uid, Name: w.Name, Namespace: w.Namespace}
	var binding *ext.PolicyReference
	var metadata *ext.WorkloadMetadata
	for _, extension := range w.Extensions {
		switch extension.Name {
		case "security-profile-reference":
			if binding != nil || extension.Config == nil {
				return identity, fmt.Errorf("invalid SecurityProfile reference for %s", identity.String())
			}
			binding = &ext.PolicyReference{}
			if err := extension.Config.UnmarshalTo(binding); err != nil {
				return identity, err
			}
		case "workload-metadata":
			if metadata != nil || extension.Config == nil {
				return identity, fmt.Errorf("invalid workload-metadata for %s", identity.String())
			}
			metadata = &ext.WorkloadMetadata{}
			if err := extension.Config.UnmarshalTo(metadata); err != nil {
				return identity, err
			}
		}
	}
	if binding == nil || binding.TypeUrl != model.SecurityProfileType {
		return identity, fmt.Errorf("SecurityProfile binding missing or invalid for %s", identity.String())
	}
	identity.SecurityProfileReferences = append([]string{}, binding.ResourceNames...)
	if metadata != nil {
		identity.Labels = metadata.Labels
	}
	return identity, nil
}
