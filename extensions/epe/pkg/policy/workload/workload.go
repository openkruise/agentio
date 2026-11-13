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
	"fmt"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/model"
)

// NewContextResolver pins Workload metadata before profile selection and filters run.
func NewContextResolver(source Resources) filter.ContextResolver {
	return func(ctx context.Context, request filter.RequestContext) (filter.RequestContext, error) {
		binding, err := lookupBinding(ctx, source, request.Caller.Subject)
		if err != nil {
			return request, err
		}
		identity := &request.Caller.Subject.Workload
		identity.UID, identity.Name, identity.Namespace = binding.UID, binding.Name, binding.Namespace
		identity.Labels, identity.SecurityProfileReferences = binding.Labels, binding.SecurityProfileReferences
		return request, nil
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
	identity.SecurityProfileReferences = make([]string, 0, len(binding.Resources))
	seen := map[string]bool{}
	for _, reference := range binding.Resources {
		if reference.GetName() == "" {
			return identity, fmt.Errorf("empty SecurityProfile reference")
		}
		if seen[reference.Name] {
			return identity, fmt.Errorf("duplicate SecurityProfile reference %q", reference.Name)
		}
		identity.SecurityProfileReferences = append(identity.SecurityProfileReferences, reference.GetName())
		seen[reference.Name] = true
	}
	if metadata != nil {
		identity.Labels = metadata.Labels
	}
	return identity, nil
}
