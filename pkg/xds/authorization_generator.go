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
	"fmt"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// AuthorizationGenerator projects global, namespace, and workload-selector
// authorizations from the authenticated client's scoped workloads.
type AuthorizationGenerator struct{}

func (AuthorizationGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.WorkloadAuthorizationType {
		return GeneratedDelta{}, fmt.Errorf("authorization generator does not support type URL %q", request.TypeURL)
	}
	if !request.Full && !request.Update.FullFor(model.WorkloadAuthorizationType) {
		return generateAuthorizationIncremental(request), nil
	}
	selected := make(map[string]model.Resource)
	for _, resource := range selectAuthorizationResources(request.Scope, request.Snapshot, selectionNames(request.Subscription)) {
		selected[resource.XDSName] = resource
	}
	return diffSelected(request.Subscription, selected), nil
}

func selectAuthorizationResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	names []string,
) []model.Resource {
	visibility := newAuthorizationVisibility(scope, snapshot)
	if !visibility.hasWorkloads {
		return nil
	}
	selected := snapshot.ListGlobalAuthorizations()
	for namespace := range visibility.namespaces {
		selected = append(selected, snapshot.ListNamespaceAuthorizations(namespace)...)
	}
	for policyName := range visibility.policyNames {
		selected = append(selected, snapshot.Lookup(model.WorkloadAuthorizationType, policyName)...)
	}
	selected = orderedUnique(selected)
	if names == nil {
		return selected
	}
	allowed := resourceKeySet(selected)
	result := make([]model.Resource, 0, len(names))
	for _, name := range names {
		for _, resource := range snapshot.Lookup(model.WorkloadAuthorizationType, name) {
			if allowed.Contains(resource.Key) {
				result = append(result, resource)
			}
		}
	}
	return orderedUnique(result)
}

// Gateways see compatibility Authorization references cluster-wide; other clients
// are restricted to their authenticated workload or node scope.
func authorizationWorkloadQuery(scope model.ClientScope) (model.WorkloadQuery, bool) {
	if scope.Class == model.ClientEgressGateway {
		return model.WorkloadQuery{AuthorizationRefsOnly: true}, true
	}
	query, ok := workloadScopeQuery(&scope)
	return query, ok
}

func workloadAuthorizationNames(resources []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, resource := range resources {
		if resource.Facts.Workload == nil {
			continue
		}
		for _, name := range resource.Facts.Workload.AuthorizationRefs {
			result.Insert(name)
		}
	}
	return result
}

func workloadNamespaces(resources []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, resource := range resources {
		if resource.Facts.Workload == nil {
			continue
		}
		result.Insert(resource.Facts.Workload.Namespace)
	}
	return result
}

func generateAuthorizationIncremental(request GenerationRequest) GeneratedDelta {
	return generateIncremental(request, func(resource model.Resource) bool {
		return request.Subscription.allows(resource) &&
			authorizationVisibleForScope(request.Scope, request.Snapshot, resource)
	}, nil, nil)
}
