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
	"sort"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// selectGeneric returns scope-allowed resources of any generic xDS type, by name or in full.
func selectGeneric(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	typeURL string,
	names []string,
) []model.Resource {
	owned := snapshot.ListResourcesOwnedByGateway(typeURL, scope.GatewayKey)
	if names == nil {
		return filterScope(scope, owned)
	}
	requested := sets.New(names...)
	candidates := owned[:0]
	for _, resource := range owned {
		if resourceNamesMatch(resource, requested.Contains) {
			candidates = append(candidates, resource)
		}
	}
	return filterScope(scope, candidates)
}

func filterScope(scope model.ClientScope, resources []model.Resource) []model.Resource {
	result := make([]model.Resource, 0, len(resources))
	for _, resource := range resources {
		if scopeAllows(scope, resource) {
			result = append(result, resource)
		}
	}
	return orderedUnique(result)
}

func resourceKeySet(resources []model.Resource) sets.Set[model.ResourceKey] {
	result := sets.NewWithLength[model.ResourceKey](len(resources))
	for _, resource := range resources {
		result.Insert(resource.Key)
	}
	return result
}

func orderedUnique(resources []model.Resource) []model.Resource {
	// Store small slice positions in the map because Resource values are large enough to be allocated indirectly.
	positions := make(map[model.ResourceKey]int, len(resources))
	result := make([]model.Resource, 0, len(resources))
	for _, resource := range resources {
		if position, found := positions[resource.Key]; found {
			result[position] = resource
			continue
		}
		positions[resource.Key] = len(result)
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].XDSName != result[j].XDSName {
			return result[i].XDSName < result[j].XDSName
		}
		return result[i].Key.Name < result[j].Key.Name
	})
	return result
}
