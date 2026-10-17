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
	"slices"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// addressSelection evaluates both full and incremental Address selection against
// one immutable snapshot. Workload scope is also used for related Services and Gateways.
type addressSelection struct {
	resources    model.ResourceSet
	scope        model.ClientScope
	typeURL      string
	subscription SubscriptionView
	// Full named selection resolves subscribed Services once; incremental selection
	// only looks up Service references of changed candidates.
	serviceKeys sets.Set[string]
}

func newAddressSelection(
	scope model.ClientScope,
	resources model.ResourceSet,
	typeURL string,
	subscription SubscriptionView,
) addressSelection {
	return addressSelection{
		resources:    resources,
		scope:        scope,
		typeURL:      typeURL,
		subscription: subscription,
	}
}

func (v *addressSelection) hasScopedWorkload(references model.WorkloadQuery) bool {
	scope := v.scope
	query, found := workloadScopeQuery(&scope)
	if !found {
		return false
	}
	query.ServiceKey = references.ServiceKey
	query.GatewayReference = references.GatewayReference
	return v.resources.HasWorkload(v.typeURL, query)
}

func (v *addressSelection) visible(resource model.Resource) bool {
	if v.scope.Class == model.ClientEgressGateway || v.scope.Class == model.ClientAgentioEgress {
		return true
	}
	if resource.Facts.GatewayOwner != "" && v.hasScopedWorkload(model.WorkloadQuery{
		GatewayReference: resource.Facts.GatewayOwner,
	}) {
		return true
	}
	if resource.IsWorkloadAddress() {
		return v.matchesWorkload(resource)
	}
	if v.typeURL != model.AddressType {
		return false
	}
	return resource.Facts.Service != nil && v.hasScopedWorkload(model.WorkloadQuery{
		ServiceKey: resource.Facts.Service.ServiceKey,
	})
}

func (v *addressSelection) matchesWorkload(resource model.Resource) bool {
	query, found := workloadScopeQuery(&v.scope)
	return found && query.Matches(resource.Facts.Workload)
}

// selected applies implicit scope, explicit names and Service expansion equally
// to named full-generation candidates and changed incremental candidates.
func (v *addressSelection) selected(resource model.Resource) bool {
	if v.subscription.Wildcard() {
		return v.visible(resource)
	}
	scope := v.scope
	if scope.Class != model.ClientSharedZTunnel && len(v.subscription.names) == 0 {
		return false
	}
	if scope.Class != model.ClientEgressGateway && scope.Class != model.ClientAgentioEgress {
		if resource.Facts.GatewayOwner != "" && v.hasScopedWorkload(model.WorkloadQuery{
			GatewayReference: resource.Facts.GatewayOwner,
		}) {
			return true
		}
		if scope.Class == model.ClientSharedZTunnel && v.matchesWorkload(resource) {
			return true
		}
		if scope.Class == model.ClientDedicatedZTunnel && !v.visible(resource) {
			return false
		}
	}
	return v.selectedByNames(resource, func(name string) bool {
		return containsSorted(v.subscription.names, name)
	})
}

// selectedByNames shares explicit-name selection between immutable generator
// views and the live interests used synchronously during demand reconciliation.
func (v *addressSelection) selectedByNames(resource model.Resource, contains func(string) bool) bool {
	if resourceNamesMatch(resource, contains) {
		return true
	}
	if workload := resource.Facts.Workload; workload != nil {
		for _, key := range workload.ServiceKeys {
			if v.subscribesService(key, contains) {
				return true
			}
		}
	}
	return false
}

func (v *addressSelection) subscribesService(key string, contains func(string) bool) bool {
	if v.serviceKeys != nil {
		return v.serviceKeys.Contains(key)
	}
	for _, service := range serviceResourcesForKey(v.resources, key) {
		if resourceNamesMatch(service, contains) {
			return true
		}
	}
	return false
}

func resourceNamesMatch(resource model.Resource, contains func(string) bool) bool {
	if contains(resource.XDSName) {
		return true
	}
	return slices.ContainsFunc(resource.Aliases, contains) || contains(resource.Key.Name)
}

// list enumerates candidates through indexes before applying the same predicate
// as incremental generation. Named lookups never scan the entire snapshot.
func (v *addressSelection) list() []model.Resource {
	if v.subscription.Wildcard() &&
		(v.scope.Class == model.ClientEgressGateway || v.scope.Class == model.ClientAgentioEgress) {
		return v.resources.List(v.typeURL)
	}
	if !v.subscription.Wildcard() && len(v.subscription.names) == 0 && v.scope.Class != model.ClientSharedZTunnel {
		return nil
	}
	var candidates []model.Resource
	scope := v.scope
	if query, found := workloadScopeQuery(&scope); found {
		workloads := v.resources.ListWorkloads(v.typeURL, query)
		gateways := gatewayReferenceKeys(workloads)
		candidates = workloads
		candidates = append(candidates, gatewayResourcesForKeys(v.resources, v.typeURL, gateways)...)
		if v.subscription.Wildcard() && v.typeURL == model.AddressType {
			candidates = append(candidates, selectedServices(v.resources, workloadServiceKeys(workloads))...)
		}
	}
	// Wildcard candidates are exact indexed scope matches and their dependencies;
	// rechecking every Workload would repeat ListWorkloads' query predicates.
	if v.subscription.Wildcard() {
		return orderedUnique(candidates)
	}
	for _, name := range v.subscription.names {
		for _, resource := range v.resources.Lookup(v.typeURL, name) {
			if v.typeURL == model.AddressType || resource.IsWorkloadAddress() {
				candidates = append(candidates, resource)
			}
		}
	}
	v.serviceKeys = serviceKeysForNames(v.resources, v.subscription.names)
	for serviceKey := range v.serviceKeys {
		for _, resource := range v.resources.ListServiceMembers(v.typeURL, serviceKey) {
			if resource.IsWorkloadAddress() {
				candidates = append(candidates, resource)
			}
		}
	}
	selected := candidates[:0]
	for _, resource := range candidates {
		if v.selected(resource) {
			selected = append(selected, resource)
		}
	}
	return orderedUnique(selected)
}
