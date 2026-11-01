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
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// WorkloadGenerator serves networking state and independently matched Workload policies.
type WorkloadGenerator struct{}

func (g WorkloadGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.AddressType && request.TypeURL != model.WorkloadType {
		return GeneratedDelta{}, fmt.Errorf("workload generator does not support type URL %q", request.TypeURL)
	}
	if request.TypeURL == model.WorkloadType {
		return g.generateDirectWorkloads(request)
	}
	if request.Full {
		resources := selectWorkloadResources(
			request.Scope, request.Snapshot, request.TypeURL, selectionNames(request.Subscription),
		)
		if request.Subscription.Wildcard() && len(request.Subscription.sent) == 0 &&
			(request.Scope.Class == model.ClientDedicatedZTunnel || request.Scope.Class == model.ClientSharedZTunnel) {
			return GeneratedDelta{
				Resources:      collapseSortedXDSNames(resources),
				Removed:        generateWDSIncremental(request, false).Removed,
				elideSentState: true,
			}, nil
		}
		selected := make(map[string]model.Resource)
		for _, resource := range resources {
			selected[resource.XDSName] = resource
		}
		delta := diffSelected(request.Subscription, selected)
		delta.elideSentState = request.Subscription.Wildcard()
		if delta.elideSentState {
			delta.Removed = sets.SortedList(
				sets.New(delta.Removed...).Merge(sets.New(generateWDSIncremental(request, false).Removed...)),
			)
		}
		return delta, nil
	}
	return generateWDSIncremental(request, false), nil
}

func (g WorkloadGenerator) generateDirectWorkloads(request GenerationRequest) (GeneratedDelta, error) {
	sourceRequest := request
	sourceRequest.TypeURL = model.WorkloadType
	// Direct Workloads keep per-connection sent state even for wildcard
	// watches: only egress gateways consume them, and sent versions are what
	// let a full regeneration send a diff instead of retransmitting the entire set.
	projectDelta := func(delta GeneratedDelta) (GeneratedDelta, error) {
		projected, err := g.projectAddresses(delta.Resources)
		if err != nil {
			return GeneratedDelta{}, err
		}
		delta.Resources = unsentResources(request.Subscription, projected)
		delta.elideSentState = false
		return delta, nil
	}
	if request.Full || request.Update.FullFor(model.WorkloadType) {
		addresses := selectWorkloadResources(
			request.Scope, request.Snapshot, model.AddressType, selectionNames(request.Subscription))
		projected, err := g.projectAddresses(addresses)
		if err != nil {
			return GeneratedDelta{}, err
		}
		selected := make(map[string]model.Resource, len(projected))
		for _, resource := range projected {
			selected[resource.XDSName] = resource
		}
		return diffDemandWorkloads(request, selected), nil
	}
	return projectDelta(generateWDSIncremental(sourceRequest, true))
}

// diffDemandWorkloads also resends explicitly requested Workloads after client
// eviction. Workload subscriptions are gateway-only; resolve names and Service
// members through the indexes, then reuse the already selected projections.
func diffDemandWorkloads(request GenerationRequest, selected map[string]model.Resource) GeneratedDelta {
	if len(request.SubscribedNames) == 0 {
		return diffSelected(request.Subscription, selected)
	}
	resend := sets.New[string]()
	var missing []string
	markRequested := func(name string) bool {
		resource, found := selected[name]
		if !found {
			return false
		}
		if version, sent := request.Subscription.SentVersion(name); sent && version == resource.Hash {
			resend.Insert(name)
		}
		return true
	}
	for _, name := range request.SubscribedNames {
		if name == "*" {
			continue
		}
		found := false
		for _, address := range request.Snapshot.Lookup(model.AddressType, name) {
			if address.IsWorkloadAddress() && markRequested(address.XDSName) {
				found = true
			}
			if service := address.Facts.Service; service != nil {
				for _, member := range request.Snapshot.ListServiceMembers(model.AddressType, service.ServiceKey) {
					if member.IsWorkloadAddress() && markRequested(member.XDSName) {
						found = true
					}
				}
			}
		}
		if !found {
			missing = append(missing, name)
		}
	}
	delta := diffResourceSelection(selected, request.Subscription.SentNames(), func(name string) (string, bool) {
		version, sent := request.Subscription.SentVersion(name)
		return version, sent && !resend.Contains(name)
	})
	if len(missing) > 0 {
		delta.Removed = append(delta.Removed, missing...)
		slices.Sort(delta.Removed)
		delta.Removed = slices.Compact(delta.Removed)
	}
	return delta
}

func (g WorkloadGenerator) projectAddresses(addresses []model.Resource) ([]model.Resource, error) {
	result := make([]model.Resource, 0, len(addresses))
	for _, addressResource := range addresses {
		address := &workloadv1.Address{}
		if err := addressResource.Value.UnmarshalTo(address); err != nil {
			return nil, fmt.Errorf("decode Address %s: %w", addressResource.Key.Name, err)
		}
		workload := address.GetWorkload()
		if workload == nil {
			continue
		}
		// Deterministic marshaling keeps the projected hash stable across
		// regenerations; the default marshal randomizes map-field order and
		// would resend every workload on each full diff.
		value := new(anypb.Any)
		if err := anypb.MarshalFrom(value, workload, proto.MarshalOptions{Deterministic: true}); err != nil {
			return nil, fmt.Errorf("marshal direct Workload %s: %w", addressResource.Key.Name, err)
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.WorkloadType, Name: addressResource.Key.Name},
			addressResource.XDSName, value, addressResource.Aliases, addressResource.Facts)
		if err != nil {
			return nil, err
		}
		result = append(result, resource)
	}
	return result, nil
}

func selectWorkloadResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	typeURL string,
	names []string,
) []model.Resource {
	selection := newAddressSelection(scope, snapshot, typeURL, SubscriptionView{
		wildcard: names == nil,
		names:    names,
	})
	return selection.list()
}

func serviceKeysForNames(snapshot model.ResourceSet, names []string) sets.Set[string] {
	serviceKeys := sets.New[string]()
	if names == nil {
		return serviceKeys
	}
	for _, name := range names {
		for _, resource := range snapshot.Lookup(model.AddressType, name) {
			if resource.Facts.Service != nil {
				serviceKeys.Insert(resource.Facts.Service.ServiceKey)
			}
		}
	}
	return serviceKeys
}

func workloadMatchesScope(scope model.ClientScope, resource model.Resource) bool {
	query, found := workloadScopeQuery(&scope)
	return found && query.Matches(resource.Facts.Workload)
}

func scopedWorkloads(scope model.ClientScope, snapshot model.ResourceSet, typeURL string) []model.Resource {
	query, found := workloadScopeQuery(&scope)
	if !found {
		return nil
	}
	return snapshot.ListWorkloads(typeURL, query)
}

func workloadScopeQuery(scope *model.ClientScope) (model.WorkloadQuery, bool) {
	switch scope.Class {
	case model.ClientDedicatedZTunnel:
		if scope.WorkloadUID != "" && scope.Source.Validate() == nil {
			return model.WorkloadQuery{
				WorkloadUID: scope.WorkloadUID,
				Source:      scope.Source,
				Principal:   &scope.Principal,
			}, true
		}
		return model.WorkloadQuery{}, false
	case model.ClientSharedZTunnel:
		return model.WorkloadQuery{NodeName: scope.NodeName}, true
	default:
		return model.WorkloadQuery{}, false
	}
}

func selectedServices(snapshot model.ResourceSet, serviceKeys sets.Set[string]) []model.Resource {
	result := make([]model.Resource, 0, len(serviceKeys))
	for serviceKey := range serviceKeys {
		for _, resource := range snapshot.Lookup(model.AddressType, serviceKey) {
			if resource.Facts.Service != nil && resource.Facts.Service.ServiceKey == serviceKey {
				result = append(result, resource)
			}
		}
	}
	return result
}

func gatewayReferenceKeys(resources []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, resource := range resources {
		if resource.Facts.Workload == nil {
			continue
		}
		for _, key := range resource.Facts.Workload.GatewayReferences {
			result.Insert(key)
		}
	}
	return result
}

func workloadServiceKeys(resources []model.Resource) sets.Set[string] {
	result := sets.New[string]()
	for _, resource := range resources {
		if resource.Facts.Workload == nil {
			continue
		}
		for _, key := range resource.Facts.Workload.ServiceKeys {
			result.Insert(key)
		}
	}
	return result
}

func gatewayResourcesForKeys(
	snapshot model.ResourceSet,
	typeURL string,
	keys sets.Set[string],
) []model.Resource {
	result := make([]model.Resource, 0, len(keys))
	for key := range keys {
		result = append(result, snapshot.ListResourcesOwnedByGateway(typeURL, key)...)
	}
	return orderedUnique(result)
}

// generateWDSIncremental reselects affected addresses from the current snapshot.
// Wildcard Address removals use historical visibility metadata rather than a
// per-connection sent table; payloads always come from the current snapshot.
func generateWDSIncremental(request GenerationRequest, workloadsOnly bool) GeneratedDelta {
	selection := newAddressSelection(request.Scope, request.Snapshot, model.AddressType, request.Subscription)
	visible := func(resource model.Resource) bool {
		return (!workloadsOnly || resource.IsWorkloadAddress()) && selection.selected(resource)
	}
	var previouslyVisible func(*xdsstore.Identity) bool
	elide := request.Subscription.Wildcard() && !workloadsOnly
	if elide {
		previouslyVisible = func(identity *xdsstore.Identity) bool {
			resource := model.Resource{XDSName: identity.Name, Facts: identity.Facts}
			if selection.visible(resource) {
				return true
			}
			for workload := range identity.Workloads {
				facts := &model.WorkloadResourceFacts{
					WorkloadUID: workload.UID,
					Source:      workload.Source,
					Principal:   workload.Principal,
					NodeName:    workload.NodeName,
				}
				if workloadMatchesScope(request.Scope, model.Resource{Facts: model.ResourceFacts{Workload: facts}}) {
					return true
				}
			}
			return false
		}
	}
	delta := generateIncremental(request, visible, previouslyVisible, nil)
	delta.elideSentState = elide
	return delta
}

func serviceResourcesForKey(snapshot model.ResourceSet, serviceKey string) []model.Resource {
	result := make([]model.Resource, 0, 1)
	for _, resource := range snapshot.Lookup(model.AddressType, serviceKey) {
		if resource.Facts.Service != nil && resource.Facts.Service.ServiceKey == serviceKey {
			result = append(result, resource)
		}
	}
	return result
}
