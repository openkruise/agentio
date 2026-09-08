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

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"istio.io/istio/pkg/util/sets"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// SandboxPolicyResolver resolves the complete SNI payload attached to a sandbox UID.
type SandboxPolicyResolver interface {
	SNIPolicy(string) *extensionsv1.SniTrafficPolicy
}

// WorkloadGenerator applies workload-discovery scope and on-demand projection
// for Address and Workload resources.
type WorkloadGenerator struct {
	policies SandboxPolicyResolver
}

func NewWorkloadGenerator(policies SandboxPolicyResolver) WorkloadGenerator {
	return WorkloadGenerator{policies: policies}
}

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
				elideSentState: true,
			}, nil
		}
		selected := make(map[string]model.Resource)
		for _, resource := range resources {
			selected[resource.XDSName] = resource
		}
		delta := diffSelected(request.Subscription, selected)
		delta.elideSentState = request.Subscription.Wildcard()
		return delta, nil
	}
	return generateWDSDirty(request, false), nil
}

// collapseSortedXDSNames preserves the full selection's deterministic
// last-key-wins behavior without rebuilding and sorting a second map.
func collapseSortedXDSNames(resources []model.Resource) []model.Resource {
	write := 0
	for read := range resources {
		if write > 0 && resources[write-1].XDSName == resources[read].XDSName {
			resources[write-1] = resources[read]
			continue
		}
		resources[write] = resources[read]
		write++
	}
	clear(resources[write:])
	return resources[:write]
}

func (g WorkloadGenerator) generateDirectWorkloads(request GenerationRequest) (GeneratedDelta, error) {
	sourceRequest := request
	sourceRequest.TypeURL = model.AddressType
	// Direct Workloads keep per-connection sent state even for wildcard
	// watches: only egress gateways consume them, and sent versions are what
	// let a full regeneration (policy-binding triggers) send a diff instead of
	// retransmitting the entire set.
	projectDelta := func(delta GeneratedDelta) (GeneratedDelta, error) {
		projected, err := g.projectAddresses(delta.Resources)
		if err != nil {
			return GeneratedDelta{}, err
		}
		delta.Resources = projected
		delta.elideSentState = false
		return delta, nil
	}
	if request.Full || request.Update.FullFor(model.WorkloadType) {
		selected := make(map[string]model.Resource)
		addresses := selectWorkloadResources(
			request.Scope, request.Snapshot, model.AddressType, selectionNames(request.Subscription))
		projected, err := g.projectAddresses(addresses)
		if err != nil {
			return GeneratedDelta{}, err
		}
		for _, resource := range projected {
			selected[resource.XDSName] = resource
		}
		return diffSelected(request.Subscription, selected), nil
	}
	return projectDelta(generateWDSDirty(sourceRequest, true))
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
		if sandboxUID := sandboxUIDForResource(addressResource); sandboxUID != "" && g.policies != nil {
			if payload := g.policies.SNIPolicy(sandboxUID); payload != nil {
				config := new(anypb.Any)
				if err := anypb.MarshalFrom(config, payload, proto.MarshalOptions{Deterministic: true}); err != nil {
					return nil, fmt.Errorf("marshal SNI policy for workload %s: %w", addressResource.Key.Name, err)
				}
				workload.Extensions = append(workload.Extensions, &workloadv1.Extension{Name: "sni-traffic-policy", Config: config})
			}
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

func sandboxUIDForResource(resource model.Resource) string {
	if resource.Facts.Workload != nil {
		return resource.Facts.Workload.SandboxUID
	}
	return ""
}

func selectWorkloadResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	typeURL string,
	names []string,
) []model.Resource {
	if scope.Class == model.ClientEgressGateway {
		if names == nil {
			return snapshot.List(typeURL)
		}
		selected := make([]model.Resource, 0, len(names))
		for _, name := range names {
			for _, resource := range snapshot.Lookup(typeURL, name) {
				if typeURL == model.AddressType || resource.IsWorkloadAddress() {
					selected = append(selected, resource)
				}
			}
		}
		for serviceKey := range serviceKeysForNames(snapshot, names) {
			for _, resource := range snapshot.ListServiceMembers(typeURL, serviceKey) {
				if resource.IsWorkloadAddress() {
					selected = append(selected, resource)
				}
			}
		}
		return orderedUnique(selected)
	}

	workloads := scopedWorkloads(scope, snapshot, typeURL)
	referencedGateways := gatewayReferenceKeys(workloads)
	withGateways := func(selected []model.Resource) []model.Resource {
		selected = append(selected, gatewayResourcesForKeys(snapshot, typeURL, referencedGateways)...)
		return orderedUnique(selected)
	}
	allowedWorkloads := resourceKeySet(workloads)
	serviceKeys := workloadServiceKeys(workloads)
	if names == nil {
		// The workload slice is private to this selection, so related resources can reuse its backing array.
		selected := workloads
		if typeURL == model.AddressType {
			selected = append(selected, selectedServices(snapshot, serviceKeys)...)
		}
		return withGateways(selected)
	}
	if len(names) == 0 {
		if scope.Class == model.ClientSharedZTunnel {
			return withGateways(workloads)
		}
		return nil
	}

	selected := make([]model.Resource, 0, len(names))
	if scope.Class == model.ClientSharedZTunnel {
		// Node-local workloads stay implicit; explicit workload and Service/VIP
		// lookups are not node-filtered.
		selected = append(selected, workloads...)
		selectedServiceKeys := serviceKeysForNames(snapshot, names)
		for _, name := range names {
			for _, candidate := range snapshot.Lookup(typeURL, name) {
				if candidate.IsWorkloadAddress() {
					selected = append(selected, candidate)
					continue
				}
				if typeURL != model.AddressType {
					continue
				}
				if candidate.Facts.Service != nil {
					selected = append(selected, candidate)
					selectedServiceKeys.Insert(candidate.Facts.Service.ServiceKey)
				}
			}
		}
		for serviceKey := range selectedServiceKeys {
			for _, endpoint := range snapshot.ListServiceMembers(typeURL, serviceKey) {
				if endpoint.IsWorkloadAddress() {
					selected = append(selected, endpoint)
				}
			}
		}
		return withGateways(selected)
	}
	selectedServiceKeys := sets.New[string]()
	for _, name := range names {
		for _, candidate := range snapshot.Lookup(typeURL, name) {
			switch {
			case candidate.IsWorkloadAddress():
				if scope.Class != model.ClientSharedZTunnel {
					if allowedWorkloads.Contains(candidate.Key) {
						selected = append(selected, candidate)
					}
				}
			case typeURL == model.AddressType && candidate.Facts.Service != nil:
				serviceKey := candidate.Facts.Service.ServiceKey
				if serviceKeys.Contains(serviceKey) {
					selected = append(selected, candidate)
					selectedServiceKeys.Insert(serviceKey)
				}
			}
		}
	}
	for serviceKey := range serviceKeysForNames(snapshot, names) {
		if serviceKeys.Contains(serviceKey) {
			selectedServiceKeys.Insert(serviceKey)
		}
	}
	for serviceKey := range selectedServiceKeys {
		for _, endpoint := range snapshot.ListServiceMembers(typeURL, serviceKey) {
			if !endpoint.IsWorkloadAddress() {
				continue
			}
			if allowedWorkloads.Contains(endpoint.Key) {
				selected = append(selected, endpoint)
			}
		}
	}
	return withGateways(selected)
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
	workload := resource.Facts.Workload
	if workload == nil {
		return false
	}
	switch scope.Class {
	case model.ClientDedicatedZTunnel:
		return workload.SandboxUID == scope.SandboxUID
	case model.ClientSharedZTunnel:
		return workload.NodeName == scope.NodeName
	default:
		return false
	}
}

func scopedWorkloads(scope model.ClientScope, snapshot model.ResourceSet, typeURL string) []model.Resource {
	query, found := workloadScopeQuery(scope)
	if !found {
		return nil
	}
	return snapshot.ListWorkloads(typeURL, query)
}

func workloadScopeQuery(scope model.ClientScope) (model.WorkloadQuery, bool) {
	switch scope.Class {
	case model.ClientDedicatedZTunnel:
		return model.WorkloadQuery{SandboxUID: scope.SandboxUID}, true
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
