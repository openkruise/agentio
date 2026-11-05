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

package store

import (
	"slices"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// indexDependencies expands selection dependencies before publications are
// merged, while intermediate references and their target identities are still
// available. Final client visibility remains the generator's responsibility.
func indexDependencies(
	index map[model.ResourceKey]Candidate,
	before, after model.ResourceSet,
	changes []model.ResourceChange,
) {
	namespaces := sets.New[string]()
	for _, change := range changes {
		if change.Old != nil && change.New != nil && change.Old.Facts.Equal(change.New.Facts) &&
			change.Old.XDSName == change.New.XDSName && slices.Equal(change.Old.Aliases, change.New.Aliases) {
			continue
		}
		for _, resource := range []*model.Resource{change.Old, change.New} {
			if resource == nil || resource.Facts.References == nil {
				continue
			}
			for _, key := range resource.Facts.References.Keys {
				for _, snapshot := range []model.ResourceSet{before, after} {
					if target, exists := snapshot.Get(key); exists {
						addCandidate(index, target, nil)
					}
				}
			}
		}
		if change.Key.TypeURL != model.AddressType {
			continue
		}
		indexWithdrawnScopes(index, before, change)

		for _, resource := range []*model.Resource{change.Old, change.New} {
			if resource == nil {
				continue
			}
			workload := resource.Facts.Workload
			if workload != nil {
				namespaces.Insert(workload.Namespace)
			}
			for _, snapshot := range []model.ResourceSet{before, after} {
				if service := resource.Facts.Service; service != nil {
					for _, member := range snapshot.ListServiceMembers(model.AddressType, service.ServiceKey) {
						addCandidate(index, member, nil)
					}
				}
				if workload != nil {
					indexWorkloadDependencies(index, snapshot, workload)
				}
			}
		}
	}
	if len(namespaces) == 0 {
		return
	}
	// These policies have no per-workload scope metadata. Expand each set once
	// per publication, retaining identities from both snapshots for withdrawals.
	for _, snapshot := range []model.ResourceSet{before, after} {
		for _, policy := range snapshot.ListGlobalAuthorizations() {
			addCandidate(index, policy, nil)
		}
		for namespace := range namespaces {
			for _, policy := range snapshot.ListNamespaceAuthorizations(namespace) {
				addCandidate(index, policy, nil)
			}
		}
	}
}

func indexWithdrawnScopes(
	index map[model.ResourceKey]Candidate,
	before model.ResourceSet,
	change model.ResourceChange,
) {
	// When an address disappears or changes identity, retain the scopes that
	// could see its old Service/Gateway identity. Later reference removals may
	// otherwise find neither the resource nor its old owners in any snapshot.
	old, next := change.Old, change.New
	if old == nil {
		return
	}
	if next != nil && old.XDSName == next.XDSName && old.Facts.GatewayOwner == next.Facts.GatewayOwner &&
		(old.Facts.Service == nil || next.Facts.Service != nil && *old.Facts.Service == *next.Facts.Service) {
		return
	}
	queries := make([]model.WorkloadQuery, 0, 2)
	if old.Facts.Service != nil {
		queries = append(queries, model.WorkloadQuery{ServiceKey: old.Facts.Service.ServiceKey})
	}
	if old.Facts.GatewayOwner != "" {
		queries = append(queries, model.WorkloadQuery{GatewayReference: old.Facts.GatewayOwner})
	}
	identity := Identity{Name: old.XDSName, Facts: old.Facts, Workloads: sets.New[WorkloadIdentity]()}
	for _, query := range queries {
		for _, workload := range before.ListWorkloads(model.AddressType, query) {
			identity.Workloads.Insert(workloadIdentity(workload.Facts.Workload))
		}
	}
	if len(identity.Workloads) != 0 {
		candidate := index[old.Key]
		candidate.Identities = mergeIdentity(candidate.Identities, identity)
		index[old.Key] = candidate
	}
}

func indexWorkloadDependencies(
	index map[model.ResourceKey]Candidate,
	snapshot model.ResourceSet,
	workload *model.WorkloadResourceFacts,
) {
	add := func(resources []model.Resource, scope *model.WorkloadResourceFacts) {
		for _, dependency := range resources {
			addCandidate(index, dependency, scope)
		}
	}
	for _, key := range workload.ServiceKeys {
		for _, service := range snapshot.Lookup(model.AddressType, key) {
			if service.Facts.Service != nil && service.Facts.Service.ServiceKey == key {
				addCandidate(index, service, workload)
			}
		}
	}
	for _, key := range workload.GatewayReferences {
		add(snapshot.ListResourcesOwnedByGateway(model.AddressType, key), workload)
	}
	for _, name := range workload.TrafficPolicyRefs {
		add(snapshot.Lookup(model.TrafficPolicyType, name), nil)
	}
	for _, name := range workload.AuthorizationRefs {
		add(snapshot.Lookup(model.WorkloadAuthorizationType, name), nil)
	}
	add(snapshot.ListSandboxesByAttester(workload.WorkloadUID), nil)
}
