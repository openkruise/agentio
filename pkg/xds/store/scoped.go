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
	"maps"
	"sort"
	"sync"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

type addressScopeIndex struct {
	once                sync.Once
	addressesByWorkload map[string][]Candidate
	addressesByService  map[string][]Candidate
	addressesByGateway  map[string][]Candidate
	unscopedAddresses   []Candidate
}

// Ordinary streams skip this cost; dedicated streams share one immutable index.
func (u Update) indexAddressScopes() *addressScopeIndex {
	index := u.addressScopes
	index.once.Do(func() {
		index.addressesByWorkload = make(map[string][]Candidate)
		index.addressesByService = make(map[string][]Candidate)
		index.addressesByGateway = make(map[string][]Candidate)
		for _, candidate := range u.candidates[model.AddressType] {
			if len(candidate.Identities) == 0 {
				index.unscopedAddresses = append(index.unscopedAddresses, candidate)
				continue
			}
			workloads, services, gateways := sets.New[string](), sets.New[string](), sets.New[string]()
			for _, identity := range candidate.Identities {
				if facts := identity.Facts.Workload; facts != nil {
					workloads.Insert(facts.WorkloadUID)
				}
				if facts := identity.Facts.Service; facts != nil {
					services.Insert(facts.ServiceKey)
				}
				if owner := identity.Facts.GatewayOwner; owner != "" {
					gateways.Insert(owner)
				}
				for workload := range identity.Workloads {
					workloads.Insert(workload.UID)
				}
			}
			for uid := range workloads {
				index.addressesByWorkload[uid] = append(index.addressesByWorkload[uid], candidate)
			}
			for key := range services {
				index.addressesByService[key] = append(index.addressesByService[key], candidate)
			}
			for key := range gateways {
				index.addressesByGateway[key] = append(index.addressesByGateway[key], candidate)
			}
		}
	})
	return index
}

// ForWorkload preserves current dependencies and old identities needed for withdrawals.
// The resource generator still enforces source identity, principal and visibility.
func (u Update) ForWorkload(uid string, snapshot model.ResourceSet) Update {
	if len(u.candidates[model.AddressType]) == 0 || u.FullFor(model.AddressType) {
		return u
	}
	index := u.indexAddressScopes()
	selected := make(map[model.ResourceKey]Candidate)
	add := func(candidates []Candidate) {
		for _, candidate := range candidates {
			selected[candidate.Key] = candidate
		}
	}
	add(index.unscopedAddresses)
	add(index.addressesByWorkload[uid])
	addDependencies := func(workload *model.WorkloadResourceFacts) {
		for _, key := range workload.ServiceKeys {
			add(index.addressesByService[key])
		}
		for _, key := range workload.GatewayReferences {
			add(index.addressesByGateway[key])
		}
	}
	for _, workload := range snapshot.ListWorkloads(model.AddressType, model.WorkloadQuery{WorkloadUID: uid}) {
		addDependencies(workload.Facts.Workload)
	}
	for _, candidate := range index.addressesByWorkload[uid] {
		for _, identity := range candidate.Identities {
			if workload := identity.Facts.Workload; workload != nil && workload.WorkloadUID == uid {
				addDependencies(workload)
			}
		}
	}
	u.candidates = maps.Clone(u.candidates)
	u.candidates[model.AddressType] = make([]Candidate, 0, len(selected))
	for _, candidate := range selected {
		u.candidates[model.AddressType] = append(u.candidates[model.AddressType], candidate)
	}
	sort.Slice(u.candidates[model.AddressType], func(i, j int) bool {
		return u.candidates[model.AddressType][i].Key.Name < u.candidates[model.AddressType][j].Key.Name
	})
	// Queued scoped notices must not retain the original cluster-wide indexes.
	u.addressScopes = nil
	if len(selected) != 0 {
		u.addressScopes = &addressScopeIndex{}
	}
	return u
}
