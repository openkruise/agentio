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
	"slices"
	"sort"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// Identity retains selection metadata for an observed wire name, never its
// payload. Workloads records scopes whose dependencies made this name visible;
// wildcard Address watches use this evidence to withdraw resources without a
// per-connection table of everything previously sent.
type Identity struct {
	Name      string
	Facts     model.ResourceFacts
	Workloads sets.Set[WorkloadIdentity]
}

// WorkloadIdentity is the part of Workload facts that defines an authenticated
// client scope. It deliberately excludes policy and networking references.
type WorkloadIdentity struct {
	UID       string
	Source    model.SourceRef
	Principal model.Principal
	NodeName  string
}

func workloadIdentity(workload *model.WorkloadResourceFacts) WorkloadIdentity {
	return WorkloadIdentity{
		UID:       workload.WorkloadUID,
		Source:    workload.Source,
		Principal: workload.Principal,
		NodeName:  workload.NodeName,
	}
}

// Candidate identifies a resource to reselect from the current snapshot.
// Identities includes intermediate names and visibility, even across rollbacks.
type Candidate struct {
	Key        model.ResourceKey
	Identities []Identity
}

// Update is an immutable invalidation notice, not a delta to replay. Publications
// may be observed by Demand before their notices are consumed. Merging notices
// therefore unions candidates and never cancels changes by comparing endpoints.
type Update struct {
	version       string
	candidates    map[string][]Candidate
	affectedTypes sets.Set[string]
	full          bool
	fullTypes     sets.Set[string]
	addressScopes *addressScopeIndex
}

// Version identifies the most recent publication included in this notice.
func (u Update) Version() string { return u.version }

// Affects reports whether a watched type has candidates or needs a full refresh.
func (u Update) Affects(typeURL string) bool {
	return u.FullFor(typeURL) || u.affectedTypes.Contains(typeURL)
}

// FullFor reports whether a dynamic notification requires a full selection.
func (u Update) FullFor(typeURL string) bool {
	return u.full && (len(u.fullTypes) == 0 || u.fullTypes.Contains(typeURL))
}

// Candidates borrows the immutable, key-ordered invalidation index. Neither the
// slice nor its nested metadata may be modified. Direct Workloads are projected
// from Address candidates, so their source keys retain the Address type URL.
func (u Update) Candidates(typeURL string) []Candidate {
	if typeURL == model.WorkloadType {
		typeURL = model.AddressType
	}
	return u.candidates[typeURL]
}

func updateBetween(before, after model.ResourceSet, changes []model.ResourceChange) Update {
	candidates := make(map[model.ResourceKey]Candidate, len(changes))
	for _, change := range changes {
		for _, resource := range []*model.Resource{change.Old, change.New} {
			if resource != nil {
				addCandidate(candidates, *resource, nil)
			}
		}
	}
	indexDependencies(candidates, before, after, changes)
	return indexedUpdate(after.Version(), candidates)
}

func indexedUpdate(version string, candidates map[model.ResourceKey]Candidate) Update {
	u := Update{
		version:       version,
		candidates:    make(map[string][]Candidate),
		affectedTypes: sets.New[string](),
	}
	for key, candidate := range candidates {
		u.candidates[key.TypeURL] = append(u.candidates[key.TypeURL], candidate)
		u.affectedTypes.Insert(key.TypeURL)
		if key.TypeURL == model.AddressType {
			u.affectedTypes.Insert(model.WorkloadType)
		}
	}
	for typeURL := range u.candidates {
		sort.Slice(u.candidates[typeURL], func(i, j int) bool {
			return u.candidates[typeURL][i].Key.Name < u.candidates[typeURL][j].Key.Name
		})
	}
	if len(u.candidates[model.AddressType]) != 0 {
		u.addressScopes = &addressScopeIndex{}
	}
	return u
}

func addCandidate(
	index map[model.ResourceKey]Candidate,
	resource model.Resource,
	workload *model.WorkloadResourceFacts,
) {
	candidate := index[resource.Key]
	candidate.Key = resource.Key
	identity := Identity{Name: resource.XDSName, Facts: resource.Facts}
	if workload != nil {
		identity.Workloads = sets.New(workloadIdentity(workload))
	}
	candidate.Identities = mergeIdentity(candidate.Identities, identity)
	index[resource.Key] = candidate
}

func mergeIdentity(identities []Identity, identity Identity) []Identity {
	for i, existing := range identities {
		if existing.Name != identity.Name || !existing.Facts.Equal(identity.Facts) {
			continue
		}
		if len(identity.Workloads) != 0 {
			if identities[i].Workloads == nil {
				identities[i].Workloads = sets.New[WorkloadIdentity]()
			}
			identities[i].Workloads.Merge(identity.Workloads)
		}
		return identities
	}
	return append(identities, identity)
}

// Merge unions already-published invalidations. Only Store.Apply may fold
// unobservable, pre-publication transitions into a net change.
func Merge(older, newer Update) Update {
	merged := Update{
		version:       newer.version,
		candidates:    older.candidates,
		affectedTypes: older.affectedTypes,
		addressScopes: older.addressScopes,
	}
	addressChanged := false
	copied := false
	if merged.candidates == nil {
		merged.candidates = make(map[string][]Candidate, len(newer.candidates))
		copied = true
	}
	for typeURL, incoming := range newer.candidates {
		batch, changed := mergeCandidates(older.candidates[typeURL], incoming)
		if changed {
			addressChanged = addressChanged || typeURL == model.AddressType
			if !copied {
				merged.candidates = maps.Clone(older.candidates)
				copied = true
			}
			merged.candidates[typeURL] = batch
		}
	}
	if merged.affectedTypes == nil || !older.affectedTypes.SupersetOf(newer.affectedTypes) {
		merged.affectedTypes = sets.NewWithLength[string](len(older.affectedTypes) + len(newer.affectedTypes))
		merged.affectedTypes.Merge(older.affectedTypes)
		merged.affectedTypes.Merge(newer.affectedTypes)
	}
	merged.full = older.full || newer.full
	if merged.full && !(older.full && len(older.fullTypes) == 0 || newer.full && len(newer.fullTypes) == 0) {
		merged.fullTypes = sets.New[string]()
		merged.fullTypes.Merge(older.fullTypes)
		merged.fullTypes.Merge(newer.fullTypes)
	}
	if addressChanged {
		merged.addressScopes = &addressScopeIndex{}
	}
	return merged
}

// Both inputs are immutable, key-ordered sets. Disjoint types and identity
// metadata remain shared; overlapping batches only need a linear merge.
func mergeCandidates(older, newer []Candidate) ([]Candidate, bool) {
	if len(older) == 0 {
		return newer, len(newer) != 0
	}
	if len(newer) == 0 {
		return older, false
	}
	count, unchanged := candidateUnionSize(older, newer)
	// Repeated rule changes retain the same names and ownership evidence.
	// Reuse their immutable union instead of copying it for every queued client.
	if unchanged && count == len(older) {
		return older, false
	}
	merged := make([]Candidate, 0, count)
	for len(older) != 0 && len(newer) != 0 {
		switch {
		case older[0].Key.Name < newer[0].Key.Name:
			merged = append(merged, older[0])
			older = older[1:]
		case older[0].Key.Name > newer[0].Key.Name:
			merged = append(merged, newer[0])
			newer = newer[1:]
		default:
			candidate := older[0]
			copied := false
			for _, incoming := range newer[0].Identities {
				match := -1
				for i, existing := range candidate.Identities {
					if existing.Name == incoming.Name && existing.Facts.Equal(incoming.Facts) {
						match = i
						break
					}
				}
				if match >= 0 && candidate.Identities[match].Workloads.SupersetOf(incoming.Workloads) {
					continue
				}
				// Copy only when the union introduces new visibility evidence.
				if !copied {
					candidate.Identities = slices.Clone(candidate.Identities)
					copied = true
				}
				if match < 0 {
					candidate.Identities = append(candidate.Identities, incoming)
				} else if len(candidate.Identities[match].Workloads) == 0 {
					candidate.Identities[match].Workloads = incoming.Workloads
				} else {
					workloads := maps.Clone(candidate.Identities[match].Workloads)
					workloads.Merge(incoming.Workloads)
					candidate.Identities[match].Workloads = workloads
				}
			}
			merged = append(merged, candidate)
			older, newer = older[1:], newer[1:]
		}
	}
	merged = append(merged, older...)
	return append(merged, newer...), true
}

// candidateUnionSize also reports whether the union retains only existing evidence.
func candidateUnionSize(older, newer []Candidate) (int, bool) {
	// Count repeated keys before allocating so pending notices retain only
	// enough capacity for their union, including heavily overlapping updates.
	count := len(older) + len(newer)
	unchanged := true
	for i, j := 0, 0; i < len(older) && j < len(newer); {
		switch {
		case older[i].Key.Name < newer[j].Key.Name:
			i++
		case older[i].Key.Name > newer[j].Key.Name:
			j++
		default:
			count--
			for _, incoming := range newer[j].Identities {
				found := false
				for _, existing := range older[i].Identities {
					if existing.Name == incoming.Name && existing.Facts.Equal(incoming.Facts) &&
						existing.Workloads.SupersetOf(incoming.Workloads) {
						found = true
						break
					}
				}
				if !found {
					unchanged = false
					break
				}
			}
			i++
			j++
		}
	}
	return count, unchanged
}

func coalesceChanges(changes []model.ResourceChange) []model.ResourceChange {
	indexed := make(map[model.ResourceKey]model.ResourceChange, len(changes))
	for _, change := range changes {
		if existing, found := indexed[change.Key]; found {
			change.Old = existing.Old
		}
		indexed[change.Key] = change
	}
	result := make([]model.ResourceChange, 0, len(indexed))
	for _, change := range indexed {
		if !sameResource(change.Old, change.New) {
			result = append(result, change)
		}
	}
	return result
}

func sameResource(left, right *model.Resource) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Hash == right.Hash
}
