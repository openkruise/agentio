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

package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"istio.io/istio/pkg/util/sets"
)

// ResourceSet is an immutable, indexed snapshot of discovery resources.
type ResourceSet struct {
	resources map[string]*resourceTypeIndex
	version   string
	length    int
}

// NewResourceSet indexes resources by type and name; pre-hashed resources are validated but not re-normalized.
func NewResourceSet(resources []Resource) (ResourceSet, error) {
	result := ResourceSet{resources: make(map[string]*resourceTypeIndex)}
	for _, resource := range resources {
		normalized := resource
		if normalized.Hash == "" {
			var err error
			normalized, err = NewResource(
				resource.Key,
				resource.XDSName,
				Prebuilt(resource.Value),
				resource.Aliases,
				resource.Facts,
			)
			if err != nil {
				return ResourceSet{}, err
			}
		} else if err := validateResource(normalized); err != nil {
			return ResourceSet{}, err
		}
		index := result.resources[normalized.Key.TypeURL]
		if index == nil {
			index = &resourceTypeIndex{}
			result.resources[normalized.Key.TypeURL] = index
		}
		shardID := resourceShard(normalized.Key.Name)
		if index.shards[shardID] == nil {
			index.shards[shardID] = make(map[string]Resource)
		}
		if _, found := index.shards[shardID][normalized.Key.Name]; found {
			return ResourceSet{}, fmt.Errorf("duplicate resource %s/%s", normalized.Key.TypeURL, normalized.Key.Name)
		}
		index.shards[shardID][normalized.Key.Name] = normalized
		indexResourceLookups(index, normalized)
		for _, key := range normalized.Facts.referenceKeys() {
			if index.references == nil {
				index.references = new(resourceReferenceCounts)
			}
			shard := resourceShard(key.Name)
			if index.references[shard] == nil {
				index.references[shard] = make(map[ResourceKey]int)
			}
			index.references[shard][key]++
		}
		index.length++
		result.length++
	}
	for _, index := range result.resources {
		finalizeLookupIndex(&index.lookup)
		finalizeLookupIndex(&index.facts)
	}
	result.version = result.computeVersion()
	return result, nil
}

// Version returns the snapshot version used for discovery publication.
func (s ResourceSet) Version() string {
	return s.version
}

// Len returns the total number of resources across all types.
func (s ResourceSet) Len() int {
	return s.length
}

// Get returns a resource by key. The result shares storage with the set and
// must not be mutated.
func (s ResourceSet) Get(key ResourceKey) (Resource, bool) {
	index := s.resources[key.TypeURL]
	if index == nil {
		return Resource{}, false
	}
	resource, found := index.shards[resourceShard(key.Name)][key.Name]
	if !found {
		return Resource{}, false
	}
	return resource, true
}

// Lookup returns resources addressed by a canonical key, wire name, or alias.
// It uses the immutable lookup index and never scans the type snapshot.
func (s ResourceSet) Lookup(typeURL, name string) []Resource {
	index := s.resources[typeURL]
	if index == nil || name == "" {
		return nil
	}
	names := append([]string(nil), lookupNames(&index.lookup, name)...)
	if resource, found := s.Get(ResourceKey{TypeURL: typeURL, Name: name}); found {
		names = append(names, resource.Key.Name)
	}
	return resourcesForNames(index, names)
}

// ListWorkloads returns resources of the given type matching every query constraint.
func (s ResourceSet) ListWorkloads(typeURL string, query WorkloadQuery) []Resource {
	index := s.resources[typeURL]
	if index == nil {
		return nil
	}
	candidates := workloadQueryCandidates(&index.facts, query)
	if len(candidates) == 0 {
		return nil
	}
	// Fact postings are already sorted and unique, so resolve them directly without rebuilding a set and sorting it.
	result := make([]Resource, 0, len(candidates))
	for _, name := range candidates {
		resource, found := index.shards[resourceShard(name)][name]
		if found && query.Matches(resource.Facts.Workload) {
			result = append(result, resource)
		}
	}
	return result
}

// HasReference uses counts for body retention; no caller needs the referrers' names.
func (s ResourceSet) HasReference(key ResourceKey) bool {
	for _, index := range s.resources {
		if index.references != nil && index.references[resourceShard(key.Name)][key] > 0 {
			return true
		}
		if key.TypeURL == TrafficPolicyType &&
			len(lookupNames(&index.facts, resourceFactIndexKey(resourceFactTrafficPolicyReference, key.Name))) != 0 {
			return true
		}
	}
	return false
}

// HasWorkload reports whether any resource of the type matches the query.
func (s ResourceSet) HasWorkload(typeURL string, query WorkloadQuery) bool {
	index := s.resources[typeURL]
	if index == nil {
		return false
	}
	for _, name := range workloadQueryCandidates(&index.facts, query) {
		resource, found := index.shards[resourceShard(name)][name]
		if found && query.Matches(resource.Facts.Workload) {
			return true
		}
	}
	return false
}

// ListSandboxesByAttester uses the Sandbox-side index in this publication.
func (s ResourceSet) ListSandboxesByAttester(workloadUID string) []Resource {
	return s.listByFact(SandboxType, resourceFactAttesterWorkloadUID, workloadUID)
}

// ListServiceMembers returns resources of the type belonging to a Service.
func (s ResourceSet) ListServiceMembers(typeURL, serviceKey string) []Resource {
	return s.listByFact(typeURL, resourceFactService, serviceKey)
}

// ListResourcesOwnedByGateway returns resources published for a gateway.
func (s ResourceSet) ListResourcesOwnedByGateway(typeURL, gatewayKey string) []Resource {
	return s.listByFact(typeURL, resourceFactGatewayOwner, gatewayKey)
}

// ListGlobalAuthorizations returns authorizations with global scope.
func (s ResourceSet) ListGlobalAuthorizations() []Resource {
	return s.listByFact(WorkloadAuthorizationType, resourceFactAuthorizationGlobal, "global")
}

// ListNamespaceAuthorizations returns authorizations scoped to the namespace.
func (s ResourceSet) ListNamespaceAuthorizations(namespace string) []Resource {
	return s.listByFact(WorkloadAuthorizationType, resourceFactAuthorizationNamespace, namespace)
}

func (s ResourceSet) listByFact(typeURL string, kind resourceFactKind, key string) []Resource {
	index := s.resources[typeURL]
	if index == nil || key == "" {
		return nil
	}
	return resourcesForNames(index, lookupNames(&index.facts, resourceFactIndexKey(kind, key)))
}

// List returns every resource of a type, ordered by name. The results share
// storage with the set and must not be mutated.
func (s ResourceSet) List(typeURL string) []Resource {
	index := s.resources[typeURL]
	if index == nil {
		return nil
	}
	result := make([]Resource, 0, index.length)
	for _, shard := range index.shards {
		for _, resource := range shard {
			result = append(result, resource)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key.Name < result[j].Key.Name })
	return result
}

// Types returns the resource type URLs in sorted order.
func (s ResourceSet) Types() []string {
	result := make([]string, 0, len(s.resources))
	for typeURL := range s.resources {
		result = append(result, typeURL)
	}
	sort.Strings(result)
	return result
}

// CountsByType returns snapshot cardinality without allocating every resource.
func (s ResourceSet) CountsByType() map[string]int {
	result := make(map[string]int, len(s.resources))
	for typeURL, index := range s.resources {
		result[typeURL] = index.length
	}
	return result
}

// Apply returns a new immutable snapshot by copying only the shards that contain
// an effective change. This keeps steady-state work bounded even when Address
// and Workload contain hundreds of thousands of resources.
func (s ResourceSet) Apply(changes []ResourceChange) (ResourceSet, bool, error) {
	if len(changes) == 0 {
		return s, false, nil
	}
	resources := make(map[string]*resourceTypeIndex, len(s.resources))
	maps.Copy(resources, s.resources)
	clonedTypes := make(map[string]*resourceTypeIndex)
	type shardKey struct {
		typeURL string
		shard   uint16
	}
	clonedShards := sets.New[shardKey]()
	clonedReferences := sets.New[shardKey]()
	lookupUpdates := lookupIndexUpdates{cloned: sets.New[lookupShardKey](), batch: len(changes) > 1}
	effective := make([]ResourceChange, 0, len(changes))
	length := s.length
	for _, change := range changes {
		if strings.TrimSpace(change.Key.TypeURL) == "" || strings.TrimSpace(change.Key.Name) == "" {
			return ResourceSet{}, false, fmt.Errorf("resource change key is required")
		}
		index := resources[change.Key.TypeURL]
		shardID := resourceShard(change.Key.Name)
		var currentShard map[string]Resource
		if index != nil {
			currentShard = index.shards[shardID]
		}
		current, found := currentShard[change.Key.Name]
		if change.New == nil {
			if !found {
				continue
			}
		} else {
			normalized, err := normalizeChangedResource(change)
			if err != nil {
				return ResourceSet{}, false, err
			}
			if found && current.Hash == normalized.Hash {
				continue
			}
			change.New = &normalized
		}

		if _, cloned := clonedTypes[change.Key.TypeURL]; !cloned {
			copied := &resourceTypeIndex{}
			if index != nil {
				*copied = *index
			}
			index = copied
			resources[change.Key.TypeURL] = index
			clonedTypes[change.Key.TypeURL] = index
		} else {
			index = clonedTypes[change.Key.TypeURL]
		}
		key := shardKey{typeURL: change.Key.TypeURL, shard: shardID}
		if !clonedShards.Contains(key) {
			original := index.shards[shardID]
			copied := make(map[string]Resource, len(original)+1)
			maps.Copy(copied, original)
			index.shards[shardID] = copied
			clonedShards.Insert(key)
		}
		old := current
		if found {
			change.Old = &old
		}
		updateResourceLookupDiff(index, change.Old, change.New, change.Key.TypeURL, &lookupUpdates)
		var oldReferences, newReferences []ResourceKey
		if change.Old != nil {
			oldReferences = change.Old.Facts.referenceKeys()
		}
		if change.New != nil {
			newReferences = change.New.Facts.referenceKeys()
		}
		if !slices.Equal(oldReferences, newReferences) {
			if original := s.resources[change.Key.TypeURL]; original != nil && index.references != nil &&
				index.references == original.references {
				references := *index.references
				index.references = &references
			}
			for _, item := range []struct {
				references []ResourceKey
				delta      int
			}{{oldReferences, -1}, {newReferences, 1}} {
				for _, reference := range item.references {
					if index.references == nil {
						index.references = new(resourceReferenceCounts)
					}
					shard := resourceShard(reference.Name)
					key := shardKey{typeURL: change.Key.TypeURL, shard: shard}
					if !clonedReferences.Contains(key) {
						copied := make(map[ResourceKey]int, len(index.references[shard])+1)
						maps.Copy(copied, index.references[shard])
						index.references[shard] = copied
						clonedReferences.Insert(key)
					}
					counts := index.references[shard]
					counts[reference] += item.delta
					if counts[reference] == 0 {
						delete(counts, reference)
					}
				}
			}
		}
		if change.New == nil {
			delete(index.shards[shardID], change.Key.Name)
			index.length--
			length--
		} else {
			index.shards[shardID][change.Key.Name] = *change.New
			if !found {
				index.length++
				length++
			}
		}
		effective = append(effective, change)
	}
	if len(effective) == 0 {
		return s, false, nil
	}
	lookupUpdates.apply(resources)
	for typeURL, index := range clonedTypes {
		if index.length == 0 {
			delete(resources, typeURL)
		}
	}
	return ResourceSet{
		resources: resources,
		version:   incrementalVersion(s.version, effective),
		length:    length,
	}, true, nil
}

// Diff describes the key-level difference from s to next. It is intended for
// startup and recovery publication; the normal KRT path already supplies these
// changes and does not call Diff.
func (s ResourceSet) Diff(next ResourceSet) []ResourceChange {
	changes := make([]ResourceChange, 0)
	for typeURL, currentIndex := range s.resources {
		for _, currentShard := range currentIndex.shards {
			for name, current := range currentShard {
				updated, found := next.Get(ResourceKey{TypeURL: typeURL, Name: name})
				if found && updated.Hash == current.Hash {
					continue
				}
				old := current
				change := ResourceChange{Key: current.Key, Old: &old}
				if found {
					newResource := updated
					change.New = &newResource
				}
				changes = append(changes, change)
			}
		}
	}
	for typeURL, nextIndex := range next.resources {
		for _, nextShard := range nextIndex.shards {
			for name, resource := range nextShard {
				if _, found := s.Get(ResourceKey{TypeURL: typeURL, Name: name}); found {
					continue
				}
				newResource := resource
				changes = append(changes, ResourceChange{Key: resource.Key, New: &newResource})
			}
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Key.TypeURL != changes[j].Key.TypeURL {
			return changes[i].Key.TypeURL < changes[j].Key.TypeURL
		}
		return changes[i].Key.Name < changes[j].Key.Name
	})
	return changes
}

func incrementalVersion(previous string, changes []ResourceChange) string {
	ordered := append([]ResourceChange(nil), changes...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Key.TypeURL != ordered[j].Key.TypeURL {
			return ordered[i].Key.TypeURL < ordered[j].Key.TypeURL
		}
		return ordered[i].Key.Name < ordered[j].Key.Name
	})
	hasher := sha256.New()
	hasher.Write([]byte(previous))
	for _, change := range ordered {
		hasher.Write([]byte{0})
		hasher.Write([]byte(change.Key.TypeURL))
		hasher.Write([]byte{0})
		hasher.Write([]byte(change.Key.Name))
		hasher.Write([]byte{0})
		if change.New == nil {
			hasher.Write([]byte("deleted"))
		} else {
			hasher.Write([]byte(change.New.Hash))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// computeVersion folds every resource hash into one snapshot version. It reads
// the hashes straight out of the index: going through List would allocate and
// order the full resource set a second time for no benefit.
func (s ResourceSet) computeVersion() string {
	hasher := sha256.New()
	for _, typeURL := range s.Types() {
		for _, resource := range s.List(typeURL) {
			hasher.Write([]byte(resource.Hash))
			hasher.Write([]byte{0})
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func normalizeChangedResource(change ResourceChange) (Resource, error) {
	if change.New.Key != change.Key {
		return Resource{}, fmt.Errorf(
			"resource change key %v does not match new resource key %v",
			change.Key,
			change.New.Key,
		)
	}
	normalized := *change.New
	if normalized.Hash == "" {
		var err error
		normalized, err = NewResource(
			normalized.Key,
			normalized.XDSName,
			Prebuilt(normalized.Value),
			normalized.Aliases,
			normalized.Facts,
		)
		if err != nil {
			return Resource{}, err
		}
	} else if err := validateResource(normalized); err != nil {
		return Resource{}, err
	}
	return normalized, nil
}
