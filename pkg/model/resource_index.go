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
	"maps"
	"slices"
	"sort"
	"strings"

	"istio.io/istio/pkg/util/sets"
)

const resourceShardCount = 1024

// resourceTypeIndex shards the otherwise very large Address/Workload maps.
// Applying one key copies one small shard and the fixed-size shard table, while
// unchanged shards remain shared by immutable snapshots already in use.
type resourceTypeIndex struct {
	shards [resourceShardCount]map[string]Resource
	lookup resourceLookupIndex
	facts  resourceLookupIndex
	length int
}

// resourceLookupIndex is sharded so one-key updates copy one shard only.
type resourceLookupIndex struct {
	shards [resourceShardCount]map[string][]string
}

type lookupShardKey struct {
	typeURL string
	kind    byte
	shard   uint16
}

func resourceShard(name string) uint16 {
	// FNV-1a is stable, fast, and sufficient for distributing resource names.
	var hash uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		hash ^= uint32(name[i])
		hash *= 16777619
	}
	return uint16(hash & (resourceShardCount - 1))
}

type resourceFactKind byte

const (
	resourceFactWorkloadUID resourceFactKind = iota + 1
	resourceFactWorkloadAuthorizationRefs
	resourceFactWorkloadTrafficPolicyRefs
	resourceFactAttesterWorkloadUID
	resourceFactSource
	resourceFactNode
	resourceFactPrincipal
	resourceFactNamespace
	resourceFactService
	resourceFactGatewayReference
	resourceFactAuthorizationReference
	resourceFactTrafficPolicyReference
	resourceFactGatewayOwner
	resourceFactAuthorizationGlobal
	resourceFactAuthorizationNamespace
	resourceFactReference
)

func resourceFactIndexKey(kind resourceFactKind, key string) string {
	return string([]byte{byte(kind)}) + "\x00" + key
}

func resourceReferenceIndexKey(key ResourceKey) string {
	if key.TypeURL == TrafficPolicyType {
		return resourceFactIndexKey(resourceFactTrafficPolicyReference, key.Name)
	}
	return resourceFactIndexKey(resourceFactReference, key.TypeURL+"\x00"+key.Name)
}

func resourceFactKeys(resource Resource) []string {
	result := make([]string, 0, 8)
	add := func(kind resourceFactKind, key string) {
		if key != "" {
			result = append(result, resourceFactIndexKey(kind, key))
		}
	}
	if workload := resource.Facts.Workload; workload != nil {
		if workloadHasAuthorizationRefs(workload) {
			add(resourceFactWorkloadAuthorizationRefs, "enabled")
		}
		if len(workload.TrafficPolicyRefs) > 0 {
			add(resourceFactWorkloadTrafficPolicyRefs, "enabled")
		}
		add(resourceFactWorkloadUID, workload.WorkloadUID)
		add(resourceFactSource, workload.Source.String())
		add(resourceFactNode, workload.NodeName)
		add(resourceFactPrincipal, workload.Principal.String())
		add(resourceFactNamespace, workload.Namespace)
		for _, key := range workload.ServiceKeys {
			add(resourceFactService, key)
		}
		for _, key := range workload.GatewayReferences {
			add(resourceFactGatewayReference, key)
		}
		for _, key := range workload.AuthorizationRefs {
			add(resourceFactAuthorizationReference, key)
		}
		for _, key := range workload.TrafficPolicyRefs {
			add(resourceFactTrafficPolicyReference, key)
		}
	}
	for _, key := range resource.Facts.referenceKeys() {
		if key.TypeURL == TrafficPolicyType && resource.Facts.Workload != nil && slices.Contains(resource.Facts.Workload.TrafficPolicyRefs, key.Name) {
			continue
		}
		result = append(result, resourceReferenceIndexKey(key))
	}
	if sandbox := resource.Facts.Sandbox; sandbox != nil {
		add(resourceFactAttesterWorkloadUID, sandbox.AttesterWorkloadUID)
	}
	if resource.Facts.Service != nil {
		add(resourceFactService, resource.Facts.Service.ServiceKey)
	}
	add(resourceFactGatewayOwner, resource.Facts.GatewayOwner)
	if authorization := resource.Facts.Authorization; authorization != nil {
		switch authorization.Scope {
		case AuthorizationScopeGlobal:
			add(resourceFactAuthorizationGlobal, "global")
		case AuthorizationScopeNamespace:
			add(resourceFactAuthorizationNamespace, authorization.Namespace)
		}
	}
	return result
}

// workloadQueryCandidates finds a smallest fact posting without building a
// temporary slice of index keys. A singleton is already minimal; the caller
// still checks every query predicate against that candidate's Workload facts.
func workloadQueryCandidates(index *resourceLookupIndex, query WorkloadQuery) []string {
	fields := [...]struct {
		kind  resourceFactKind
		value string
	}{
		{resourceFactWorkloadUID, query.WorkloadUID},
		{resourceFactSource, query.Source.String()},
		{resourceFactAuthorizationReference, query.AuthorizationReference},
		{resourceFactTrafficPolicyReference, query.TrafficPolicyReference},
		{resourceFactNode, query.NodeName},
		{resourceFactNamespace, query.Namespace},
		{resourceFactService, query.ServiceKey},
		{resourceFactGatewayReference, query.GatewayReference},
	}
	// Validate all predicates before taking a shortcut. An invalid later field
	// must still fail closed even if an earlier index has exactly one candidate.
	for _, field := range fields {
		if field.value != "" && strings.TrimSpace(field.value) == "" {
			return nil
		}
	}
	if query.Source != (SourceRef{}) && query.Source.Validate() != nil {
		return nil
	}
	if query.Principal != nil && query.Principal.Validate() != nil {
		return nil
	}
	var candidates []string
	consider := func(kind resourceFactKind, value string) bool {
		names := lookupNames(index, resourceFactIndexKey(kind, value))
		if candidates == nil || len(names) < len(candidates) {
			candidates = names
		}
		return len(names) <= 1
	}
	for _, field := range fields {
		if field.value != "" && consider(field.kind, field.value) {
			return candidates
		}
	}
	if query.AuthorizationRefsOnly && consider(resourceFactWorkloadAuthorizationRefs, "enabled") {
		return candidates
	}
	if query.TrafficPolicyRefsOnly && consider(resourceFactWorkloadTrafficPolicyRefs, "enabled") {
		return candidates
	}
	if query.Principal != nil {
		consider(resourceFactPrincipal, query.Principal.String())
	}
	return candidates
}

// Authorization references are generated from shared policies for older data planes.
func workloadHasAuthorizationRefs(workload *WorkloadResourceFacts) bool {
	return len(workload.AuthorizationRefs) > 0
}

// Matches reports whether the workload satisfies every query constraint.
func (query WorkloadQuery) Matches(workload *WorkloadResourceFacts) bool {
	if workload == nil ||
		(query.AuthorizationRefsOnly && !workloadHasAuthorizationRefs(workload)) ||
		(query.TrafficPolicyRefsOnly && len(workload.TrafficPolicyRefs) == 0) ||
		(query.WorkloadUID != "" && workload.WorkloadUID != query.WorkloadUID) ||
		(query.Source != (SourceRef{}) && workload.Source != query.Source) ||
		(query.NodeName != "" && workload.NodeName != query.NodeName) ||
		(query.Principal != nil && workload.Principal != *query.Principal) ||
		(query.Namespace != "" && workload.Namespace != query.Namespace) ||
		!workloadReferencesMatch(workload, query) {
		return false
	}
	return true
}

func indexResourceLookups(index *resourceTypeIndex, resource Resource) {
	appendLookupName(&index.lookup, resource.XDSName, resource.Key.Name)
	for _, alias := range resource.Aliases {
		appendLookupName(&index.lookup, alias, resource.Key.Name)
	}
	for _, key := range resourceFactKeys(resource) {
		appendLookupName(&index.facts, key, resource.Key.Name)
	}
}

func appendLookupName(index *resourceLookupIndex, key, name string) {
	if key == "" || name == "" {
		return
	}
	shardID := resourceShard(key)
	if index.shards[shardID] == nil {
		index.shards[shardID] = make(map[string][]string)
	}
	index.shards[shardID][key] = append(index.shards[shardID][key], name)
}

func finalizeLookupIndex(index *resourceLookupIndex) {
	for shardID := range index.shards {
		for key, names := range index.shards[shardID] {
			sort.Strings(names)
			index.shards[shardID][key] = compactSorted(names)
		}
	}
}

func compactSorted(values []string) []string {
	if len(values) < 2 {
		return values
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] == values[write-1] {
			continue
		}
		values[write] = values[read]
		write++
	}
	return values[:write]
}

func lookupNames(index *resourceLookupIndex, key string) []string {
	return index.shards[resourceShard(key)][key]
}

func resourcesForNames(index *resourceTypeIndex, names []string) []Resource {
	if len(names) == 0 {
		return nil
	}
	unique := sets.NewWithLength[string](len(names))
	result := make([]Resource, 0, len(names))
	for _, name := range names {
		if unique.Contains(name) {
			continue
		}
		resource, found := index.shards[resourceShard(name)][name]
		if !found {
			continue
		}
		unique.Insert(name)
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key.Name < result[j].Key.Name })
	return result
}

type resourceLookupEntry struct {
	kind byte
	key  string
}

func resourceLookupEntries(resource *Resource) sets.Set[resourceLookupEntry] {
	entries := sets.New[resourceLookupEntry]()
	if resource == nil {
		return entries
	}
	add := func(kind byte, key string) {
		if key != "" {
			entries.Insert(resourceLookupEntry{kind: kind, key: key})
		}
	}
	add(0, resource.XDSName)
	for _, alias := range resource.Aliases {
		add(0, alias)
	}
	for _, key := range resourceFactKeys(*resource) {
		add(1, key)
	}
	return entries
}

func updateResourceLookupDiff(
	index *resourceTypeIndex,
	oldResource, newResource *Resource,
	typeURL string,
	updates *lookupIndexUpdates,
) {
	oldEntries := resourceLookupEntries(oldResource)
	newEntries := resourceLookupEntries(newResource)
	name := ""
	if newResource != nil {
		name = newResource.Key.Name
	} else if oldResource != nil {
		name = oldResource.Key.Name
	}
	for entry := range oldEntries {
		if newEntries.Contains(entry) {
			continue
		}
		updates.record(index, entry, name, false, typeURL)
	}
	for entry := range newEntries {
		if oldEntries.Contains(entry) {
			continue
		}
		updates.record(index, entry, name, true, typeURL)
	}
}

type lookupMembershipKey struct {
	typeURL string
	entry   resourceLookupEntry
}

type lookupMembershipChange struct {
	name string
	add  bool
}

// Defer membership changes until the entire publication is known. Shared
// policies can have very large postings; copying one per changed workload makes
// a batch quadratic even though the outer index maps are sharded.
type lookupIndexUpdates struct {
	cloned  sets.Set[lookupShardKey]
	batch   bool
	pending map[lookupMembershipKey][]lookupMembershipChange
}

func (u *lookupIndexUpdates) record(index *resourceTypeIndex, entry resourceLookupEntry,
	name string, add bool, typeURL string,
) {
	lookup := writableLookupShard(index, entry, typeURL, u.cloned)
	names := lookup[entry.key]
	// Empty and singleton postings are cheap to update directly. Only shared
	// lists need coalescing; unique resource names should not allocate a queue.
	if u.batch && len(names) > 1 {
		if u.pending == nil {
			u.pending = make(map[lookupMembershipKey][]lookupMembershipChange)
		}
		key := lookupMembershipKey{typeURL: typeURL, entry: entry}
		u.pending[key] = append(u.pending[key], lookupMembershipChange{name: name, add: add})
		return
	}
	updateLookupMembership(lookup, entry.key, names, name, add)
}

func (u *lookupIndexUpdates) apply(resources map[string]*resourceTypeIndex) {
	for key, changes := range u.pending {
		index := resources[key.typeURL]
		lookup := writableLookupShard(index, key.entry, key.typeURL, u.cloned)
		names := lookup[key.entry.key]
		if len(changes) == 1 {
			updateLookupMembership(lookup, key.entry.key, names, changes[0].name, changes[0].add)
			continue
		}
		// Apply may contain repeated changes to the same resource. Preserve the
		// last membership decision for each name, without modifying old snapshots.
		slices.SortStableFunc(changes, func(a, b lookupMembershipChange) int { return strings.Compare(a.name, b.name) })
		count, length := 0, len(names)
		for i := 0; i < len(changes); {
			end := i + 1
			for end < len(changes) && changes[end].name == changes[i].name {
				end++
			}
			change := changes[end-1]
			position := sort.SearchStrings(names, change.name)
			contains := position < len(names) && names[position] == change.name
			if change.add != contains {
				changes[count] = change
				count++
				if change.add {
					length++
				} else {
					length--
				}
			}
			i = end
		}
		if count == 0 {
			continue
		}
		if length == 0 {
			delete(lookup, key.entry.key)
			continue
		}
		updated := make([]string, 0, length)
		position := 0
		for _, change := range changes[:count] {
			next := position + sort.SearchStrings(names[position:], change.name)
			updated = append(updated, names[position:next]...)
			position = next
			if change.add {
				updated = append(updated, change.name)
			} else {
				position++
			}
		}
		updated = append(updated, names[position:]...)
		lookup[key.entry.key] = updated
	}
}

func updateLookupMembership(lookup map[string][]string, key string, names []string, name string, add bool) {
	position := sort.SearchStrings(names, name)
	contains := position < len(names) && names[position] == name
	if add == contains {
		return
	}
	if add {
		updated := make([]string, len(names)+1)
		copy(updated, names[:position])
		updated[position] = name
		copy(updated[position+1:], names[position:])
		lookup[key] = updated
		return
	}
	if len(names) == 1 {
		delete(lookup, key)
		return
	}
	updated := make([]string, 0, len(names)-1)
	updated = append(updated, names[:position]...)
	updated = append(updated, names[position+1:]...)
	lookup[key] = updated
}

func writableLookupShard(index *resourceTypeIndex, entry resourceLookupEntry,
	typeURL string, cloned sets.Set[lookupShardKey],
) map[string][]string {
	lookup := &index.lookup
	if entry.kind == 1 {
		lookup = &index.facts
	}
	outerShardID := resourceShard(entry.key)
	outerCloneKey := lookupShardKey{typeURL: typeURL, kind: entry.kind, shard: outerShardID}
	if !cloned.Contains(outerCloneKey) {
		original := lookup.shards[outerShardID]
		copied := make(map[string][]string, len(original)+1)
		maps.Copy(copied, original)
		lookup.shards[outerShardID] = copied
		cloned.Insert(outerCloneKey)
	}

	return lookup.shards[outerShardID]
}

func workloadReferencesMatch(workload *WorkloadResourceFacts, query WorkloadQuery) bool {
	if (query.ServiceKey != "" && !slices.Contains(workload.ServiceKeys, query.ServiceKey)) ||
		(query.GatewayReference != "" && !slices.Contains(workload.GatewayReferences, query.GatewayReference)) ||
		(query.AuthorizationReference != "" && !slices.Contains(workload.AuthorizationRefs, query.AuthorizationReference)) ||
		(query.TrafficPolicyReference != "" && !slices.Contains(workload.TrafficPolicyRefs, query.TrafficPolicyReference)) {
		return false
	}
	return true
}
