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
	"cmp"
	"context"
	"slices"
	"sort"
	"time"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// GenerationRequest is the immutable input to one resource generation pass.
// Full selects snapshot-based generation within Subscription; otherwise Update
// carries the indexed changes for the requested type.
type GenerationRequest struct {
	// Scope is the authenticated client visibility used to filter every
	// candidate resource; generators must never widen beyond it.
	Scope model.ClientScope
	// TypeURL is the single xDS type produced by this generation pass.
	TypeURL string
	// Subscription is the immutable reconciliation scope for this pass. Named
	// demand requests may include only the requested resources; all other
	// subscription and sent state remains unchanged on the connection.
	Subscription SubscriptionView
	// Snapshot is the publication view resources are generated from; its
	// version becomes the response system version.
	Snapshot model.ResourceSet
	// Update identifies resources to reselect, including intermediate identities
	// observed before publication notices were merged.
	Update xdsstore.Update
	// Full selects the snapshot diff path instead of indexed update generation.
	// It is set for initial reads, new subscriptions, and full-rebuild updates.
	Full bool
	// SubscribedNames contains explicit initial demands, including deferred
	// demands rechecked after a source notification. Other server refreshes
	// and unsubscribe-only requests leave it empty.
	SubscribedNames []string
}

type generatedDenial struct {
	name string
	err  error
}

// GeneratedDelta describes deterministic sent-state changes. Resources become
// the successfully sent versions and Removed names are deleted, but only after
// the Delta stream accepts the response.
type GeneratedDelta struct {
	Resources []model.Resource
	Removed   []string
	// pending retains initial demands whose source exists but is not published.
	pending []string

	// expiresAt is converted to a remaining TTL at send time. Expired resources
	// become removals instead of being sent with stale certificate contents.
	// versions overrides content versions for resources with a signing generation.
	versions       map[string]string
	expiresAt      map[string]time.Time
	denied         []generatedDenial
	allowed        []string
	elideSentState bool
}

// ResourceGenerator builds resources for one Delta xDS type without mutating
// stream state or writing to the stream.
type ResourceGenerator interface {
	Generate(context.Context, GenerationRequest) (GeneratedDelta, error)
}

func selectionNames(subscription SubscriptionView) []string {
	if subscription.Wildcard() {
		return nil
	}
	return subscription.Names()
}

func diffSelected(subscription SubscriptionView, selected map[string]model.Resource) GeneratedDelta {
	return diffResourceSelection(selected, subscription.SentNames(), subscription.SentVersion)
}

// diffSubscribed also resends explicitly subscribed names: the client may have
// evicted its local copy. Only resources in the authorized selection are sent.
func diffSubscribed(
	subscription SubscriptionView,
	selected map[string]model.Resource,
	subscribedNames []string,
) GeneratedDelta {
	delta := diffSelected(subscription, selected)
	if len(subscribedNames) == 0 {
		return delta
	}
	// Reconnects can replay the entire interest set. Index the diff once rather
	// than scanning a growing response for every explicitly subscribed name.
	resourceNames := sets.NewWithLength[string](len(delta.Resources))
	for _, resource := range delta.Resources {
		resourceNames.Insert(resource.XDSName)
	}
	removedNames := sets.New(delta.Removed...)
	for _, name := range subscribedNames {
		if name == "*" {
			continue
		}
		if resource, ok := selected[name]; ok {
			if !resourceNames.Contains(name) {
				delta.Resources = append(delta.Resources, resource)
				resourceNames.Insert(resource.XDSName)
			}
		} else if !removedNames.Contains(name) {
			delta.Removed = append(delta.Removed, name)
			removedNames.Insert(name)
		}
	}
	return delta
}

func diffResourceSelection(
	selected map[string]model.Resource,
	sentNames []string,
	sentVersion func(string) (string, bool),
) GeneratedDelta {
	resources := make([]model.Resource, 0, len(selected))
	for name, resource := range selected {
		if version, found := sentVersion(name); found && version == resource.Hash {
			continue
		}
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].XDSName < resources[j].XDSName })
	removed := make([]string, 0)
	for _, name := range sentNames {
		if _, found := selected[name]; !found {
			removed = append(removed, name)
		}
	}
	return GeneratedDelta{Resources: resources, Removed: removed}
}

// generateIncremental reads invalidated keys from the current snapshot. Only
// visible resources and identities requiring withdrawal allocate output space;
// no client-specific lookup results are retained beyond this generation pass.
func generateIncremental(
	request GenerationRequest,
	visible func(model.Resource) bool,
	previouslyVisible func(*xdsstore.Identity) bool,
	identityInScope func(*xdsstore.Identity) bool,
) GeneratedDelta {
	var delta GeneratedDelta
	for _, candidate := range request.Update.Candidates(request.TypeURL) {
		resource, found := request.Snapshot.Get(candidate.Key)
		selected := found && visible(resource)
		if selected {
			delta.Resources = append(delta.Resources, resource)
		}
		for i := range candidate.Identities {
			identity := &candidate.Identities[i]
			// Gateway wire names are shared across owners and variants. A sent
			// name alone does not mean this identity ever belonged to the client.
			if identityInScope != nil && !identityInScope(identity) {
				continue
			}
			if selected && identity.Name == resource.XDSName {
				continue
			}
			if _, sent := request.Subscription.SentVersion(identity.Name); sent ||
				previouslyVisible != nil && previouslyVisible(identity) {
				delta.Removed = append(delta.Removed, identity.Name)
			}
		}
	}
	sortResources := func() {
		slices.SortFunc(delta.Resources, func(left, right model.Resource) int {
			if order := cmp.Compare(left.XDSName, right.XDSName); order != 0 {
				return order
			}
			return cmp.Compare(left.Key.Name, right.Key.Name)
		})
	}
	sortResources()
	delta.Resources = collapseSortedXDSNames(delta.Resources)
	slices.Sort(delta.Removed)
	delta.Removed = slices.Compact(delta.Removed)
	selectedCount := len(delta.Resources)
	lookupType := request.TypeURL
	if lookupType == model.WorkloadType {
		lookupType = model.AddressType
	}
	write := 0
	for _, name := range delta.Removed {
		if _, found := slices.BinarySearchFunc(delta.Resources[:selectedCount], name,
			func(resource model.Resource, name string) int { return cmp.Compare(resource.XDSName, name) }); found {
			continue
		}
		// A queued deletion must not withdraw a same-name replacement whose
		// publication notice is still pending. Resolve only actual withdrawals.
		matches := request.Snapshot.Lookup(lookupType, name)
		var replacement *model.Resource
		for i := len(matches) - 1; i >= 0; i-- {
			if matches[i].XDSName == name && visible(matches[i]) {
				replacement = &matches[i]
				break
			}
		}
		if replacement != nil {
			delta.Resources = append(delta.Resources, *replacement)
			continue
		}
		delta.Removed[write] = name
		write++
	}
	clear(delta.Removed[write:])
	delta.Removed = delta.Removed[:write]
	if len(delta.Resources) != selectedCount {
		sortResources()
	}
	// Direct Workload versions are compared after Address projection.
	if request.TypeURL != model.WorkloadType {
		delta.Resources = unsentResources(request.Subscription, delta.Resources)
	}
	return delta
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

func unsentResources(subscription SubscriptionView, resources []model.Resource) []model.Resource {
	return slices.DeleteFunc(resources, func(resource model.Resource) bool {
		version, found := subscription.SentVersion(resource.XDSName)
		return found && version == resource.Hash
	})
}
