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

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// SandboxGenerator serves bindings and inline rules from one immutable
// publication. Scope is recomputed from Sandbox attesters, never from a UID claimed
// in a subscribe request. Gateways retain their existing cluster discovery scope.
type SandboxGenerator struct {
	Source model.SourceReader
}

// Generate returns the Sandbox delta visible to the authenticated client scope.
func (g SandboxGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.SandboxType {
		return GeneratedDelta{}, fmt.Errorf("sandbox generator does not support type URL %q", request.TypeURL)
	}
	if request.Full || request.Update.FullFor(request.TypeURL) {
		selected := selectSandboxResources(request.Scope, request.Snapshot, request.TypeURL, request.Subscription)
		for name, resource := range selected {
			if !matchesSource(resource, g.Source) {
				delete(selected, name)
			}
		}
		delta := diffSubscribed(request.Subscription, selected, request.SubscribedNames)
		deferUnpublishedRemovals(request, &delta, g.Source)
		return delta, nil
	}
	return generateIncremental(request, func(resource model.Resource) bool {
		return request.Subscription.allows(resource) &&
			sandboxResourceVisible(
				request.Scope,
				request.Snapshot,
				resource,
			) && matchesSource(resource, g.Source)
	}, nil, nil), nil
}

func scopedSandboxNames(scope model.ClientScope, snapshot model.ResourceSet) sets.Set[string] {
	result := sets.New[string]()
	for _, workload := range scopedWorkloads(scope, snapshot, model.AddressType) {
		for _, sandbox := range snapshot.ListSandboxesByAttester(workload.Facts.Workload.WorkloadUID) {
			result.Insert(sandbox.Key.Name)
		}
	}
	return result
}

func sandboxVisible(scope model.ClientScope, snapshot model.ResourceSet, uid string) bool {
	sandbox, found := snapshot.Get(model.ResourceKey{TypeURL: model.SandboxType, Name: uid})
	return found && sandboxResourceVisible(scope, snapshot, sandbox)
}

func sandboxResourceVisible(scope model.ClientScope, snapshot model.ResourceSet, sandbox model.Resource) bool {
	if scope.Class == model.ClientEgressGateway || scope.Class == model.ClientAgentioEgress {
		return true
	}
	facts := sandbox.Facts.Sandbox
	if facts == nil || facts.AttesterWorkloadUID == "" {
		return false
	}
	query, ok := workloadScopeQuery(&scope)
	if !ok || (query.WorkloadUID != "" && query.WorkloadUID != facts.AttesterWorkloadUID) {
		return false
	}
	query.WorkloadUID = facts.AttesterWorkloadUID
	return snapshot.HasWorkload(model.AddressType, query)
}

func selectSandboxResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	typeURL string,
	sub SubscriptionView,
) map[string]model.Resource {
	result := make(map[string]model.Resource)
	add := func(r model.Resource) {
		if sub.allows(r) {
			result[r.XDSName] = r
		}
	}
	if scope.Class == model.ClientEgressGateway || scope.Class == model.ClientAgentioEgress {
		if sub.Wildcard() {
			for _, r := range snapshot.List(typeURL) {
				add(r)
			}
		} else {
			for _, name := range sub.Names() {
				for _, r := range snapshot.Lookup(typeURL, name) {
					add(r)
				}
			}
		}
		return result
	}
	if typeURL == model.SandboxType && !sub.Wildcard() {
		for _, uid := range sub.Names() {
			if !sandboxVisible(scope, snapshot, uid) {
				continue
			}
			if r, ok := snapshot.Get(model.ResourceKey{TypeURL: typeURL, Name: uid}); ok {
				add(r)
			}
		}
		return result
	}
	for uid := range scopedSandboxNames(scope, snapshot) {
		if r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.SandboxType, Name: uid}); ok {
			add(r)
		}
	}
	return result
}
