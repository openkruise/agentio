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

// TrafficPolicyGenerator serves shared policies referenced by authorized
// Workloads. Named subscriptions never widen that scope.
type TrafficPolicyGenerator struct{}

func (TrafficPolicyGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.TrafficPolicyType {
		return GeneratedDelta{}, fmt.Errorf("traffic policy generator does not support type URL %q", request.TypeURL)
	}
	if request.Full || request.Update.FullFor(request.TypeURL) {
		selected := selectTrafficPolicyResources(request.Scope, request.Snapshot, request.Subscription)
		return diffSubscribed(request.Subscription, selected, request.SubscribedNames), nil
	}
	query, ok := trafficPolicyWorkloadQuery(request.Scope)
	return generateIncremental(request, func(resource model.Resource) bool {
		if !ok || !request.Subscription.allows(resource) {
			return false
		}
		query.TrafficPolicyReference = resource.Key.Name
		return request.Snapshot.HasWorkload(model.AddressType, query)
	}, nil), nil
}

func selectTrafficPolicyResources(
	scope model.ClientScope,
	snapshot model.ResourceSet,
	sub SubscriptionView,
) map[string]model.Resource {
	selected := make(map[string]model.Resource)
	query, ok := trafficPolicyWorkloadQuery(scope)
	if !ok {
		return selected
	}
	if !sub.Wildcard() {
		for _, name := range sub.Names() {
			for _, resource := range snapshot.Lookup(model.TrafficPolicyType, name) {
				query.TrafficPolicyReference = resource.Key.Name
				if sub.allows(resource) && snapshot.HasWorkload(model.AddressType, query) {
					selected[resource.XDSName] = resource
				}
			}
		}
		return selected
	}
	names := sets.New[string]()
	for _, workload := range snapshot.ListWorkloads(model.AddressType, query) {
		names.InsertAll(workload.Facts.Workload.TrafficPolicyRefs...)
	}
	for name := range names {
		if resource, ok := snapshot.Get(
			model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: name},
		); ok &&
			sub.allows(resource) {
			selected[resource.XDSName] = resource
		}
	}
	return selected
}

// Egress gateways consume Workload policies cluster-wide. Other clients use
// their authenticated node or Workload scope, not remote address visibility.
func trafficPolicyWorkloadQuery(scope model.ClientScope) (model.WorkloadQuery, bool) {
	if scope.Class == model.ClientEgressGateway || scope.Class == model.ClientAgentioEgress ||
		scope.Class == model.ClientResourceConsumer {
		return model.WorkloadQuery{TrafficPolicyRefsOnly: true}, true
	}
	return workloadScopeQuery(&scope)
}
