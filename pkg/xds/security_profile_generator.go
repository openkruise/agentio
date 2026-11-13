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

	"github.com/openkruise/agentio/pkg/model"
)

// SecurityProfileGenerator serves HTTP and connection policies to EPE and gateways.
type SecurityProfileGenerator struct{}

// Generate returns the requested SecurityProfiles visible to an EPE client.
func (SecurityProfileGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL != model.SecurityProfileType {
		return GeneratedDelta{}, fmt.Errorf("unsupported security profile type %q", request.TypeURL)
	}
	visible := func(resource model.Resource) bool {
		return (request.Scope.Class == model.ClientEPE ||
			(request.Scope.Class == model.ClientAgentioEgress || request.Scope.Class == model.ClientEgressGateway) && request.Snapshot.HasReference(resource.Key)) && request.Subscription.allows(resource)
	}
	if !request.Full && !request.Update.FullFor(request.TypeURL) {
		return generateIncremental(request, visible, nil, nil), nil
	}
	selected := map[string]model.Resource{}
	if request.Scope.Class == model.ClientEPE || request.Scope.Class == model.ClientAgentioEgress ||
		request.Scope.Class == model.ClientEgressGateway {
		if request.Subscription.Wildcard() {
			for _, resource := range request.Snapshot.List(request.TypeURL) {
				if visible(resource) {
					selected[resource.XDSName] = resource
				}
			}
		} else {
			for _, name := range request.Subscription.Names() {
				for _, resource := range request.Snapshot.Lookup(request.TypeURL, name) {
					if visible(resource) {
						selected[resource.XDSName] = resource
					}
				}
			}
		}
	}
	return diffSubscribed(request.Subscription, selected, request.SubscribedNames), nil
}
