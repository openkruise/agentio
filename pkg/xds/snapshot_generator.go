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
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// SnapshotGenerator generates precompiled resources from store snapshots and incremental updates.
type SnapshotGenerator struct{}

// Generate selects visible snapshot resources and computes their subscription delta.
func (SnapshotGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if request.TypeURL == "" {
		return GeneratedDelta{}, fmt.Errorf("generation type URL is required")
	}
	if request.Full {
		return generateSnapshotDiff(request), nil
	}
	return generateSnapshotIncremental(request), nil
}

func generateSnapshotDiff(request GenerationRequest) GeneratedDelta {
	selected := make(map[string]model.Resource)
	for _, resource := range selectGeneric(
		request.Scope, request.Snapshot, request.TypeURL, selectionNames(request.Subscription),
	) {
		selected[resource.XDSName] = resource
	}
	if len(request.SubscribedNames) == 0 {
		return diffSelected(request.Subscription, selected)
	}
	subscribed := sets.New(request.SubscribedNames...)
	return diffResourceSelection(selected, request.Subscription.SentNames(), func(name string) (string, bool) {
		resource := selected[name]
		if resourceNamesMatch(resource, subscribed.Contains) {
			return "", false
		}
		return request.Subscription.SentVersion(name)
	})
}

func generateSnapshotIncremental(request GenerationRequest) GeneratedDelta {
	return generateIncremental(request, func(resource model.Resource) bool {
		return scopeAllows(request.Scope, resource) && request.Subscription.allows(resource)
	}, nil, func(identity *xdsstore.Identity) bool {
		return scopeAllows(request.Scope, model.Resource{
			Key:   model.ResourceKey{TypeURL: request.TypeURL},
			Facts: identity.Facts,
		})
	})
}
