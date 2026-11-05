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
	"sort"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// A previous complete result is usable during updates of the same source,
// but must not be inherited by an object recreated under the same resource key.
func matchesSource(resource model.Resource, source model.SourceReader) bool {
	if source == nil {
		return true
	}
	identity, found := source.Lookup(resource.Key)
	return found && identity.UID == resource.Facts.SourceIdentity.UID
}

// Pending initial demands remain subscribed until publication or cancellation.
// Do not wait in Generate: other keys and resource types share the same ADS
// stream. Never suppress withdrawal of an already sent resource, since that
// could retain access after an authorization change.
func deferUnpublishedRemovals(
	request GenerationRequest,
	delta *GeneratedDelta,
	source model.SourceReader,
) {
	if source == nil {
		return
	}
	removed := delta.Removed[:0]
	for _, name := range delta.Removed {
		if _, sent := request.Subscription.SentVersion(name); !sent {
			key := model.ResourceKey{TypeURL: request.TypeURL, Name: name}
			if _, found := source.Lookup(key); found {
				delta.pending = append(delta.pending, name)
				continue
			}
		}
		removed = append(removed, name)
	}
	delta.Removed = removed
}

func hasPendingConfigs(watches map[string]*watchState) bool {
	for _, watch := range watches {
		if len(watch.pending) > 0 {
			return true
		}
	}
	return false
}

// Source deletions can precede publication. Recheck deferred names affected by
// this notification using the same selection and authorization as initial demand.
func (s *Server) pushPendingConfigs(
	stream DeltaStream,
	scope model.ClientScope,
	connLog *agentlog.Logger,
	typeURL string,
	watch *watchState,
	snapshot model.ResourceSet,
	update xdsstore.Update,
) error {
	if len(watch.pending) == 0 {
		return nil
	}
	var names []string
	if update.FullFor(typeURL) {
		names = sortedNames(watch.pending)
	} else {
		for _, candidate := range update.Candidates(typeURL) {
			if watch.pending.Contains(candidate.Key.Name) {
				names = append(names, candidate.Key.Name)
			}
		}
		sort.Strings(names)
	}
	if len(names) == 0 {
		return nil
	}
	return s.generateAndSend(stream, connLog, watch, GenerationRequest{
		Scope:           scope,
		TypeURL:         typeURL,
		Subscription:    SubscriptionView{names: names},
		Snapshot:        snapshot,
		Full:            true,
		SubscribedNames: names,
	}, false, nil)
}
