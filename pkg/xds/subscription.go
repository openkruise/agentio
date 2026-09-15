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
	"errors"
	"maps"
	"slices"
	"sort"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// maxSubscriptionNames caps named subscriptions per watch to bound per-connection memory.
const maxSubscriptionNames = 10000

var errTooManySubscribedNames = errors.New("subscription exceeds the resource name limit")

type watchState struct {
	wildcard bool
	names    sets.Set[string]
	sent     map[string]string
	started  bool
	// Nonces are scoped to this stream and resource type. nonceSent advances
	// only after Send succeeds; ACK/NACK state only accepts that exact nonce.
	nonceSent   string
	nonceAcked  string
	nonceNacked string
	// A later send leaves the previous rejection available until a matching ACK.
	// nonceNacked == nonceSent identifies a rejection of the latest response.
	lastError     string
	lastErrorCode codes.Code
	// denied tracks refused names so each refusal is logged once per stream.
	denied sets.Set[string]
}

// recordAcknowledgement ignores spontaneous requests and acknowledgements of
// older or unknown responses. Subscription changes are handled independently.
func (watch *watchState) recordAcknowledgement(request *discoveryv3.DeltaDiscoveryRequest) bool {
	nonce := request.GetResponseNonce()
	if nonce == "" || nonce != watch.nonceSent {
		return false
	}
	if detail := request.GetErrorDetail(); detail != nil {
		watch.nonceNacked = nonce
		watch.lastError = detail.GetMessage()
		watch.lastErrorCode = codes.Code(detail.GetCode())
		if watch.nonceAcked == nonce {
			watch.nonceAcked = ""
		}
	} else {
		watch.nonceAcked = nonce
		watch.nonceNacked = ""
		watch.lastError = ""
		watch.lastErrorCode = codes.OK
	}
	return true
}

func sortedNames(names sets.Set[string]) []string {
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func applySubscription(watch *watchState, request *discoveryv3.DeltaDiscoveryRequest) (bool, error) {
	changed := !watch.started
	insertName := func(name string) error {
		if watch.names.Contains(name) {
			return nil
		}
		if len(watch.names) >= maxSubscriptionNames {
			return errTooManySubscribedNames
		}
		watch.names.Insert(name)
		return nil
	}
	if !watch.started {
		watch.started = true
		watch.wildcard = len(request.GetResourceNamesSubscribe()) == 0 && implicitWildcardTypeURL(request.GetTypeUrl())
		maps.Copy(watch.sent, request.GetInitialResourceVersions())
		if !watch.wildcard {
			for name := range request.GetInitialResourceVersions() {
				if err := insertName(name); err != nil {
					return changed, err
				}
			}
		}
	}
	for _, name := range request.GetResourceNamesSubscribe() {
		if name == "*" {
			if !watch.wildcard {
				changed = true
			}
			watch.wildcard = true
			continue
		}
		if !watch.names.Contains(name) {
			changed = true
		}
		if err := insertName(name); err != nil {
			return changed, err
		}
	}
	for _, name := range request.GetResourceNamesUnsubscribe() {
		if name == "*" {
			if watch.wildcard {
				changed = true
			}
			watch.wildcard = false
			continue
		}
		if watch.names.Contains(name) {
			changed = true
		}
		watch.names.Delete(name)
	}
	return changed, nil
}

func implicitWildcardTypeURL(typeURL string) bool {
	switch typeURL {
	case model.SecretType, model.EndpointType, model.RouteType, model.ExtensionConfigurationType:
		return false
	default:
		return true
	}
}

// SubscriptionView is an immutable copy of the subscription state visible to a
// resource generator. Its accessors never expose the Delta stream's live maps.
type SubscriptionView struct {
	wildcard bool
	names    []string
	sent     map[string]string
}

func newSubscriptionView(watch *watchState) SubscriptionView {
	names := sortedNames(watch.names)
	sent := make(map[string]string, len(watch.sent))
	maps.Copy(sent, watch.sent)
	return SubscriptionView{wildcard: watch.wildcard, names: names, sent: sent}
}

func newIncrementalSubscriptionView(watch *watchState, typeURL string, update xdsstore.Update) SubscriptionView {
	view := SubscriptionView{
		wildcard: watch.wildcard,
		names:    sortedNames(watch.names),
		sent:     make(map[string]string),
	}
	var changes []model.ResourceChange
	if view.wildcard {
		changes = update.ReadOnlyChangesForType(typeURL)
	} else {
		changes = update.ChangesForNames(typeURL, view.names)
	}
	copySentForChanges(&view, watch, changes)
	return view
}

func copySentForChanges(view *SubscriptionView, watch *watchState, changes []model.ResourceChange) {
	copySent := func(resource *model.Resource) {
		if resource == nil {
			return
		}
		if version, found := watch.sent[resource.XDSName]; found {
			view.sent[resource.XDSName] = version
		}
	}
	for _, change := range changes {
		copySent(change.Old)
		copySent(change.New)
	}
}

// Wildcard reports whether every resource of this type is subscribed.
func (s SubscriptionView) Wildcard() bool {
	return s.wildcard
}

// Names returns the explicitly subscribed names in lexical order.
func (s SubscriptionView) Names() []string {
	result := make([]string, len(s.names))
	copy(result, s.names)
	return result
}

// SentVersion returns the version last sent successfully for a wire name.
func (s SubscriptionView) SentVersion(name string) (string, bool) {
	version, found := s.sent[name]
	return version, found
}

// SentNames returns successfully sent wire names in lexical order.
func (s SubscriptionView) SentNames() []string {
	result := make([]string, 0, len(s.sent))
	for name := range s.sent {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func (s SubscriptionView) allows(resource model.Resource) bool {
	if s.wildcard {
		return true
	}
	if containsSorted(s.names, resource.XDSName) {
		return true
	}
	for _, alias := range resource.Aliases {
		if containsSorted(s.names, alias) {
			return true
		}
	}
	return false
}

func containsSorted(values []string, value string) bool {
	_, found := slices.BinarySearch(values, value)
	return found
}
