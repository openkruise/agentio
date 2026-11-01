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
	"maps"
	"slices"
	"sort"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

type watchState struct {
	sds      *sdsSession
	wildcard bool
	names    sets.Set[string]
	sent     map[string]string
	started  bool
	// Nonces are scoped to this stream and resource type. nonceSent advances
	// only after Send succeeds; diagnostics only accept that exact nonce.
	nonceSent   string
	nonceAcked  string
	nonceNacked string
	// A later send leaves the previous rejection available until a matching ACK.
	// nonceNacked == nonceSent identifies a rejection of the latest response.
	lastError     string
	lastErrorCode codes.Code
	// A single outstanding response needs no per-resource index. Overlapping
	// sends and NACKs materialize the latest unacknowledged nonce for each name.
	trackAcks       bool
	pendingResponse *discoveryv3.DeltaDiscoveryResponse
	pendingAcks     map[string]string
	recovering      bool
	// denied tracks refused names so each refusal is logged once per stream.
	denied sets.Set[string]
	// pending contains initial demands deferred until publication or source removal.
	pending sets.Set[string]
}

// recordAcknowledgement resolves outstanding resource deliveries and only lets
// the latest response update acknowledgement diagnostics. Subscription changes
// are handled independently.
func (watch *watchState) recordAcknowledgement(request *discoveryv3.DeltaDiscoveryRequest) bool {
	nonce := request.GetResponseNonce()
	if nonce == "" {
		return false
	}
	if response := watch.pendingResponse; response != nil && response.Nonce == nonce {
		if request.GetErrorDetail() == nil {
			watch.pendingResponse = nil
		} else {
			watch.indexPendingResponse()
		}
	}
	// Late replies still resolve their outstanding resources. A newer response
	// may only cover some names from a rejected batch; its ACK cannot accept the
	// rest. Superseded deliveries no longer need a separate response history.
	for name, pendingNonce := range watch.pendingAcks {
		if pendingNonce != nonce {
			continue
		}
		if request.GetErrorDetail() != nil {
			watch.recovering = true
		} else {
			delete(watch.pendingAcks, name)
		}
	}
	if len(watch.pendingAcks) == 0 {
		watch.recovering = false
	}
	if nonce != watch.nonceSent {
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

func (watch *watchState) indexPendingResponse() {
	response := watch.pendingResponse
	if response == nil {
		return
	}
	if watch.pendingAcks == nil {
		watch.pendingAcks = make(map[string]string, len(response.Resources)+len(response.RemovedResources))
	}
	for _, resource := range response.Resources {
		watch.pendingAcks[resource.Name] = response.Nonce
	}
	for _, name := range response.RemovedResources {
		watch.pendingAcks[name] = response.Nonce
	}
	watch.pendingResponse = nil
}

func sortedNames(names sets.Set[string]) []string {
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func applySubscription(watch *watchState, request *discoveryv3.DeltaDiscoveryRequest) bool {
	changed := !watch.started
	if !watch.started {
		watch.started = true
		// Cached wildcard versions are not explicit named subscriptions.
		watch.wildcard = slices.Contains(request.GetResourceNamesSubscribe(), "*") ||
			(len(request.GetResourceNamesSubscribe()) == 0 && implicitWildcardTypeURL(request.GetTypeUrl()))
		maps.Copy(watch.sent, request.GetInitialResourceVersions())
		if !watch.wildcard {
			for name := range request.GetInitialResourceVersions() {
				watch.names.Insert(name)
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
		watch.names.Insert(name)
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
		watch.pending.Delete(name)
		// Unsubscribing is not a deletion; a late removal could fail a new demand.
		delete(watch.sent, name)
		watch.indexPendingResponse()
		delete(watch.pendingAcks, name)
	}
	if len(watch.pendingAcks) == 0 {
		watch.recovering = false
	}
	return changed
}

func implicitWildcardTypeURL(typeURL string) bool {
	switch typeURL {
	case model.SecretType, model.EndpointType, model.RouteType, model.ExtensionConfigurationType:
		return false
	default:
		return true
	}
}

// SubscriptionView is the immutable subscription scope visible to a resource
// generator. Its accessors never expose the Delta stream's live maps.
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

// demandSubscriptionView reconciles only explicitly requested resources,
// including unique Workload aliases and missing names. Empty sent state forces
// a reply after client eviction. Ambiguous aliases and Service expansion still
// use the complete selection; other subscriptions retain their sent versions.
func demandSubscriptionView(snapshot model.ResourceSet, typeURL string, names []string) (SubscriptionView, bool) {
	if len(names) == 0 {
		return SubscriptionView{}, false
	}
	lookupType := typeURL
	switch typeURL {
	case model.WorkloadType:
		lookupType = model.AddressType
	case model.TrafficPolicyType, model.SandboxType:
	default:
		return SubscriptionView{}, false
	}
	for _, name := range names {
		if name == "*" {
			return SubscriptionView{}, false
		}
		resources := snapshot.Lookup(lookupType, name)
		if len(resources) == 0 {
			continue
		}
		if len(resources) != 1 ||
			(typeURL == model.WorkloadType && !resources[0].IsWorkloadAddress()) ||
			(typeURL != model.WorkloadType && resources[0].XDSName != name) {
			return SubscriptionView{}, false
		}
	}
	return SubscriptionView{names: sortedNames(sets.New(names...))}, true
}

// demandReconciliationView also limits cache-eviction reconciliation to the
// affected Workloads and canonical TrafficPolicies. Remaining aliases and Service
// subscriptions can keep a canonical resource selected after a name is unsubscribed.
func demandReconciliationView(snapshot model.ResourceSet, typeURL string, scope model.ClientScope,
	watch *watchState, subscribed, unsubscribed []string,
) (SubscriptionView, bool) {
	view, ok := demandSubscriptionView(snapshot, typeURL, subscribed)
	if len(unsubscribed) == 0 {
		return view, ok
	}
	if typeURL == model.TrafficPolicyType && (len(subscribed) == 0 || ok) {
		for _, name := range unsubscribed {
			resources := snapshot.Lookup(typeURL, name)
			if name == "*" || containsSorted(view.names, name) || len(resources) != 1 ||
				resources[0].XDSName != name || len(resources[0].Aliases) != 0 {
				return SubscriptionView{}, false
			}
		}
		// applySubscription already forgot these canonical names and versions.
		// Reconcile only new demands; cache eviction must not rescan retained policies.
		return view, true
	}
	if typeURL != model.WorkloadType || (len(subscribed) > 0 && !ok) {
		return SubscriptionView{}, false
	}
	view.sent = make(map[string]string)
	names := sets.New(view.names...)
	selection := newAddressSelection(
		scope,
		snapshot,
		model.AddressType,
		SubscriptionView{},
	)
	for _, name := range unsubscribed {
		if name == "*" {
			return SubscriptionView{}, false
		}
		resources := snapshot.Lookup(model.AddressType, name)
		if len(resources) != 1 || !resources[0].IsWorkloadAddress() {
			return SubscriptionView{}, false
		}
		resource := resources[0]
		// Check live interests without sorting the entire subscription cache.
		if !selection.selectedByNames(resource, watch.names.Contains) {
			// An alias unsubscribe must forget the canonical sent state too.
			// Sending a removal could cancel a later demand for the same resource.
			delete(watch.sent, resource.XDSName)
			continue
		}
		if version, found := watch.sent[resource.XDSName]; found {
			view.sent[resource.XDSName] = version
		}
		names.Insert(resource.XDSName)
	}
	view.names = sortedNames(names)
	return view, true
}

// newIncrementalSubscriptionView copies sent versions only for affected wire
// identities. Subscription names still describe the complete selection, so
// aliases and dependency expansion cannot accidentally withdraw another match.
func newIncrementalSubscriptionView(watch *watchState, typeURL string, update xdsstore.Update) SubscriptionView {
	view := SubscriptionView{wildcard: watch.wildcard, names: sortedNames(watch.names), sent: make(map[string]string)}
	for _, candidate := range update.Candidates(typeURL) {
		for _, identity := range candidate.Identities {
			if version, found := watch.sent[identity.Name]; found {
				view.sent[identity.Name] = version
			}
		}
	}
	return view
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
