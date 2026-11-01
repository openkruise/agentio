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
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"istio.io/istio/pkg/util/sets"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// pushOrder gives send calls a deterministic per-type order; it is not an ACK barrier.
var pushOrder = []string{
	model.ClusterType,
	model.EndpointType,
	model.ListenerType,
	model.RouteType,
	model.SecretType,
	model.AddressType,
	model.WorkloadType,
	model.WorkloadAuthorizationType,
	model.TrafficPolicyType,
	model.SandboxType,
	model.ExtensionConfigurationType,
	model.ProxyConfigType,
}

func (s *Server) handleRequest(
	stream DeltaStream,
	scope model.ClientScope,
	connLog *agentlog.Logger,
	watches map[string]*watchState,
	subscription xdsstore.Subscription,
	request *discoveryv3.DeltaDiscoveryRequest,
) error {
	typeURL := request.GetTypeUrl()
	connLog.Debug("Delta ADS request", "type_url", typeURL,
		"sub", len(request.GetResourceNamesSubscribe()),
		"unsub", len(request.GetResourceNamesUnsubscribe()),
		"initial_versions", len(request.GetInitialResourceVersions()),
		"nonce", request.GetResponseNonce())
	known, allowed := typeAccess(scope.Class, typeURL)
	if known && !allowed {
		return status.Errorf(codes.PermissionDenied, "client class %s cannot subscribe to %s", scope.Class, typeURL)
	}
	watch := watches[typeURL]
	if watch == nil {
		watch = &watchState{names: sets.New[string](), sent: make(map[string]string)}
		switch typeURL {
		case model.ClusterType, model.EndpointType, model.ListenerType, model.RouteType,
			model.ExtensionConfigurationType, model.ProxyConfigType:
			watch.trackAcks = true
		}
		watches[typeURL] = watch
		subscription.Watch(typeURL)
	}
	initial := !watch.started

	// Subscription changes are applied before nonce checks: a stale nonce must
	// not drop a subscription carried in the same request.
	changed := applySubscription(watch, request)

	matched := watch.recordAcknowledgement(request)
	if nonce := request.GetResponseNonce(); nonce != "" && !matched {
		metrics.Default.RecordXDSStaleNonce()
		connLog.Debug("xDS stale acknowledgement", "type_url", typeURL,
			"nonce", nonce, "nonce_sent", watch.nonceSent)
	}
	if detail := request.GetErrorDetail(); detail != nil {
		// Keep counting all received NACKs, including late ones, without letting
		// a late rejection overwrite the latest response's acknowledgement state.
		metrics.Default.RecordXDSNACK()
		connLog.Warn("xDS NACK", "principal", scope.Principal.String(),
			"type_url", typeURL, "nonce", request.GetResponseNonce(),
			"nonce_sent", watch.nonceSent, "matched", matched,
			"code", codes.Code(detail.GetCode()).String(), "detail", detail.GetMessage())
	} else if matched {
		metrics.Default.RecordXDSACK()
		connLog.Debug("xDS ACK", "type_url", typeURL, "nonce", watch.nonceAcked)
	}

	if initial {
		if known {
			connLog.Debug("Delta ADS watch started",
				"type_url", typeURL, "wildcard", watch.wildcard,
				"resources", len(watch.names), "initial_versions", len(request.GetInitialResourceVersions()))
		} else {
			connLog.Warn("Delta ADS client subscribed to unsupported type; returning an empty response",
				"type_url", typeURL)
		}
	}

	// Explicit subscriptions request retransmission after client eviction.
	// Pure ACK/NACKs do not retry unchanged configuration.
	if !changed && request.GetResponseNonce() != "" && len(request.GetResourceNamesSubscribe()) == 0 {
		return nil
	}
	if generator, ok := s.generator(typeURL).(*SDSGenerator); ok {
		if watch.sds == nil {
			watch.sds = newSDSSession(stream.Context(), generator, scope)
		}
		snapshot := s.resources.Snapshot()
		staticNames := staticSDSNames(snapshot, scope)
		var demand, staticDemand []string
		unsubscribed := sets.New(request.GetResourceNamesUnsubscribe()...)
		for _, name := range request.GetResourceNamesSubscribe() {
			if unsubscribed.Contains(name) {
				continue
			}
			if staticNames.Contains(name) {
				// Ordinary Secrets use the current snapshot synchronously, outside
				// the on-demand signing queue and its authorization lifecycle.
				staticDemand = append(staticDemand, name)
				continue
			}
			// Envoy re-subscribes held resources on a new stream. Restore history
			// without turning it into cold signing demand.
			if _, restored := request.GetInitialResourceVersions()[name]; initial && restored {
				continue
			}
			demand = append(demand, name)
		}
		watch.sds.subscribe(demand)
		watch.sds.unsubscribe(request.GetResourceNamesUnsubscribe())
		watch.sds.start(snapshot)
		if initial || len(staticDemand) > 0 {
			view := newSubscriptionView(watch)
			// Validate every retained version before asynchronous replacements finish.
			return s.generateAndSend(stream, connLog, watch, GenerationRequest{
				Scope:           scope,
				TypeURL:         typeURL,
				Subscription:    view,
				Snapshot:        snapshot,
				Full:            true,
				SubscribedNames: staticDemand,
			}, initial && len(watch.sds.jobs) == 0)
		}
		return nil
	}
	if !initial && !watch.wildcard &&
		(scope.Class == model.ClientEgressGateway || scope.Class == model.ClientAgentioEgress) {
		snapshot := s.resources.Snapshot()
		if view, ok := demandReconciliationView(snapshot, typeURL, scope, watch,
			request.GetResourceNamesSubscribe(), request.GetResourceNamesUnsubscribe()); ok {
			return s.generateAndSend(stream, connLog, watch, GenerationRequest{
				Scope:           scope,
				TypeURL:         typeURL,
				Subscription:    view,
				Snapshot:        snapshot,
				Full:            true,
				SubscribedNames: append([]string(nil), request.GetResourceNamesSubscribe()...),
			}, true)
		}
	}
	return s.sendDiffForNames(stream, scope, connLog, typeURL, watch, true, request.GetResourceNamesSubscribe())
}

func orderedWatchedTypes(watches map[string]*watchState, update xdsstore.Update) []string {
	result := make([]string, 0, len(watches))
	added := sets.NewWithLength[string](len(watches))
	for _, typeURL := range pushOrder {
		if watch := watches[typeURL]; watch != nil && watch.started && update.Affects(typeURL) {
			result = append(result, typeURL)
			added.Insert(typeURL)
		}
	}
	remaining := make([]string, 0)
	for typeURL, watch := range watches {
		if watch == nil || !watch.started || !update.Affects(typeURL) {
			continue
		}
		if !added.Contains(typeURL) {
			remaining = append(remaining, typeURL)
		}
	}
	sort.Strings(remaining)
	return append(result, remaining...)
}

func (s *Server) pushUpdate(
	stream DeltaStream,
	scope model.ClientScope,
	connLog *agentlog.Logger,
	watches map[string]*watchState,
	update xdsstore.Update,
) error {
	snapshot := s.resources.Snapshot()
	for _, typeURL := range orderedWatchedTypes(watches, update) {
		watch := watches[typeURL]
		full := update.FullFor(typeURL)
		var subscription SubscriptionView
		if full {
			subscription = newSubscriptionView(watch)
		} else {
			subscription = newIncrementalSubscriptionView(watch, typeURL, update)
		}
		if err := s.generateAndSend(stream, connLog, watch, GenerationRequest{
			Scope:        scope,
			TypeURL:      typeURL,
			Subscription: subscription,
			Snapshot:     snapshot,
			Update:       update,
			Full:         full,
		}, false); err != nil {
			return err
		}
		if err := s.pushPendingConfigs(stream, scope, connLog, typeURL, watch, snapshot, update); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) sendDiff(stream DeltaStream,
	scope model.ClientScope, connLog *agentlog.Logger, typeURL string, watch *watchState, force bool,
) error {
	return s.sendDiffForNames(stream, scope, connLog, typeURL, watch, force, nil)
}

func (s *Server) sendDiffForNames(
	stream DeltaStream,
	scope model.ClientScope,
	connLog *agentlog.Logger,
	typeURL string,
	watch *watchState,
	force bool,
	subscribedNames []string,
) error {
	snapshot := s.resources.Snapshot()
	return s.generateAndSend(stream, connLog, watch, GenerationRequest{
		Scope:           scope,
		TypeURL:         typeURL,
		Subscription:    newSubscriptionView(watch),
		Snapshot:        snapshot,
		Full:            true,
		SubscribedNames: append([]string(nil), subscribedNames...),
	}, force)
}

// sendIncremental reselects candidates from the current snapshot. Named and
// non-WDS watches leave sent state for every other key untouched; wildcard Address watches elide that state entirely.
func (s *Server) sendIncremental(stream DeltaStream,
	scope model.ClientScope, connLog *agentlog.Logger, typeURL string, watch *watchState, update xdsstore.Update,
) error {
	subscriptionView := newIncrementalSubscriptionView(watch, typeURL, update)
	request := GenerationRequest{
		Scope:        scope,
		TypeURL:      typeURL,
		Subscription: subscriptionView,
		Snapshot:     s.resources.Snapshot(),
		Update:       update,
	}
	return s.generateAndSend(stream, connLog, watch, request, false)
}

func (s *Server) generateAndSend(
	stream DeltaStream,
	connLog *agentlog.Logger,
	watch *watchState,
	request GenerationRequest,
	force bool,
) error {
	started := time.Now()
	if watch.recovering {
		if !request.Full {
			relevant := slices.ContainsFunc(
				request.Update.Candidates(request.TypeURL),
				func(candidate xdsstore.Candidate) bool {
					resource, found := request.Snapshot.Get(candidate.Key)
					if found && scopeAllows(request.Scope, resource) {
						return true
					}
					// Retain withdrawals and ownership transfers, including intermediate owners.
					return slices.ContainsFunc(candidate.Identities, func(identity xdsstore.Identity) bool {
						return scopeAllows(request.Scope, model.Resource{Key: candidate.Key, Facts: identity.Facts})
					})
				},
			)
			if !relevant {
				return nil
			}
		}
		// Include uncertain removals while retaining already accepted versions.
		request.Full = true
		request.Subscription = newSubscriptionView(watch)
		for name := range watch.pendingAcks {
			request.Subscription.sent[name] = ""
		}
	}
	if q := watch.sds; q != nil {
		staticNames := staticSDSNames(request.Snapshot, q.scope)
		// Publishing a static Secret supersedes same-name issuance, even if the
		// static resource is later removed before the old worker finishes.
		q.unsubscribe(staticNames.UnsortedList())
		// A removal tears down Envoy's pending certificate request. Keep real
		// demand alive during rotation; its worker will replace the certificate.
		if request.Full && q.generator.provider.SignerRevision() != "" &&
			q.generator.provider.Authorize(q.scope) == nil {
			for name := range q.jobs {
				delete(request.Subscription.sent, name)
			}
		}
	}
	delta, err := s.generator(request.TypeURL).Generate(stream.Context(), request)
	if err != nil {
		metrics.Default.RecordXDSPushFailure(metrics.XDSPushFailureGenerate, request.TypeURL)
		logPushFailure(connLog, "generate", request.TypeURL, started, err)
		return err
	}
	return s.sendGeneratedDelta(stream, connLog, watch, request, delta, force, started)
}

func (s *Server) sendGeneratedDelta(
	stream DeltaStream,
	connLog *agentlog.Logger,
	watch *watchState,
	request GenerationRequest,
	delta GeneratedDelta,
	force bool,
	started time.Time,
) error {
	resources, removed, err := validateGeneratedDelta(request.TypeURL, delta)
	if err != nil {
		metrics.Default.RecordXDSPushFailure(metrics.XDSPushFailureValidate, request.TypeURL)
		logPushFailure(connLog, "validate", request.TypeURL, started, err)
		return err
	}
	if request.TypeURL == model.ExtensionConfigurationType {
		// https://github.com/envoyproxy/envoy/issues/32823: Envoy must garbage
		// collect extensions when they become unreferenced rather than have them
		// deleted immediately, so ECDS never sends removals. Sent state is kept
		// because Envoy retains the extension.
		if len(removed) > 0 {
			watch.indexPendingResponse()
		}
		for _, name := range removed {
			delete(watch.pendingAcks, name)
		}
		if len(watch.pendingAcks) == 0 {
			watch.recovering = false
		}
		removed = nil
	}
	applyGenerationOutcomes(watch, request.Scope, connLog, delta)
	if len(delta.pending) > 0 {
		if watch.pending == nil {
			watch.pending = sets.New[string]()
		}
		watch.pending.InsertAll(delta.pending...)
	}
	if len(resources) == 0 && len(removed) == 0 && !force {
		return nil
	}
	version := request.Snapshot.Version()
	nonce := fmt.Sprintf("%d", s.nonce.Add(1))
	response := &discoveryv3.DeltaDiscoveryResponse{
		SystemVersionInfo: version,
		TypeUrl:           request.TypeURL,
		Nonce:             nonce,
		Resources:         resources,
		RemovedResources:  removed,
	}
	sizeBytes := responseResourceSize(resources)
	defer func() {
		metrics.Default.RecordLegacyXDSPush(time.Since(started), sizeBytes)
	}()
	if err := stream.Send(response); err != nil {
		metrics.Default.RecordXDSPushFailure(metrics.XDSPushFailureSend, request.TypeURL)
		logPushFailure(connLog, "send", request.TypeURL, started, err)
		return err
	}
	for _, name := range removed {
		watch.pending.Delete(name)
	}
	for _, resource := range resources {
		watch.pending.Delete(resource.Name)
	}
	duration := time.Since(started)
	metrics.Default.RecordXDSPush(duration, len(resources)+len(removed), sizeBytes)
	pushLog := connLog.Debug
	if request.Full && (len(resources) > 0 || len(removed) > 0) {
		pushLog = connLog.Info
	}
	pushMode := "incremental"
	if request.Full {
		pushMode = "full"
	}
	pushLog("Delta ADS push", "principal", request.Scope.Principal.String(),
		"type_url", request.TypeURL, "push", pushMode, "version", version,
		"resources", len(resources), "removed", len(removed),
		"size", byteSize(sizeBytes), "duration", duration,
		"nonce_sent", nonce, "nonce_acked", watch.nonceAcked,
		"nonce_nacked", watch.nonceNacked, "last_error", watch.lastError,
		"last_error_code", watch.lastErrorCode.String())
	if delta.elideSentState {
		// Replace, not clear, so a reconnect's InitialResourceVersions map does
		// not keep its backing array alive.
		watch.sent = make(map[string]string)
	} else {
		for _, name := range removed {
			delete(watch.sent, name)
		}
		for _, resource := range resources {
			watch.sent[resource.Name] = resource.Version
		}
	}
	if watch.trackAcks {
		// A delivery covering the same names fully supersedes the previous one.
		if pending := watch.pendingResponse; pending != nil &&
			slices.EqualFunc(pending.Resources, resources, func(a, b *discoveryv3.Resource) bool {
				return a.Name == b.Name
			}) && slices.Equal(pending.RemovedResources, removed) {
			watch.pendingResponse = nil
		}
		watch.indexPendingResponse()
		if len(watch.pendingAcks) == 0 {
			watch.pendingResponse = response
		} else {
			for _, resource := range resources {
				watch.pendingAcks[resource.Name] = nonce
			}
			for _, name := range removed {
				watch.pendingAcks[name] = nonce
			}
		}
	}
	watch.nonceSent = nonce
	return nil
}

func logPushFailure(connLog *agentlog.Logger, stage, typeURL string, started time.Time, err error) {
	attrs := []any{"stage", stage, "type_url", typeURL, "duration", time.Since(started), "error", err}
	if expectedStreamError(err) {
		connLog.Debug("Delta ADS push failed", attrs...)
		return
	}
	connLog.Warn("Delta ADS push failed", attrs...)
}

func responseResourceSize(resources []*discoveryv3.Resource) int {
	size := 0
	for _, resource := range resources {
		if resource == nil || resource.GetResource() == nil {
			continue
		}
		size += len(resource.GetResource().GetValue())
	}
	return size
}

func byteSize(bytes int) string {
	const unit = 1000
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	value, suffix := float64(bytes)/unit, "kB"
	if value >= unit {
		value, suffix = value/unit, "MB"
	}
	if value >= unit {
		value, suffix = value/unit, "GB"
	}
	return fmt.Sprintf("%.1f%s", value, suffix)
}

func validateGeneratedDelta(typeURL string, delta GeneratedDelta) ([]*discoveryv3.Resource, []string, error) {
	resources := append([]model.Resource(nil), delta.Resources...)
	sort.Slice(resources, func(i, j int) bool { return resources[i].XDSName < resources[j].XDSName })
	wire := make([]*discoveryv3.Resource, 0, len(resources))
	names := sets.NewWithLength[string](len(resources))
	var expired []string
	for _, resource := range resources {
		if resource.Key.TypeURL != typeURL || resource.Value == nil || resource.Value.GetTypeUrl() != typeURL {
			return nil, nil, fmt.Errorf(
				"generator for %s returned resource %q with mismatched type URL",
				typeURL,
				resource.XDSName,
			)
		}
		if strings.TrimSpace(resource.Key.Name) == "" || strings.TrimSpace(resource.XDSName) == "" ||
			resource.Hash == "" {
			return nil, nil, fmt.Errorf("generator for %s returned a resource with an invalid name or version", typeURL)
		}
		if names.Contains(resource.XDSName) {
			return nil, nil, fmt.Errorf(
				"generator for %s returned duplicate resource name %q",
				typeURL,
				resource.XDSName,
			)
		}
		names.Insert(resource.XDSName)
		item := &discoveryv3.Resource{
			Name:     resource.XDSName,
			Aliases:  resource.Aliases,
			Version:  resource.Hash,
			Resource: resource.Value,
		}
		if version, ok := delta.versions[resource.XDSName]; ok {
			item.Version = version
		}
		if deadline, ok := delta.expiresAt[resource.XDSName]; ok {
			ttl := time.Until(deadline)
			if ttl <= 0 {
				expired = append(expired, resource.XDSName)
				continue
			}
			item.Ttl = durationpb.New(ttl)
		}
		wire = append(wire, item)
	}
	removed := append([]string(nil), delta.Removed...)
	sort.Strings(removed)
	for index, name := range removed {
		if strings.TrimSpace(name) == "" {
			return nil, nil, fmt.Errorf("generator for %s returned an empty removed resource name", typeURL)
		}
		if index > 0 && removed[index-1] == name {
			return nil, nil, fmt.Errorf("generator for %s returned duplicate removed resource name %q", typeURL, name)
		}
		if names.Contains(name) {
			return nil, nil, fmt.Errorf("generator for %s both generated and removed resource %q", typeURL, name)
		}
	}
	removed = append(removed, expired...)
	sort.Strings(removed)
	return wire, removed, nil
}

func applyGenerationOutcomes(
	watch *watchState,
	scope model.ClientScope,
	connLog *agentlog.Logger,
	delta GeneratedDelta,
) {
	for _, name := range delta.allowed {
		watch.denied.Delete(name)
	}
	for _, denial := range delta.denied {
		if watch.denied == nil {
			watch.denied = sets.New[string]()
		}
		if watch.denied.Contains(denial.name) {
			continue
		}
		watch.denied.Insert(denial.name)
		metrics.Default.RecordXDSDeniedResource()
		connLog.Warn("omitting resource", "resource", denial.name,
			"principal", scope.Principal.String(), "error", denial.err)
	}
}
