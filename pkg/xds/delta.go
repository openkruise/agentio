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
	"sort"
	"strings"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/istio/pkg/util/sets"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
)

// pushOrder gives send calls a deterministic per-type order; it is not an ACK barrier.
var pushOrder = []string{
	model.ClusterType,
	model.EndpointType,
	model.ListenerType,
	model.RouteType,
	model.SecretType,
	model.SniTrafficPolicyType,
	model.AddressType,
	model.WorkloadType,
	model.WorkloadAuthorizationType,
	model.ExtensionConfigurationType,
	model.ProxyConfigType,
}

func (s *Server) handleRequest(stream DeltaStream,
	scope model.ClientScope, connLog *agentlog.Logger, watches map[string]*watchState, subscription ResourceSubscription,
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
		watches[typeURL] = watch
		subscription.Watch(typeURL)
	}
	initial := !watch.started

	// Subscription changes are applied before nonce checks: a stale nonce must
	// not drop a subscription carried in the same request.
	changed, err := applySubscription(watch, request)
	if err != nil {
		// A Delta server can only refuse over-limit subscriptions by closing
		// the stream.
		return status.Errorf(codes.ResourceExhausted, "subscribe to %s: %v", typeURL, err)
	}

	if detail := request.GetErrorDetail(); detail != nil {
		metrics.Default.RecordXDSNACK()
		connLog.Warn("xDS NACK", "principal", scope.Principal.String(),
			"type_url", typeURL, "code", codes.Code(detail.GetCode()).String(),
			"detail", detail.GetMessage())
	}
	if initial {
		if known {
			connLog.Debug("Delta ADS watch started", "client_class", scope.Class,
				"type_url", typeURL, "wildcard", watch.wildcard,
				"resources", len(watch.names), "initial_versions", len(request.GetInitialResourceVersions()))
		} else {
			connLog.Warn("Delta ADS client subscribed to unsupported type; returning an empty response",
				"client_class", scope.Class, "type_url", typeURL)
		}
	}

	// A nonce with an unchanged subscription is a pure acknowledgement; there
	// is nothing to send.
	explicitSecretSubscribe := typeURL == model.SecretType && len(request.GetResourceNamesSubscribe()) > 0
	if !changed && request.GetResponseNonce() != "" && !explicitSecretSubscribe {
		return nil
	}
	return s.sendDiffForNames(stream, scope, connLog, typeURL, watch, true, request.GetResourceNamesSubscribe())
}

func orderedWatchedTypes(watches map[string]*watchState, update Update) []string {
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
	update Update,
) error {
	for _, typeURL := range orderedWatchedTypes(watches, update) {
		watch := watches[typeURL]
		if update.FullFor(typeURL) {
			if err := s.sendDiff(stream, scope, connLog, typeURL, watch, false); err != nil {
				return err
			}
			continue
		}
		if err := s.sendDirty(stream, scope, connLog, typeURL, watch, update); err != nil {
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

func (s *Server) sendDiffForNames(stream DeltaStream,
	scope model.ClientScope, connLog *agentlog.Logger, typeURL string, watch *watchState, force bool, subscribedNames []string,
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

// sendDirty builds a Delta response directly from the KRT changes carried by
// the store update. Named and non-WDS watches leave sent state for every other
// key untouched; wildcard Address watches elide that state entirely.
func (s *Server) sendDirty(stream DeltaStream,
	scope model.ClientScope, connLog *agentlog.Logger, typeURL string, watch *watchState, update Update,
) error {
	request := GenerationRequest{
		Scope:        scope,
		TypeURL:      typeURL,
		Subscription: newDirtySubscriptionView(watch, typeURL, update),
		Snapshot:     update.After(),
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
		removed = nil
	}
	applyGenerationOutcomes(watch, request.Scope, connLog, delta)
	if len(resources) == 0 && len(removed) == 0 && !force {
		return nil
	}
	version := request.Update.Version()
	if request.Full {
		version = request.Snapshot.Version()
	}
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
		"type_url", request.TypeURL, "push", pushMode,
		"resources", len(resources), "removed", len(removed),
		"size", byteSize(sizeBytes), "duration", duration)
	if delta.elideSentState {
		// Replace, not clear, so a reconnect's InitialResourceVersions map does
		// not keep its backing array alive.
		watch.sent = make(map[string]string)
	} else {
		for _, name := range removed {
			delete(watch.sent, name)
		}
		for _, resource := range delta.Resources {
			watch.sent[resource.XDSName] = resource.Hash
		}
	}
	watch.nonce = nonce
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
	for _, resource := range resources {
		if resource.Key.TypeURL != typeURL || resource.Value == nil || resource.Value.GetTypeUrl() != typeURL {
			return nil, nil, fmt.Errorf("generator for %s returned resource %q with mismatched type URL", typeURL, resource.XDSName)
		}
		if strings.TrimSpace(resource.Key.Name) == "" || strings.TrimSpace(resource.XDSName) == "" || resource.Hash == "" {
			return nil, nil, fmt.Errorf("generator for %s returned a resource with an invalid name or version", typeURL)
		}
		if names.Contains(resource.XDSName) {
			return nil, nil, fmt.Errorf("generator for %s returned duplicate resource name %q", typeURL, resource.XDSName)
		}
		names.Insert(resource.XDSName)
		wire = append(wire, &discoveryv3.Resource{
			Name:     resource.XDSName,
			Aliases:  resource.Aliases,
			Version:  resource.Hash,
			Resource: resource.Value,
		})
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
	return wire, removed, nil
}

func applyGenerationOutcomes(watch *watchState, scope model.ClientScope, connLog *agentlog.Logger, delta GeneratedDelta) {
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
