// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Package attributes resolves Envoy attributes — the request pseudo-headers,
// source identity and filter state — into the per-request context the engine
// consumes. Nothing here is expression-visible; the expression vocabulary
// lives in the inputs package.
package attributes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/types"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/labels"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

const (
	// ExtProcAttrsKey is the top-level key under which Envoy delivers the
	// ext_proc filter attributes.
	ExtProcAttrsKey = "envoy.filters.http.ext_proc"

	FilterStateDownstreamPeerName      = "filter_state['downstream_peer'].name"
	FilterStateDownstreamPeerNamespace = "filter_state['downstream_peer'].namespace"
	// FilterStateWorkloadName carries the source pod name captured on HBONE CONNECT.
	FilterStateWorkloadName = "filter_state['agentio.workload.name']"
	// FilterStateWorkloadNamespace carries the source pod namespace captured on HBONE CONNECT.
	FilterStateWorkloadNamespace = "filter_state['agentio.workload.namespace']"
	// AttrSourceAddress is Envoy's standard CEL attribute for the
	// connection peer (the calling Sandbox pod, from the egress gateway's
	// perspective). It is delivered as "<ip>:<port>"; only the IP half is
	// what we want, so callers strip the trailing port. The egress
	// gateway must list "source.address" in its ext_proc
	// request_attributes for this to be populated.
	AttrSourceAddress         = "source.address"
	FilterStateWorkloadLabels = "filter_state['agentio.workload.labels']"
	// FilterStateSandboxLabels is the legacy label attribute used during rolling upgrades.
	FilterStateSandboxLabels = "filter_state['sandbox.labels']"
	FilterStateSandboxToken  = "filter_state['sandbox.token']"

	AttrDestinationPort    = "destination.port"
	AttrDestinationAddress = "destination.address"
)

// Extract resolves the Envoy ext-proc headers message and its attributes
// into the per-request Peer (caller identity and credential) and
// httpreq.HTTPRequest. For ordinary requests, the Envoy-authenticated
// destination.port overrides the authority port so a forged Host cannot evade
// port policy. CONNECT is the exception: its authority names the tunnel target
// while destination.port names the explicit proxy, so the target authority
// port is retained. When pod identity is missing from filter_state it returns a
// partial Peer and a zero HTTPRequest; callers must check Peer.Valid and decide
// the disposition (the ext-proc server passes such requests through unless its
// fail-closed switch is set). A malformed sandbox token leaves Peer.Token nil.
// Log lines use the logger from ctx, so request-scoped key/values are carried
// on them.
func Extract(
	ctx context.Context,
	headers *extProcPb.HttpHeaders,
	attrs map[string]*structpb.Struct,
) (filter.Peer, httpreq.HTTPRequest) {
	logger := log.FromContext(ctx)
	loggerD := logger.V(logging.DEBUG)

	podNamespace := extractFilterStateString(attrs, FilterStateWorkloadNamespace)
	if podNamespace == "" {
		podNamespace = extractFilterStateString(attrs, FilterStateDownstreamPeerNamespace)
	}
	podName := extractFilterStateString(attrs, FilterStateWorkloadName)
	if podName == "" {
		podName = extractFilterStateString(attrs, FilterStateDownstreamPeerName)
	}
	peer := filter.Peer{
		Pod: types.NamespacedName{Namespace: podNamespace, Name: podName},
		IP:  extractPodIP(attrs),
	}
	labelsKey := FilterStateWorkloadLabels
	if _, present := attrs[ExtProcAttrsKey].GetFields()[labelsKey]; !present {
		labelsKey = FilterStateSandboxLabels
	}
	workloadLabelsEncoded := extractFilterStateString(attrs, labelsKey)

	if podNamespace == "" || podName == "" {
		// Envoy must supply the captured workload headers or legacy peer
		// metadata. Without a complete identity the caller decides the
		// disposition and logs it at the operator-visible level.
		loggerD.Info("pod identity missing from filter_state",
			"podNamespace", podNamespace, "podName", podName)
		return peer, httpreq.HTTPRequest{}
	}

	// Workload labels use the new attribute when present, including empty values.
	// Both attribute names carry the same base64-encoded
	// "k1=v1,k2=v2" string.
	podLabels := labels.ParseSandboxLabels(workloadLabelsEncoded)
	if workloadLabelsEncoded != "" && len(podLabels) == 0 {
		loggerD.Info("workload labels were present but failed to decode", "attribute", labelsKey)
	}
	// Guarded: Go builds the key-value slice at the call site, before Info can
	// check the level and drop it, so an unguarded line costs an allocation on
	// every request even with DEBUG off.
	if loggerD.Enabled() {
		loggerD.Info("extracted pod info from attributes",
			"pod", podName, "namespace", podNamespace, "labels", podLabels)
	}
	peer.Labels = podLabels

	peer.Token = parseSandboxToken(ctx, extractFilterStateString(attrs, FilterStateSandboxToken))

	req := parseHTTPRequest(ctx, extractHeaderMap(headers))

	// For ordinary requests, prefer the real TCP destination port observed by
	// Envoy. A CONNECT authority is different: it is the RFC-defined tunnel
	// target, while destination.port is only the explicit proxy's listener.
	if dstPort := extractAttributeInt(
		attrs,
		AttrDestinationPort,
	); !strings.EqualFold(req.Method, "CONNECT") && dstPort > 0 &&
		dstPort <= 65535 {
		req.Port = int32(dstPort)
	}
	if !strings.EqualFold(req.Method, "CONNECT") {
		req.OriginalDestination = extractOriginalDestination(attrs)
		if req.OriginalDestination.IsValid() {
			req.Port = int32(req.OriginalDestination.Port())
		}
	}

	return peer, req
}

// destination.address is Envoy's restored downstream local IP:port, not a
// client header. Also accept an IP with a separate destination.port attribute.
// CONNECT is excluded by the caller because its local address is the proxy.
func extractOriginalDestination(attrs map[string]*structpb.Struct) netip.AddrPort {
	raw := extractFilterStateString(attrs, AttrDestinationAddress)
	port := extractAttributeInt(attrs, AttrDestinationPort)
	address, err := netip.ParseAddrPort(raw)
	if err != nil {
		ip, ipErr := netip.ParseAddr(raw)
		if ipErr != nil || port <= 0 || port > 65535 {
			return netip.AddrPort{}
		}
		address = netip.AddrPortFrom(ip, uint16(port))
	}
	if address.Port() == 0 || address.Addr().Zone() != "" ||
		(port != 0 && (port < 0 || port > 65535 || port != int64(address.Port()))) {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
}

// parseSandboxToken parses the raw filter_state['sandbox.token'] string:
// base64-decoded JSON, falling back to raw JSON when the value is not valid
// base64. On success the parsed token is returned; on failure a DEBUG line
// is logged and nil is returned. Returns nil when the raw value is empty.
func parseSandboxToken(ctx context.Context, raw string) *filter.SandboxToken {
	if raw == "" {
		return nil
	}
	tokenJSON, decErr := base64.StdEncoding.DecodeString(raw)
	if decErr != nil {
		tokenJSON = []byte(raw)
	}
	var st filter.SandboxToken
	if err := json.Unmarshal(tokenJSON, &st); err != nil {
		log.FromContext(ctx).V(logging.DEBUG).Info("failed to parse sandbox.token", "error", err)
		return nil
	}
	return &st
}

// extractPodIP returns the caller pod IP from Envoy's source.address
// attribute, delivered as "<ip>:<port>"; only the IP half is returned.
// Returns an empty string when the attribute is absent or unparseable.
func extractPodIP(attrs map[string]*structpb.Struct) string {
	raw := extractFilterStateString(attrs, AttrSourceAddress)
	if raw == "" {
		return ""
	}
	if raw[0] == '[' {
		if end := strings.IndexByte(raw, ']'); end > 0 {
			return raw[1:end]
		}
		return raw
	}
	if idx := strings.LastIndexByte(raw, ':'); idx >= 0 {
		return raw[:idx]
	}
	return raw
}

// getExtProcStruct returns the top-level structpb.Struct for the ext_proc
// filter attributes without any copying or allocation. Only the exact
// ExtProcAttrsKey is honoured: accepting look-alike keys would make the
// identity source non-deterministic across map iterations.
func getExtProcStruct(attrs map[string]*structpb.Struct) *structpb.Struct {
	return attrs[ExtProcAttrsKey]
}

// extractAttributeInt extracts a numeric attribute from the ext_proc
// attributes struct. Returns 0 when the key is absent or not numeric.
func extractAttributeInt(attrs map[string]*structpb.Struct, key string) int64 {
	s := getExtProcStruct(attrs)
	if s == nil {
		return 0
	}
	fields := s.GetFields()
	if fields == nil {
		return 0
	}
	v, ok := fields[key]
	if !ok {
		return 0
	}
	if n := v.GetNumberValue(); n != 0 {
		return int64(n)
	}
	return 0
}

// extractFilterStateString extracts a string value from the Envoy ext_proc
// filter_state attributes using zero-copy protobuf field access. It looks up
// the key directly, then tries the filter_state['key'] format. There is no
// fuzzy fallback: a value whose key we cannot name exactly is not ours to
// consume as identity.
func extractFilterStateString(attrs map[string]*structpb.Struct, key string) string {
	s := getExtProcStruct(attrs)
	if s == nil {
		return ""
	}
	fields := s.GetFields()
	if fields == nil {
		return ""
	}
	if v, ok := fields[key]; ok {
		return valueToString(v)
	}
	fsKey := "filter_state['" + key + "']"
	if v, ok := fields[fsKey]; ok {
		return valueToString(v)
	}
	return ""
}

// valueToString extracts a string from a structpb.Value. For simple string
// values it returns directly; for struct values it looks for a "value" field.
func valueToString(v *structpb.Value) string {
	if v == nil {
		return ""
	}
	if s := v.GetStringValue(); s != "" {
		return s
	}
	if sv := v.GetStructValue(); sv != nil {
		if inner, ok := sv.GetFields()["value"]; ok {
			return inner.GetStringValue()
		}
	}
	return ""
}

// extractHeaderMap converts Envoy's HeaderMap to a plain string map for easier processing.
// Envoy normalizes header names to lowercase per HTTP/2 spec, so keys are stored in lowercase.
func extractHeaderMap(headers *extProcPb.HttpHeaders) map[string]string {
	if headers == nil || headers.GetHeaders() == nil {
		return map[string]string{}
	}
	hs := headers.GetHeaders().GetHeaders()
	// Sized up front: without the hint the map rehashes several times on a
	// realistic header count, and the header count is known here.
	result := make(map[string]string, len(hs))
	for _, h := range hs {
		if h.Key != "" {
			result[strings.ToLower(h.Key)] = HeaderValue(h)
		}
	}
	return result
}
