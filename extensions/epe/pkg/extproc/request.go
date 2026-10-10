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
package extproc

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	structpb "google.golang.org/protobuf/types/known/structpb"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

const (
	// headerRequestID is Envoy's standard per-request correlation header.
	// Its value is attached to every log line in the ext-proc request path
	// (empty string when the header is absent).
	headerRequestID = "x-request-id"
	// logKeyRequestID is the structured-log key carrying the request ID.
	logKeyRequestID = "requestID"
	// requestBodyMode must stay BUFFERED: STREAMED releases acknowledged chunks
	// upstream before the verdict and prevents body-phase header mutations.
	requestBodyMode = extProcV3.ProcessingMode_BUFFERED
	// responseBodyMode has the same constraint in the response direction.
	responseBodyMode = extProcV3.ProcessingMode_BUFFERED

	connectRequestBodyUnsupportedDetails  = "epe_connect_request_body_unsupported"
	connectResponseBodyUnsupportedDetails = "epe_connect_response_body_unsupported"
	connectBodyUnsupportedStatus          = 500
	missingIdentityDetails                = "epe_missing_source_identity"
	missingIdentityStatus                 = 403
)

// HandleRequestHeaders resolves the caller identity, matches profiles into
// ordered units, and runs the ordered engine. All observations land in
// state.stream.Info; the stream loggers consume it once at stream end.
func (s *Server) HandleRequestHeaders(ctx context.Context, headers *extProcPb.HttpHeaders, attrs map[string]*structpb.Struct, state *streamState) ([]*extProcPb.ProcessingResponse, error) {
	// Tag every log line in this request's ext-proc path with the request
	// ID, and propagate it through ctx so downstream filters inherit it.
	requestID := extractRequestID(headers)
	logger := log.FromContext(ctx).WithValues(logKeyRequestID, requestID)
	ctx = log.IntoContext(ctx, logger)
	loggerD := logger.V(logging.DEBUG)
	// The log lines on this path are guarded rather than left to the level
	// check inside Info: Go builds the key-value slice at the call site, so an
	// unguarded line costs an allocation on every request even with the level
	// off.
	if loggerD.Enabled() {
		// Attribute values can carry credentials (filter_state tokens);
		// log only the key names.
		loggerD.Info("handling request headers", "req.AttributeKeys", slices.Sorted(maps.Keys(attrs)))
	}

	st := state.stream
	st.RequestID = requestID
	state.markRequestSeen()

	peer, req := attributes.Extract(ctx, headers, attrs)
	st.Peer = peer
	st.Request = req
	isConnect := strings.EqualFold(req.Method, "CONNECT")

	if !peer.Valid() {
		// Without a source pod identity no SecurityProfile can be applied.
		// The default passes such requests through so a misconfigured
		// metadata exchange degrades policy coverage, not connectivity;
		// FailClosedOnMissingIdentity turns it into a deny for deployments
		// that require enforcement over availability.
		resp, disposition := defaultPassThrough, "passed through"
		if s.failClosedOnMissingIdentity {
			resp, disposition = missingIdentityDeny, "denied"
		}
		logger.V(logging.DEFAULT).Info("pod identity missing from filter_state",
			"podNamespace", peer.Pod.Namespace, "podName", peer.Pod.Name,
			"disposition", disposition)
		return resp, nil
	}

	// Profile lookup, rule matching and config projection all live behind
	// the resolver, so this adapter never names a policy type.
	pod := inputs.Pod{
		Name:      peer.Pod.Name,
		Namespace: peer.Pod.Namespace,
		IP:        peer.IP,
		Labels:    peer.Labels,
	}
	res, err := s.resolve(ctx, pod, &req)
	st.Destination = res.Destination
	// Installed before the error is honoured: a resolver that fails may still
	// have matched rules worth recording, and finishStream promotes the error
	// to the disposition the logger reports. Without this, a resolve failure
	// is the one error class audit never sees. Guarded so a resolution that
	// carries no logger cannot erase one an earlier resolution installed.
	if res.StreamLogger != nil {
		state.streamLogger = res.StreamLogger
	}
	if err != nil {
		return nil, err
	}

	// Single VERBOSE summary line per request — pod identity, request
	// identity, and resolved unit count.
	if loggerV := logger.V(logging.VERBOSE); loggerV.Enabled() {
		loggerV.Info("handling request",
			"pod", peer.Pod.Name, "namespace", peer.Pod.Namespace,
			"method", req.Method, "host", req.Host, "port", req.Port, "path", req.Path,
			"units", len(res.Units))
	}

	if len(res.Units) == 0 {
		if loggerD.Enabled() {
			loggerD.Info("no policy applies to this pod",
				"pod", peer.Pod.Name, "namespace", peer.Pod.Namespace, "labels", peer.Labels)
		}
		return defaultPassThrough, nil
	}

	// Record the resolved units only after the early returns, so a resolution
	// that yields nothing cannot erase a previous one. The stream logger was
	// already installed above, before the resolve error was honoured.
	state.units = res.Units
	subscriptions, err := s.eng.ValidateSubscriptions(state.engineUnits())
	if err != nil {
		return nil, err
	}

	// End-of-stream headers mean no body will follow: the empty body is final,
	// so hand it to the walk up front and body requests are satisfied inline
	// instead of pausing.
	var evalOpts []engine.RequestOption
	if headers.GetEndOfStream() && !isConnect {
		evalOpts = append(evalOpts, engine.WithAvailableRequestBody(filter.Body{Complete: true}))
	}
	reqHeadersRes, evalErr := s.eng.EvalRequestHeaders(ctx, st, state.engineUnits(), evalOpts...)
	if evalErr != nil {
		return nil, evalErr
	}
	// Upgrade payload is not an HTTP message body. Buffering a CONNECT body
	// would either wait for tunnel EOF or hit Envoy's buffer limit, so a policy
	// that requires request payload inspection is unsupported and fails closed
	// before the CONNECT reaches the proxy. Do this even when Envoy marked the
	// headers end-of-stream: satisfying NeedBody with a synthetic empty body
	// would silently claim the policy ran against the tunnel payload.
	if isConnect && reqHeadersRes.NeedsBody() {
		reqHeadersRes.Disposition = engine.DispositionBlocked
		reqHeadersRes.Reply = filter.Reply{
			Status:  connectBodyUnsupportedStatus,
			Details: connectRequestBodyUnsupportedDetails,
		}
	}
	// A bypass in this walk bounds the response-phase dispatch;
	// HandleRequestBody records the asynchronous case.
	state.responseScope = reqHeadersRes.ResponseScope

	responses := translateRequestHeadersResult(reqHeadersRes, loggerD, peer)

	// ModeOverride must restate both body modes because Envoy copies them
	// unconditionally. A blocked result must not carry an override.
	if reqHeadersRes.Disposition != engine.DispositionBlocked {
		wantResponse := subscriptions&filter.PhaseResponseHeaders != 0
		wantBody := reqHeadersRes.NeedsBody()
		if wantBody || wantResponse {
			override := &extProcV3.ProcessingMode{
				RequestBodyMode:  extProcV3.ProcessingMode_NONE,
				ResponseBodyMode: extProcV3.ProcessingMode_NONE,
			}
			if wantBody {
				override.RequestBodyMode = requestBodyMode
			}
			if wantResponse {
				override.ResponseHeaderMode = extProcV3.ProcessingMode_SEND
			}
			resp := cloneResponse(responses[0])
			resp.ModeOverride = override
			responses = append([]*extProcPb.ProcessingResponse{resp}, responses[1:]...)
		}
		if wantBody {
			state.requestBodyContinuation = reqHeadersRes
		}
		if wantResponse {
			state.awaitResponseHeaders = true
		}
	}

	// Finalization for terminal dispositions lives in armFinalization; the
	// no-op it performs for a passthrough or mutated result leaves teardown to
	// stream end, mirroring the body phase.
	state.armFinalization(reqHeadersRes.Disposition)
	return responses, nil
}

// HandleResponseHeaders records the upstream status into the stream and
// dispatches the response-headers phase.
func (s *Server) HandleResponseHeaders(ctx context.Context, headers *extProcPb.HttpHeaders, state *streamState) ([]*extProcPb.ProcessingResponse, error) {
	if state == nil || state.lifecycle == lifecycleIdle {
		return nil, status.Error(codes.FailedPrecondition,
			"received response headers before request headers")
	}
	if headers == nil || headers.GetHeaders() == nil {
		return nil, status.Error(codes.InvalidArgument, "response headers are missing")
	}

	if state.lifecycle == lifecycleFinalized {
		// A static response-header mode can outlive a terminal request decision.
		// Acknowledge the first valid message without reopening filter dispatch or audit.
		state.awaitResponseHeaders = false
		return emptyResponseHeadersAck, nil
	}

	respHeaders := make(map[string]string, len(headers.GetHeaders().GetHeaders()))
	responseStatus := 0
	for _, h := range headers.GetHeaders().GetHeaders() {
		key := strings.ToLower(h.Key)
		value := attributes.HeaderValue(h)
		respHeaders[key] = value
		if key == ":status" {
			if code, err := strconv.Atoi(value); err == nil {
				responseStatus = code
			}
		}
	}
	state.stream.Response = httpreq.HTTPResponse{Status: responseStatus, Headers: respHeaders}
	// End-of-stream response headers are the complete bodyless response. Satisfy
	// any NeedBody action inline because no response-body message will follow.
	var evalOpts []engine.ResponseOption
	isConnect := strings.EqualFold(state.stream.Request.Method, "CONNECT")
	if headers.GetEndOfStream() && !isConnect {
		evalOpts = append(evalOpts, engine.WithAvailableResponseBody(filter.Body{Complete: true}))
	}
	// Dispatch only to subscribed pairs within the request walk's response scope.
	respHeadersRes, evalErr := s.eng.EvalResponseHeaders(ctx, state.stream, state.engineUnits(), state.responseScope, evalOpts...)
	if evalErr != nil {
		// Contract and protocol errors return no acknowledgement.
		return nil, evalErr
	}
	// A successful CONNECT turns subsequent response DATA into tunnel payload,
	// not an HTTP response body. Refuse body-dependent response processing at
	// the headers boundary instead of arming BUFFERED mode. The same rule is
	// applied to non-2xx CONNECT responses so policy behavior does not depend on
	// whether Envoy happened to mark a bodyless response end-of-stream.
	if isConnect && respHeadersRes.NeedsBody() {
		respHeadersRes.Disposition = engine.DispositionBlocked
		respHeadersRes.Reply = filter.Reply{
			Status:  connectBodyUnsupportedStatus,
			Details: connectResponseBodyUnsupportedDetails,
		}
	}
	state.awaitResponseHeaders = false
	responses := translateResponseHeadersResult(respHeadersRes)
	if respHeadersRes.Disposition != engine.DispositionBlocked && respHeadersRes.NeedsBody() {
		override := &extProcV3.ProcessingMode{
			RequestBodyMode:  extProcV3.ProcessingMode_NONE,
			ResponseBodyMode: responseBodyMode,
		}
		resp := cloneResponse(responses[0])
		resp.ModeOverride = override
		responses = append([]*extProcPb.ProcessingResponse{resp}, responses[1:]...)
		state.responseBodyContinuation = respHeadersRes
		return responses, nil
	}
	state.lifecycle = lifecycleFinalizePending
	return responses, nil
}

// cloneResponse copies a ProcessingResponse so ModeOverride can be set
// without mutating package-level singletons (e.g. defaultPassThrough).
// proto.Clone is used because proto messages embed internal state that must
// not be copied by assignment.
func cloneResponse(r *extProcPb.ProcessingResponse) *extProcPb.ProcessingResponse {
	return proto.Clone(r).(*extProcPb.ProcessingResponse)
}

// extractRequestID returns the x-request-id header value, or "" when the
// header is absent. Envoy normalizes header names to lowercase, but the
// comparison is case-insensitive to stay robust against non-Envoy callers
// (e.g. unit tests).
func extractRequestID(headers *extProcPb.HttpHeaders) string {
	if headers == nil || headers.GetHeaders() == nil {
		return ""
	}
	for _, h := range headers.GetHeaders().GetHeaders() {
		if strings.EqualFold(h.Key, headerRequestID) {
			return attributes.HeaderValue(h)
		}
	}
	return ""
}

// defaultPassThrough is the shared passthrough response returned when no
// filter produces mutations. It is immutable and safe to share across
// goroutines — gRPC serializes but does not mutate the proto.
var defaultPassThrough = []*extProcPb.ProcessingResponse{
	{Response: &extProcPb.ProcessingResponse_RequestHeaders{
		RequestHeaders: &extProcPb.HeadersResponse{},
	}},
}

// missingIdentityDeny is the fail-closed reply for a request whose source pod
// identity never reached the filter. Like defaultPassThrough it is immutable
// and shared across goroutines.
var missingIdentityDeny = []*extProcPb.ProcessingResponse{
	immediateFromReply(filter.Reply{Status: missingIdentityStatus, Details: missingIdentityDetails}),
}

// HandleRequestTrailers returns an empty pass-through response.
func (s *Server) HandleRequestTrailers(ctx context.Context, trailers *extProcPb.HttpTrailers) ([]*extProcPb.ProcessingResponse, error) {
	return []*extProcPb.ProcessingResponse{
		{
			Response: &extProcPb.ProcessingResponse_RequestTrailers{
				RequestTrailers: &extProcPb.TrailersResponse{},
			},
		},
	}, nil
}

// HandleResponseTrailers returns an empty pass-through response.
func (s *Server) HandleResponseTrailers(ctx context.Context, trailers *extProcPb.HttpTrailers) ([]*extProcPb.ProcessingResponse, error) {
	return []*extProcPb.ProcessingResponse{
		{
			Response: &extProcPb.ProcessingResponse_ResponseTrailers{
				ResponseTrailers: &extProcPb.TrailersResponse{},
			},
		},
	}, nil
}
