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
	"errors"
	"fmt"
	"io"
	"time"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit/accesslog"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

// Server implements the Envoy external processing server.
// https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto
type Server struct {
	resolve       engine.Resolver
	eng           *engine.Engine
	requestBudget time.Duration
	loggers       []filter.StreamLogger
	// failClosedOnMissingIdentity denies requests when the source pod
	// identity is absent from filter_state; the default passes them through.
	failClosedOnMissingIdentity bool
}

// ServerDeps holds the dependencies needed by the ext-proc server.
type ServerDeps struct {
	// Resolve maps request identity to applicable units. Required.
	Resolve engine.Resolver
	// Registrations is the action order applied inside every rule.
	Registrations []filter.Registration
	// AuditLogger receives one accesslog Entry per stream. May be nil in
	// tests; a no-op replaces it.
	AuditLogger accesslog.Logger
	// StreamLoggers are invoked once per stream, after the accesslog logger.
	// Terminal results commit after a successful response send; teardown and
	// error paths use fallback finalization.
	StreamLoggers []filter.StreamLogger
	// PluginBudget bounds all plugin work triggered by one ext_proc message.
	// Zero disables it.
	// Should be set below Envoy's message_timeout so the filter is
	// cancelled before Envoy gives up.
	PluginBudget time.Duration
	// FailClosedOnMissingIdentity denies requests when the source pod
	// identity is absent from filter_state (e.g. a misconfigured metadata
	// exchange). The default (false) passes them through.
	FailClosedOnMissingIdentity bool
}

// NewServer builds the ext-proc server from deps.
func NewServer(deps ServerDeps) *Server {
	loggers := []filter.StreamLogger{accesslog.NewStreamLog(deps.AuditLogger)}
	loggers = append(loggers, deps.StreamLoggers...)
	return &Server{
		resolve:                     deps.Resolve,
		eng:                         engine.NewEngine(deps.Registrations, deps.PluginBudget),
		requestBudget:               deps.PluginBudget,
		loggers:                     loggers,
		failClosedOnMissingIdentity: deps.FailClosedOnMissingIdentity,
	}
}

// Process is the main gRPC streaming method for the external processor.
// It receives requests from Envoy, processes them, and sends back responses.
func (s *Server) Process(srv extProcPb.ExternalProcessor_ProcessServer) (retErr error) {
	ctx := srv.Context()
	logger := log.FromContext(ctx)
	loggerD := logger.V(logging.DEBUG)
	loggerD.Info("processing request started")

	state := newStreamState()

	// The stream loggers fire exactly once. Finalized terminal responses do
	// not wait for physical stream end; this defer remains the fallback for
	// completion, per-message failure, Envoy reset, or ctx cancellation.
	// WithoutCancel: the first ctx-honoring logger would otherwise silently
	// no-op on precisely the teardown paths this exists for.
	defer func() {
		err := retErr
		if err == nil {
			err = ctx.Err()
		}
		s.finishStream(context.WithoutCancel(ctx), state, err)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, recvErr := srv.Recv()
		if recvErr == io.EOF {
			if state.awaitingInput() {
				return status.Error(codes.Unknown,
					"ext-proc stream ended with an outstanding processing obligation")
			}
			s.finishStream(context.WithoutCancel(ctx), state, nil)
			return nil
		}
		if errors.Is(recvErr, context.Canceled) || status.Code(recvErr) == codes.Canceled {
			// Envoy routinely resets the ext-proc stream instead of
			// half-closing once it needs nothing further, so cancellation
			// alone carries no error meaning. Only a cancel that truncates
			// an outstanding processing obligation is recorded as one.
			var finishErr error
			if state.awaitingInput() {
				finishErr = context.Canceled
			}
			s.finishStream(context.WithoutCancel(ctx), state, finishErr)
			return nil
		}
		if recvErr != nil {
			logger.Error(recvErr, "cannot receive stream request")
			return status.Errorf(codes.Unknown, "cannot receive stream request: %v", recvErr)
		}

		var responses []*extProcPb.ProcessingResponse
		var err error
		switch v := req.Request.(type) {
		case *extProcPb.ProcessingRequest_RequestHeaders:
			responses, err = s.HandleRequestHeaders(ctx, req.GetRequestHeaders(), req.Attributes, state)
		case *extProcPb.ProcessingRequest_RequestBody:
			// Reuse the request ID captured during the headers phase so
			// body-phase logs (and downstream filters) share the same tag.
			bodyLogger := logger.WithValues(logKeyRequestID, state.stream.RequestID)
			bodyCtx := log.IntoContext(ctx, bodyLogger)
			if bodyLoggerD := bodyLogger.V(logging.DEBUG); bodyLoggerD.Enabled() {
				bodyLoggerD.Info("incoming body chunk", "body", string(v.RequestBody.Body), "EoS", v.RequestBody.EndOfStream)
			}
			responses, err = s.processRequestBody(bodyCtx, req.GetRequestBody(), state, bodyLogger)
		case *extProcPb.ProcessingRequest_RequestTrailers:
			responses, err = s.HandleRequestTrailers(ctx, req.GetRequestTrailers())
		case *extProcPb.ProcessingRequest_ResponseHeaders:
			responses, err = s.HandleResponseHeaders(ctx, req.GetResponseHeaders(), state)
		case *extProcPb.ProcessingRequest_ResponseBody:
			responses, err = s.HandleResponseBody(ctx, req.GetResponseBody(), state)
		case *extProcPb.ProcessingRequest_ResponseTrailers:
			responses, err = s.HandleResponseTrailers(ctx, req.GetResponseTrailers())
		default:
			// The Go type names which oneof arm arrived, which is what says
			// how processing modes are misconfigured. Its contents are not
			// logged, for the same reason the failure path below does not.
			logger.Error(nil, "unknown request type",
				"messageType", fmt.Sprintf("%T", v))
			return status.Error(codes.Unknown, "unknown request type")
		}

		if err != nil {
			// The failing message type is what triages this. The message itself
			// is not logged, at any level: request headers carry
			// x-agentio-sandbox-token, so dumping it wrote a live sandbox
			// credential into the log whenever debug was enabled.
			logger.Error(err, "failed to process request",
				"messageType", messageTypeName(req))
			// Send any policy response returned with the handler error, then return
			// the original error. The effect is deliberately not observed here:
			// this path always returns an error, and error outranks every effect
			// in deriveOutcome, so observing could not change the outcome.
			for _, resp := range responses {
				if sendErr := srv.Send(resp); sendErr != nil {
					logger.Error(sendErr, "send failed while surfacing a handler error")
					break
				}
			}
			return status.Errorf(status.Code(err), "failed to handle request: %v", err)
		}

		for _, resp := range responses {
			if loggerD.Enabled() {
				// Header names but not values: a response carries the
				// credentials tokentransform injected, so the full message is as
				// sensitive as the request it answers.
				loggerD.Info("response generated",
					"responseType", responseTypeName(resp),
					"setHeaders", mutatedHeaderNames(resp))
			}
			if err := srv.Send(resp); err != nil {
				logger.Error(err, "send failed")
				return status.Errorf(codes.Unknown, "failed to send response back to Envoy: %v", err)
			}
			state.effect.observe(classifyResponse(resp))
		}
		s.finishAfterSend(ctx, state)
	}
}

// finishStream invokes the stream loggers exactly once per stream, after a
// request was actually observed. Idempotent: the first caller wins.
func (s *Server) finishStream(ctx context.Context, state *streamState, err error) {
	if state == nil || state.lifecycle == lifecycleIdle || state.lifecycle == lifecycleFinalized {
		return
	}
	state.lifecycle = lifecycleFinalized
	info := state.stream.Info
	// A filter that failed closed already recorded why this request was denied.
	// A transport error arriving afterwards must not overwrite that: the stream
	// dying is the less useful of the two explanations, and it used to erase the
	// only account of why the request was blocked at all.
	if err != nil && info.Error == "" {
		info.Error = err.Error()
	}
	info.Outcome = deriveOutcome(state.effect, err != nil, len(info.Matched))
	for _, l := range s.loggers {
		l.Log(ctx, state.stream, info)
	}
	// The resolver's per-stream logger runs last: after the static list, and
	// after the outcome derivation above, so it observes the final outcome.
	if state.streamLogger != nil {
		state.streamLogger.Log(ctx, state.stream, info)
	}
}

// finishAfterSend commits a pending finalization only after Envoy accepted the
// complete response slice for the current processing request.
func (s *Server) finishAfterSend(ctx context.Context, state *streamState) {
	if state == nil || state.lifecycle != lifecycleFinalizePending {
		return
	}
	s.finishStream(context.WithoutCancel(ctx), state, nil)
}

// streamLifecycle tracks whether the stream is idle, active, awaiting
// post-send finalization, or finalized.
type streamLifecycle uint8

const (
	// lifecycleIdle: no request observed yet; a stream that ends here
	// produces no log entry.
	lifecycleIdle streamLifecycle = iota
	// lifecycleActive: request headers were processed; the stream loggers
	// are owed exactly one entry at stream end.
	lifecycleActive
	// lifecycleFinalizePending: a terminal response was produced; the
	// finalization commits only after Envoy accepted the send.
	lifecycleFinalizePending
	// lifecycleFinalized: the stream loggers fired; later messages get a
	// bare ack and must not reopen observers or audit.
	lifecycleFinalized
)

// streamState carries per-stream state between the phases. Fields are grouped
// by writer: the resolution pin is written once by HandleRequestHeaders; the
// phase fields follow the ext_proc message flow; the lifecycle field belongs to
// finalization and audit.
type streamState struct {
	// Resolution pin — written once by HandleRequestHeaders, read-only after.
	stream *filter.Stream
	units  []engine.Unit
	// streamLogger is the per-stream logger the resolver supplied, if any.
	// It is assigned alongside units and for the same reason: both describe
	// the resolution that took effect, so a later resolution returning
	// nothing must leave both untouched rather than clear them.
	streamLogger filter.StreamLogger

	// Request phase — the headers walk's paused continuation, consumed exactly
	// once by the body phase. Non-nil is what "a request body is owed" means;
	// there is deliberately no separate flag that could drift from it.
	requestBodyContinuation *engine.RequestHeadersResult

	// Response phase — the walk's bypass point plus the protocol obligations.
	// responseScope is zero until a walk bypasses; a bypass can happen in the
	// headers walk or the resumed body walk, so both handlers write it.
	responseScope        engine.ResponseScope
	awaitResponseHeaders bool
	// responseBodyContinuation is the response walk paused at NeedBody. Its
	// presence is the response-body protocol obligation.
	responseBodyContinuation *engine.ResponseHeadersResult

	// Lifecycle / audit — see streamLifecycle.
	lifecycle streamLifecycle
	// effect is the strongest message effect actually sent to Envoy on this
	// stream, and the audit outcome's main input. Observed after each Send so a
	// response Envoy never accepted is never reported as enforcement.
	effect messageEffect
}

func newStreamState() *streamState {
	return &streamState{
		stream: &filter.Stream{Info: filter.NewStreamInfo()},
	}
}

// markRequestSeen moves an idle stream to active. It never moves the machine
// backwards: a request-headers message on a finalized stream must not resurrect
// the logging obligation.
func (st *streamState) markRequestSeen() {
	if st.lifecycle == lifecycleIdle {
		st.lifecycle = lifecycleActive
	}
}

// engineUnits returns the engine-facing units; the resolver already hands
// them over in neutral form.
func (st *streamState) engineUnits() []engine.Unit { return st.units }

// awaitingRequestBody reports whether the headers walk paused for the request
// body and the body message has not been consumed yet.
func (st *streamState) awaitingRequestBody() bool { return st.requestBodyContinuation != nil }

func (st *streamState) awaitingResponseBody() bool { return st.responseBodyContinuation != nil }

func (st *streamState) awaitingInput() bool {
	return st != nil && (st.awaitingRequestBody() || st.awaitingResponseBody() || st.awaitResponseHeaders)
}

// armFinalization records when a terminal request result may be committed.
// Block retires response obligations; bypass waits for a subscribed response phase.
func (st *streamState) armFinalization(d engine.Disposition) {
	switch d {
	case engine.DispositionBlocked:
		st.requestBodyContinuation = nil
		st.responseBodyContinuation = nil
		st.awaitResponseHeaders = false
		st.lifecycle = lifecycleFinalizePending
	case engine.DispositionBypassed:
		if !st.awaitResponseHeaders {
			st.lifecycle = lifecycleFinalizePending
		}
	}
}

// processRequestBody dispatches the complete buffered body. BUFFERED may flush
// before trailers with EndOfStream unset, so delivery is not gated on that flag.
func (s *Server) processRequestBody(ctx context.Context, body *extProcPb.HttpBody, state *streamState, logger logr.Logger) ([]*extProcPb.ProcessingResponse, error) {
	logger.V(logging.DEBUG).Info("dispatching request body",
		"bytes", len(body.GetBody()), "endOfStream", body.EndOfStream)

	return s.HandleRequestBody(ctx, body, state)
}

// messageTypeName names an ext_proc request message without rendering it. The
// message is never logged: request headers carry x-agentio-sandbox-token, and a
// body carries whatever the caller sent.
func messageTypeName(req *extProcPb.ProcessingRequest) string {
	switch req.GetRequest().(type) {
	case *extProcPb.ProcessingRequest_RequestHeaders:
		return "request_headers"
	case *extProcPb.ProcessingRequest_RequestBody:
		return "request_body"
	case *extProcPb.ProcessingRequest_RequestTrailers:
		return "request_trailers"
	case *extProcPb.ProcessingRequest_ResponseHeaders:
		return "response_headers"
	case *extProcPb.ProcessingRequest_ResponseBody:
		return "response_body"
	case *extProcPb.ProcessingRequest_ResponseTrailers:
		return "response_trailers"
	default:
		return "unknown"
	}
}

// responseTypeName names an ext_proc response message, for the same reason.
func responseTypeName(resp *extProcPb.ProcessingResponse) string {
	switch resp.GetResponse().(type) {
	case *extProcPb.ProcessingResponse_RequestHeaders:
		return "request_headers"
	case *extProcPb.ProcessingResponse_RequestBody:
		return "request_body"
	case *extProcPb.ProcessingResponse_RequestTrailers:
		return "request_trailers"
	case *extProcPb.ProcessingResponse_ResponseHeaders:
		return "response_headers"
	case *extProcPb.ProcessingResponse_ResponseBody:
		return "response_body"
	case *extProcPb.ProcessingResponse_ResponseTrailers:
		return "response_trailers"
	case *extProcPb.ProcessingResponse_ImmediateResponse:
		return "immediate"
	default:
		return "unknown"
	}
}

// mutatedHeaderNames lists the header names a response sets or removes, so a
// debug log can show which mutations were rendered. Values are omitted on
// purpose: the credential tokentransform injects is one of them, and an
// immediate response's headers are attacker-visible policy output.
func mutatedHeaderNames(resp *extProcPb.ProcessingResponse) []string {
	var mut *extProcPb.HeaderMutation
	switch r := resp.GetResponse().(type) {
	case *extProcPb.ProcessingResponse_RequestHeaders:
		mut = r.RequestHeaders.GetResponse().GetHeaderMutation()
	case *extProcPb.ProcessingResponse_RequestBody:
		mut = r.RequestBody.GetResponse().GetHeaderMutation()
	case *extProcPb.ProcessingResponse_ResponseHeaders:
		mut = r.ResponseHeaders.GetResponse().GetHeaderMutation()
	case *extProcPb.ProcessingResponse_ResponseBody:
		mut = r.ResponseBody.GetResponse().GetHeaderMutation()
	case *extProcPb.ProcessingResponse_ImmediateResponse:
		mut = r.ImmediateResponse.GetHeaders()
	}
	if mut == nil {
		return nil
	}
	names := make([]string, 0, len(mut.GetSetHeaders())+len(mut.GetRemoveHeaders()))
	for _, h := range mut.GetSetHeaders() {
		names = append(names, h.GetHeader().GetKey())
	}
	return append(names, mut.GetRemoveHeaders()...)
}
