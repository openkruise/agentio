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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit/accesslog"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

type responseHeadersProbe struct {
	filter.PassThrough
	calls int
	err   error
	// act overrides the returned action. The zero value is Continue.
	act *filter.Action
}

type requestHeadersProbe struct {
	filter.PassThrough
	calls int
}

func (p *requestHeadersProbe) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	p.calls++
	return filter.Continue(), nil
}

func (p *responseHeadersProbe) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	p.calls++
	if p.act != nil {
		return *p.act, p.err
	}
	return filter.Continue(), p.err
}

func responseHeadersState(p *responseHeadersProbe) (*Server, *streamState, *captureLogger) {
	cap := &captureLogger{}
	reg := filter.Registration{
		Name:    "response-filter",
		Phases:  filter.PhaseResponseHeaders,
		OnError: func(any) filter.FailurePolicy { return filter.FailClosed },
		Parse:   func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New:     func(filter.ErasedRuleConfig) filter.Filter { return p },
		// The response phase dispatches to subscribing configs only, recomputed
		// from the units pinned on the stream; these tests stand in for a request
		// phase whose config subscribed.
		Subscribes: func(any) filter.Phase { return filter.PhaseResponseHeaders },
	}
	s := NewServer(ServerDeps{
		Registrations: []filter.Registration{reg},
		AuditLogger:   cap,
	})
	state := newStreamState()
	state.markRequestSeen()
	id := filter.UnitID{Scope: "default/p1", Name: "response"}
	state.units = []engine.Unit{{
		ID:   id,
		Cfgs: []any{struct{}{}},
	}}
	state.awaitResponseHeaders = true
	return s, state, cap
}

type bodylessDeadlineProbe struct {
	filter.PassThrough
	headerDeadline    time.Time
	bodyDeadline      time.Time
	headerHasDeadline bool
	bodyHasDeadline   bool
}

func (p *bodylessDeadlineProbe) OnRequestHeaders(ctx context.Context, _ *filter.Stream) (filter.Action, error) {
	p.headerDeadline, p.headerHasDeadline = ctx.Deadline()
	// Make a freshly-created body-phase budget observably later than the
	// headers-phase budget. A shared parent deadline remains exactly equal.
	time.Sleep(10 * time.Millisecond)
	return filter.NeedBody(), nil
}

func (p *bodylessDeadlineProbe) OnRequestBody(ctx context.Context, _ *filter.Stream, _ filter.Body) (filter.Action, error) {
	p.bodyDeadline, p.bodyHasDeadline = ctx.Deadline()
	return filter.Continue(), nil
}

// White-box tests for internals that cannot be observed through the
// ext_proc wire (extractRequestID, stream-end bookkeeping, NewServer
// nil-logger defaulting, pass-through stubs). Full-chain behavior lives in
// the scenario_*_test.go files (package extproc_test), driven by the
// enginetest harness.

// makeRequestHeaders builds an extProcPb.HttpHeaders with the given
// pseudo-headers for testing.
func makeRequestHeaders(host, path, method string) *extProcPb.HttpHeaders {
	return &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{
			Headers: []*corev3.HeaderValue{
				{Key: ":authority", RawValue: []byte(host)},
				{Key: ":path", RawValue: []byte(path)},
				{Key: ":method", RawValue: []byte(method)},
			},
		},
	}
}

func TestExtractRequestID(t *testing.T) {
	tests := []struct {
		name    string
		headers *extProcPb.HttpHeaders
		want    string
	}{
		{
			name: "present",
			headers: &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: "x-request-id", RawValue: []byte("abc-123")},
			}}},
			want: "abc-123",
		},
		{
			name: "case-insensitive match",
			headers: &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: "X-Request-Id", RawValue: []byte("mixed-case")},
			}}},
			want: "mixed-case",
		},
		{
			name: "absent returns empty",
			headers: &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":method", RawValue: []byte("GET")},
			}}},
			want: "",
		},
		{
			name:    "nil headers returns empty",
			headers: nil,
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractRequestID(tt.headers); got != tt.want {
				t.Errorf("extractRequestID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// makeAttrsWithLabels constructs the structpb attrs that the handler reads
// from Envoy filter_state.
func makeAttrsWithLabels(namespace, name, labelsB64 string) map[string]*structpb.Struct {
	inner, _ := structpb.NewStruct(map[string]interface{}{
		attributes.FilterStateDownstreamPeerNamespace: namespace,
		attributes.FilterStateDownstreamPeerName:      name,
		attributes.FilterStateSandboxLabels:           labelsB64,
	})
	return map[string]*structpb.Struct{
		attributes.ExtProcAttrsKey: inner,
	}
}

// "app=blocked" base64-encoded, matching the format labels.ParseSandboxLabels expects.
const testLabelsB64 = "YXBwPWJsb2NrZWQ="

func TestHandleRequestHeaders_ArmsOnlyRequestBodyObligation(t *testing.T) {
	probe := &bodyProbe{}
	regs := []filter.Registration{fixedReg("body-filter", probe)}
	s := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Units: []engine.Unit{{
				ID:   filter.UnitID{Scope: "default/p1", Name: "body"},
				Cfgs: []any{struct{}{}},
			}}}, nil
		},
		Registrations: regs,
	})
	state := newStreamState()

	if _, err := s.HandleRequestHeaders(context.Background(),
		makeRequestHeaders("api.example.com", "/x", "POST"),
		makeAttrsWithLabels("default", "pod", testLabelsB64), state); err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}
	if !state.awaitingRequestBody() {
		t.Fatal("body evaluation did not arm its request-body obligation")
	}
	if state.awaitResponseHeaders {
		t.Fatal("request-body demand unexpectedly armed a response-headers obligation")
	}
	if state.lifecycle == lifecycleFinalizePending {
		t.Fatal("non-terminal headers result armed finalization")
	}
}

func TestHandleRequestHeaders_CONNECTBodyDemandFailsClosedWithoutBuffering(t *testing.T) {
	for _, endOfStream := range []bool{false, true} {
		t.Run(fmt.Sprintf("end_of_stream=%t", endOfStream), func(t *testing.T) {
			probe := &bodyProbe{}
			s, _ := wantsServer(t, []filter.Registration{fixedReg("body-filter", probe)}, []string{"r"})
			state := newStreamState()
			headers := makeRequestHeaders("target.example.com:443", "", "CONNECT")
			headers.EndOfStream = endOfStream

			responses, err := s.HandleRequestHeaders(context.Background(), headers,
				makeAttrsWithLabels("default", "pod", testLabelsB64), state)
			if err != nil {
				t.Fatalf("HandleRequestHeaders: %v", err)
			}
			if len(responses) != 1 || responses[0].GetImmediateResponse() == nil {
				t.Fatalf("responses = %+v, want one fail-closed ImmediateResponse", responses)
			}
			immediate := responses[0].GetImmediateResponse()
			if immediate.GetStatus().GetCode() != 500 || immediate.GetDetails() != "epe_connect_request_body_unsupported" {
				t.Fatalf("immediate = status %v details %q, want 500 / epe_connect_request_body_unsupported",
					immediate.GetStatus().GetCode(), immediate.GetDetails())
			}
			if responses[0].GetModeOverride() != nil {
				t.Fatalf("CONNECT fail-closed response carried body ModeOverride: %v", responses[0].GetModeOverride())
			}
			if state.awaitingRequestBody() {
				t.Fatal("CONNECT body demand armed request-body buffering")
			}
			if state.lifecycle != lifecycleFinalizePending {
				t.Fatalf("lifecycle = %v, want finalize pending", state.lifecycle)
			}
		})
	}
}

type connectResponseBodyProbe struct {
	filter.PassThrough
}

func (*connectResponseBodyProbe) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(), nil
}

func TestHandleResponseHeaders_CONNECTBodyDemandFailsClosedWithoutBuffering(t *testing.T) {
	for _, endOfStream := range []bool{false, true} {
		t.Run(fmt.Sprintf("end_of_stream=%t", endOfStream), func(t *testing.T) {
			probe := &connectResponseBodyProbe{}
			reg := filter.Registration{
				Name:       "response-body-filter",
				Phases:     filter.PhaseRequestHeaders | filter.PhaseResponseHeaders | filter.PhaseResponseBody,
				Parse:      func(json.RawMessage) (any, error) { return struct{}{}, nil },
				Subscribes: func(any) filter.Phase { return filter.PhaseResponseHeaders },
				New:        func(filter.ErasedRuleConfig) filter.Filter { return probe },
			}
			s, _ := wantsServer(t, []filter.Registration{reg}, []string{"r"})
			state := newStreamState()
			requestHeaders := makeRequestHeaders("target.example.com:443", "", "CONNECT")
			responses, err := s.HandleRequestHeaders(context.Background(), requestHeaders,
				makeAttrsWithLabels("default", "pod", testLabelsB64), state)
			if err != nil {
				t.Fatalf("HandleRequestHeaders: %v", err)
			}
			if len(responses) != 1 || responses[0].GetModeOverride().GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
				t.Fatalf("request responses = %+v, want response-headers subscription", responses)
			}

			responseHeaders := responseHeaderMsg("200")
			responseHeaders.EndOfStream = endOfStream
			responses, err = s.HandleResponseHeaders(context.Background(), responseHeaders, state)
			if err != nil {
				t.Fatalf("HandleResponseHeaders: %v", err)
			}
			if len(responses) != 1 || responses[0].GetImmediateResponse() == nil {
				t.Fatalf("responses = %+v, want one fail-closed ImmediateResponse", responses)
			}
			immediate := responses[0].GetImmediateResponse()
			if immediate.GetStatus().GetCode() != 500 || immediate.GetDetails() != "epe_connect_response_body_unsupported" {
				t.Fatalf("immediate = status %v details %q, want 500 / epe_connect_response_body_unsupported",
					immediate.GetStatus().GetCode(), immediate.GetDetails())
			}
			if responses[0].GetModeOverride() != nil {
				t.Fatalf("CONNECT fail-closed response carried body ModeOverride: %v", responses[0].GetModeOverride())
			}
			if state.responseBodyContinuation != nil {
				t.Fatal("CONNECT body demand armed response-body buffering")
			}
			if state.lifecycle != lifecycleFinalizePending {
				t.Fatalf("lifecycle = %v, want finalize pending", state.lifecycle)
			}
		})
	}
}

func TestHandleRequestHeaders_ReadinessFailureReturnsImmediate503(t *testing.T) {
	s := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Failure: &filter.Reply{
				Status:  503,
				Details: "epe_policy_not_ready",
			}}, nil
		},
	})
	state := newStreamState()

	responses, err := s.HandleRequestHeaders(context.Background(),
		makeRequestHeaders("api.example.com", "/x", "GET"),
		makeAttrsWithLabels("default", "pod", testLabelsB64), state)
	if err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want one", len(responses))
	}
	immediate := responses[0].GetImmediateResponse()
	if immediate == nil || immediate.GetStatus().GetCode() != 503 || immediate.GetDetails() != "epe_policy_not_ready" {
		t.Fatalf("response = %+v, want 503/epe_policy_not_ready ImmediateResponse", responses[0])
	}
	if state.lifecycle != lifecycleFinalizePending {
		t.Fatalf("lifecycle = %v, want finalize pending", state.lifecycle)
	}
}

func TestHandleRequestHeaders_ValidatesSubscriptionsBeforeEvaluation(t *testing.T) {
	probe := &requestHeadersProbe{}
	reg := filter.Registration{
		Name:       "invalid-subscription",
		Phases:     filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		Parse:      func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New:        func(filter.ErasedRuleConfig) filter.Filter { return probe },
		Subscribes: func(any) filter.Phase { return filter.PhaseRequestBody },
	}
	s := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Units: []engine.Unit{{
				ID:   filter.UnitID{Scope: "default/p1", Name: "invalid"},
				Cfgs: []any{struct{}{}},
			}}}, nil
		},
		Registrations: []filter.Registration{reg},
	})

	_, err := s.HandleRequestHeaders(context.Background(),
		makeRequestHeaders("api.example.com", "/x", "GET"),
		makeAttrsWithLabels("default", "pod", testLabelsB64), newStreamState())
	if err == nil || !strings.Contains(err.Error(), "invalid-subscription") {
		t.Fatalf("subscription validation error = %v", err)
	}
	if probe.calls != 0 {
		t.Fatalf("request filter ran %d times before subscription validation", probe.calls)
	}
}

func TestHandleRequestHeaders_TerminalResultsArmFinalization(t *testing.T) {
	tests := []struct {
		name   string
		action filter.Action
	}{
		{name: "blocked", action: filter.Stop(filter.Reply{Status: 403})},
		{name: "bypassed", action: filter.Bypass()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regs := []filter.Registration{fixedRegHeaders("terminal", tt.action)}
			s := NewServer(ServerDeps{
				Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
					return engine.Resolution{Units: []engine.Unit{{
						ID:   filter.UnitID{Scope: "default/p1", Name: "terminal"},
						Cfgs: []any{struct{}{}},
					}}}, nil
				},
				Registrations: regs,
			})
			state := newStreamState()

			if _, err := s.HandleRequestHeaders(context.Background(),
				makeRequestHeaders("api.example.com", "/x", "GET"),
				makeAttrsWithLabels("default", "pod", testLabelsB64), state); err != nil {
				t.Fatalf("HandleRequestHeaders: %v", err)
			}
			if state.lifecycle != lifecycleFinalizePending {
				t.Fatal("terminal headers result did not arm finalization")
			}
		})
	}
}

func TestHandleRequestHeaders_BodylessContinuationSharesMessageDeadline(t *testing.T) {
	probe := &bodylessDeadlineProbe{}
	regs := []filter.Registration{fixedReg("deadline-probe", probe)}
	s := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Units: []engine.Unit{{
				ID:   filter.UnitID{Scope: "default/p1", Name: "body"},
				Cfgs: []any{struct{}{}},
			}}}, nil
		},
		Registrations: regs,
		PluginBudget:  time.Minute,
	})
	headers := makeRequestHeaders("api.example.com", "/x", "POST")
	headers.EndOfStream = true

	if _, err := s.HandleRequestHeaders(context.Background(), headers,
		makeAttrsWithLabels("default", "pod", testLabelsB64), newStreamState()); err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}
	if !probe.headerHasDeadline || !probe.bodyHasDeadline {
		t.Fatalf("captured deadlines = headers:%v body:%v, want both present",
			probe.headerHasDeadline, probe.bodyHasDeadline)
	}
	if !probe.bodyDeadline.Equal(probe.headerDeadline) {
		t.Fatalf("body deadline = %v, headers deadline = %v; one request-header message must share one budget",
			probe.bodyDeadline, probe.headerDeadline)
	}
}

func TestHandleResponseHeaders_ConsumesObligationAfterSuccessfulDispatch(t *testing.T) {
	probe := &responseHeadersProbe{}
	s, state, _ := responseHeadersState(probe)

	if _, err := s.HandleResponseHeaders(context.Background(), &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":status", RawValue: []byte("204")},
		}},
	}, state); err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if probe.calls != 1 {
		t.Fatalf("response filter ran %d times, want 1", probe.calls)
	}
	if state.awaitResponseHeaders {
		t.Fatal("response-headers obligation was not consumed")
	}
	if state.lifecycle != lifecycleFinalizePending {
		t.Fatal("successful response dispatch did not arm finalization")
	}
}

func TestHandleResponseHeaders_ErrorKeepsObligationUncommitted(t *testing.T) {
	boom := errors.New("response filter failed")
	probe := &responseHeadersProbe{err: boom}
	s, state, _ := responseHeadersState(probe)

	resp, err := s.HandleResponseHeaders(context.Background(), &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":status", RawValue: []byte("500")},
		}},
	}, state)
	if err != nil {
		t.Fatalf("configured FailClosed returned handler error: %v", err)
	}
	// A FailClosed response error returns its synthesized deny with the error.
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1 synthesised deny", len(resp))
	}
	if resp[0].GetImmediateResponse() == nil {
		t.Fatalf("response = %T, want an ImmediateResponse carrying the deny", resp[0].GetResponse())
	}
	if state.awaitResponseHeaders {
		t.Fatal("handled FailClosed left the response-headers obligation open")
	}
	if state.lifecycle != lifecycleFinalizePending {
		t.Fatal("handled FailClosed did not arm post-send finalization")
	}
}

func TestHandleResponseHeaders_BypassAcknowledgesAndFinalizes(t *testing.T) {
	bypass := filter.Bypass()
	probe := &responseHeadersProbe{act: &bypass}
	s, state, _ := responseHeadersState(probe)

	resp, err := s.HandleResponseHeaders(context.Background(), &extProcPb.HttpHeaders{
		Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
			{Key: ":status", RawValue: []byte("200")},
		}},
	}, state)
	if err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if len(resp) != 1 || resp[0].GetResponseHeaders() == nil {
		t.Fatalf("responses = %v, want one response-headers acknowledgement", resp)
	}
	if state.awaitResponseHeaders {
		t.Fatal("successful Bypass did not consume the response-headers obligation")
	}
	if state.lifecycle != lifecycleFinalizePending {
		t.Fatal("successful Bypass did not arm finalization")
	}
	// The bypass must leave a matched unit behind: that record, plus an
	// acknowledgement that changed nothing, is what makes finishStream derive
	// "bypassed" rather than "passthrough".
	if len(state.stream.Info.Matched) == 0 {
		t.Error("bypass recorded no matched unit; the audit outcome would collapse to passthrough")
	}
}

func TestHandleResponseHeaders_MissingInputKeepsObligationAndAuditsError(t *testing.T) {
	tests := []struct {
		name    string
		headers *extProcPb.HttpHeaders
	}{
		{name: "nil message"},
		{name: "missing header map", headers: &extProcPb.HttpHeaders{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := &responseHeadersProbe{}
			s, state, cap := responseHeadersState(probe)

			_, err := s.HandleResponseHeaders(context.Background(), tt.headers, state)
			if err == nil {
				t.Fatal("missing response headers were accepted")
			}
			if probe.calls != 0 {
				t.Fatalf("response filter ran %d times, want 0", probe.calls)
			}
			if !state.awaitResponseHeaders || state.lifecycle == lifecycleFinalizePending {
				t.Fatalf("obligation state = await:%v lifecycle:%v, want awaited and not finalize-pending",
					state.awaitResponseHeaders, state.lifecycle)
			}

			s.finishStream(context.Background(), state, err)
			if len(cap.entries) != 1 || cap.entries[0].Outcome != "error" {
				t.Fatalf("accesslog = %+v, want one error entry", cap.entries)
			}
		})
	}
}

// A finalized stream acknowledges one statically configured response-header
// message without reopening filter dispatch or audit.
func TestHandleResponseHeaders_FinalizedStreamAcknowledgesFirstStaticMessageWithoutDispatch(t *testing.T) {
	probe := &responseHeadersProbe{}
	s, state, cap := responseHeadersState(probe)
	state.awaitResponseHeaders = false
	// An ImmediateResponse already went out, which is what makes the committed
	// entry "blocked".
	state.effect = effectBlocked
	s.finishStream(context.Background(), state, nil)
	headers := &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":status", RawValue: []byte("204")},
	}}}

	responses, err := s.HandleResponseHeaders(context.Background(), headers, state)
	if err != nil {
		t.Fatalf("first static HandleResponseHeaders: %v", err)
	}
	if len(responses) != 1 || responses[0].GetResponseHeaders() == nil {
		t.Fatalf("responses = %+v, want one response-headers acknowledgement", responses)
	}
	if probe.calls != 0 {
		t.Fatalf("response filter ran %d times after terminal finalization, want 0", probe.calls)
	}
	if state.lifecycle == lifecycleFinalizePending {
		t.Fatal("already finalized stream armed another finalization")
	}
	if len(cap.entries) != 1 || cap.entries[0].Outcome != "blocked" {
		t.Fatalf("accesslog = %+v, want one committed blocked entry", cap.entries)
	}
}

// capturedAuditLogger collects every audit Entry the handler submits so
// tests can assert on outcomes without depending on a real worker
// goroutine. Implements accesslog.Logger.
type capturedAuditLogger struct {
	mu      sync.Mutex
	entries []accesslog.Entry
}

func (c *capturedAuditLogger) Submit(e accesslog.Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
}

func (c *capturedAuditLogger) last(t *testing.T) accesslog.Entry {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}
	return c.entries[len(c.entries)-1]
}

// Compile-time check that capturedAuditLogger implements accesslog.Logger.
var _ accesslog.Logger = (*capturedAuditLogger)(nil)

// TestHandleRequestHeaders_NoPodIdentity verifies that when filter_state
// does not carry pod identity (e.g. the upstream metadata-exchange filter
// is misconfigured), the handler passes the request through by default and
// denies it only under the explicit fail-closed switch.
func TestHandleRequestHeaders_NoPodIdentity(t *testing.T) {
	// attrs with empty pod name + namespace simulates Envoy not populating
	// filter_state['downstream_peer'].
	run := func(failClosed bool) ([]*extProcPb.ProcessingResponse, *capturedAuditLogger) {
		cap := &capturedAuditLogger{}
		srv := NewServer(ServerDeps{
			Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
				t.Fatal("resolver called without a valid pod identity")
				return engine.Resolution{}, nil
			},
			AuditLogger:                 cap,
			FailClosedOnMissingIdentity: failClosed,
		})
		state := newStreamState()
		responses, err := srv.HandleRequestHeaders(
			context.Background(),
			makeRequestHeaders("api.example.com", "/admin", "GET"),
			makeAttrsWithLabels("", "", ""),
			state,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(responses) != 1 {
			t.Fatalf("expected 1 response, got %d", len(responses))
		}
		srv.finishStream(context.Background(), state, nil)
		return responses, cap
	}

	t.Run("default passes through", func(t *testing.T) {
		responses, cap := run(false)
		if _, ok := responses[0].Response.(*extProcPb.ProcessingResponse_RequestHeaders); !ok {
			t.Fatalf("expected pass-through RequestHeaders, got %T", responses[0].Response)
		}
		entry := cap.last(t)
		if entry.Pod.Name != "" || entry.Pod.Namespace != "" {
			t.Errorf("expected empty Pod in audit entry, got %+v", entry.Pod)
		}
	})

	t.Run("fail-closed denies", func(t *testing.T) {
		responses, _ := run(true)
		imm, ok := responses[0].Response.(*extProcPb.ProcessingResponse_ImmediateResponse)
		if !ok {
			t.Fatalf("expected ImmediateResponse deny, got %T", responses[0].Response)
		}
		if code := imm.ImmediateResponse.GetStatus().GetCode(); code != missingIdentityStatus {
			t.Errorf("status = %v, want %v", code, missingIdentityStatus)
		}
		if got := imm.ImmediateResponse.GetDetails(); got != missingIdentityDetails {
			t.Errorf("details = %q, want %q", got, missingIdentityDetails)
		}
	})
}

// TestTrailerPassThroughAndBodyOrderValidation covers the trailer stubs and
// verifies that body handlers reject messages they did not request.
func TestTrailerPassThroughAndBodyOrderValidation(t *testing.T) {
	srv := NewServer(ServerDeps{})
	ctx := context.Background()

	if _, err := srv.HandleRequestBody(ctx, &extProcPb.HttpBody{EndOfStream: true}, nil); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("HandleRequestBody without state: err=%v, want FailedPrecondition", err)
	}
	if r, err := srv.HandleRequestTrailers(ctx, nil); err != nil || len(r) != 1 {
		t.Errorf("HandleRequestTrailers: got len=%d err=%v", len(r), err)
	}
	if _, err := srv.HandleResponseBody(ctx, &extProcPb.HttpBody{}, nil); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("HandleResponseBody without state: err=%v, want FailedPrecondition", err)
	}
	if r, err := srv.HandleResponseTrailers(ctx, nil); err != nil || len(r) != 1 {
		t.Errorf("HandleResponseTrailers: got len=%d err=%v", len(r), err)
	}
}

// TestHandleRequestHeaders_AuditEntry_NilLoggerDoesNotPanic guards against
// regressions in NewServer's nil-default: the handler must still produce a
// passthrough response when ServerDeps.AuditLogger is nil.
func TestHandleRequestHeaders_AuditEntry_NilLoggerDoesNotPanic(t *testing.T) {
	srv := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{}, nil
		},
		// AuditLogger intentionally nil.
	})
	if _, err := srv.HandleRequestHeaders(
		context.Background(),
		makeRequestHeaders("api.example.com", "/x", "GET"),
		makeAttrsWithLabels("default", "pod-x", testLabelsB64),
		newStreamState(),
	); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}
