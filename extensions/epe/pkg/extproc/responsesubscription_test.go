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

// Adapter-side tests for the per-rule response-headers subscription: how the
// config-derived demand decides the single ModeOverride, how the response phase
// dispatches to exactly the subscribed pairs (bounded by a bypass), and where a
// demand that can no longer be honoured must fail loudly.
package extproc

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// wantRespFilter declares response-headers demand from the request phase and
// emits the configured ops when the response phase actually dispatches to it.
type wantRespFilter struct {
	filter.PassThrough
	requestAct filter.Action
	responseOp []filter.Mutation
	respCalls  int
	respErr    error
}

func (f *wantRespFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return f.requestAct, nil
}

func (f *wantRespFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.respCalls++
	if f.respErr != nil {
		return filter.Continue(), f.respErr
	}
	return filter.Continue(f.responseOp...), nil
}

// pauseFilter asks for the request body and nothing else. Paired with a later
// registration that declares response demand, it puts that demand in the
// *resumed* portion of the walk — the only place a late want can arise.
type pauseFilter struct {
	filter.PassThrough
	bodyAct filter.Action
}

func (f *pauseFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func (f *pauseFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	if f.bodyAct.Equal(filter.Action{}) {
		return filter.Continue(), nil
	}
	return f.bodyAct, nil
}

// respReg registers f as a filter declaring both header phases.
func respReg(name string, f filter.Filter) filter.Registration {
	return filter.Registration{
		Name:       name,
		Phases:     filter.PhaseRequestHeaders | filter.PhaseResponseHeaders,
		OnError:    func(any) filter.FailurePolicy { return filter.FailClosed },
		Parse:      func(json.RawMessage) (any, error) { return struct{}{}, nil },
		Subscribes: func(any) filter.Phase { return filter.PhaseResponseHeaders },
		New:        func(filter.ErasedRuleConfig) filter.Filter { return f },
	}
}

// pauseReg registers a body-pausing filter.
func pauseReg(name string, f filter.Filter) filter.Registration {
	return filter.Registration{
		Name:    name,
		Phases:  filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		OnError: func(any) filter.FailurePolicy { return filter.FailClosed },
		Parse:   func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New:     func(filter.ErasedRuleConfig) filter.Filter { return f },
	}
}

// wantsServer builds a Server whose resolver yields one unit per name, each
// carrying a config for every registration.
func wantsServer(t *testing.T, regs []filter.Registration, names []string) (*Server, []filter.UnitID) {
	t.Helper()
	ids := make([]filter.UnitID, 0, len(names))
	units := make([]engine.Unit, 0, len(names))
	for i, n := range names {
		id := filter.UnitID{Scope: "default/p1", Name: n, Ordinal: i}
		ids = append(ids, id)
		cfgs := make([]any, len(regs))
		for j := range regs {
			cfgs[j] = struct{}{}
		}
		units = append(units, engine.Unit{
			ID:    id,
			Scope: inputs.NewScope(inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil),
			Cfgs:  cfgs,
		})
	}
	s := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Units: units}, nil
		},
		Registrations: regs,
	})
	return s, ids
}

func responseHeaderMsg(status string) *extProcPb.HttpHeaders {
	return &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
		{Key: ":status", RawValue: []byte(status)},
	}}}
}

// runRequestHeaders drives the headers phase and returns the responses.
func runRequestHeaders(t *testing.T, s *Server, state *streamState, endOfStream bool) []*extProcPb.ProcessingResponse {
	t.Helper()
	headers := makeRequestHeaders("api.example.com", "/x", "POST")
	headers.EndOfStream = endOfStream
	resp, err := s.HandleRequestHeaders(context.Background(), headers,
		makeAttrsWithLabels("default", "pod", testLabelsB64), state)
	if err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}
	return resp
}

// A response subscription after a body-consuming rule must still open and run the
// response-header phase.
func TestHandleRequestHeaders_SubscriptionSurvivesAnEarlierPause(t *testing.T) {
	resp := &wantRespFilter{requestAct: filter.Continue()}
	regs := []filter.Registration{
		pauseReg("pause", &pauseFilter{}),
		respReg("resp", resp),
	}
	s, _ := wantsServer(t, regs, []string{"r"})
	state := newStreamState()

	// endOfStream=false: the body arrives as its own message, so the walk really
	// suspends and this reply carries the only ModeOverride the stream will get.
	responses := runRequestHeaders(t, s, state, false)

	mode := responses[0].GetModeOverride()
	if mode == nil {
		t.Fatal("no ModeOverride at all: neither the body nor the response phase was opened")
	}
	if mode.GetRequestBodyMode() != requestBodyMode {
		t.Errorf("RequestBodyMode = %v, want the pausing rule's body request", mode.GetRequestBodyMode())
	}
	if mode.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
		t.Fatalf("ResponseHeaderMode = %v, want SEND: the post-pause rule's response "+
			"mutation would never reach the wire", mode.GetResponseHeaderMode())
	}

	// The separately delivered body must be accepted before response dispatch.
	if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("payload"),
		EndOfStream: true,
	}, state); err != nil {
		t.Fatalf("HandleRequestBody: %v", err)
	}
	if _, err := s.HandleResponseHeaders(context.Background(), responseHeaderMsg("200"), state); err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if resp.respCalls != 1 {
		t.Errorf("response filter ran %d times, want exactly 1", resp.respCalls)
	}
}

func TestHandleRequestHeaders_SubscriptionOpensResponsePhase(t *testing.T) {
	f := &wantRespFilter{requestAct: filter.Continue()}
	s, _ := wantsServer(t, []filter.Registration{respReg("resp", f)}, []string{"r"})
	state := newStreamState()

	resp := runRequestHeaders(t, s, state, false)
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1", len(resp))
	}
	mode := resp[0].GetModeOverride()
	if mode == nil {
		t.Fatal("no ModeOverride: a configured response mutation never reaches Envoy")
	}
	if mode.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
		t.Fatalf("ResponseHeaderMode = %v, want SEND", mode.GetResponseHeaderMode())
	}
	// Both body modes must be restated: the merge base is the static config.
	if mode.GetRequestBodyMode() != extProcV3.ProcessingMode_NONE ||
		mode.GetResponseBodyMode() != extProcV3.ProcessingMode_NONE {
		t.Fatalf("body modes = req:%v resp:%v, want both NONE restated",
			mode.GetRequestBodyMode(), mode.GetResponseBodyMode())
	}
	if !state.awaitResponseHeaders {
		t.Fatal("the subscription did not arm the response-headers obligation")
	}
	// Nothing is stored between the phases, so the promise the ModeOverride made is
	// only real if the response phase actually dispatches to the rule.
	if _, err := s.HandleResponseHeaders(context.Background(), responseHeaderMsg("200"), state); err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if f.respCalls != 1 {
		t.Fatalf("response filter ran %d times, want exactly 1: the ModeOverride promised it", f.respCalls)
	}
}

// plainRespFilter implements the response phase without declaring demand.
type plainRespFilter struct {
	filter.PassThrough
	inner *wantRespFilter
}

func (f *plainRespFilter) OnResponseHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	return f.inner.OnResponseHeaders(ctx, st)
}

// The bodyless resume must preserve subscriptions declared after the pausing filter.
func TestHandleRequestHeaders_BodylessResumeKeepsAPostPauseSubscription(t *testing.T) {
	resp := &wantRespFilter{requestAct: filter.Continue()}
	regs := []filter.Registration{
		pauseReg("pause", &pauseFilter{}),
		respReg("resp", resp),
	}
	// Registration 1 is reached only after registration 0 resumes.
	s, _ := wantsServer(t, regs, []string{"r"})
	state := newStreamState()

	responses := runRequestHeaders(t, s, state, true)
	mode := responses[0].GetModeOverride()
	if mode == nil || mode.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
		t.Fatalf("ModeOverride = %v, want ResponseHeaderMode SEND: the post-pause subscription was dropped", mode)
	}
	if !state.awaitResponseHeaders {
		t.Fatal("bodyless resume did not arm the response-headers obligation")
	}
	if _, err := s.HandleResponseHeaders(context.Background(), responseHeaderMsg("200"), state); err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if resp.respCalls != 1 {
		t.Fatalf("response filter ran %d times, want exactly 1", resp.respCalls)
	}
}

// Response subscription and dispatch are identical with and without a request body.
func TestHandleRequestHeaders_SubscriptionIndependentOfBodyPresence(t *testing.T) {
	for _, endOfStream := range []bool{false, true} {
		name := "with body"
		if endOfStream {
			name = "bodyless"
		}
		t.Run(name, func(t *testing.T) {
			resp := &wantRespFilter{requestAct: filter.Continue()}
			// Registration 0 subscribes; registration 1 then pauses for the body.
			regs := []filter.Registration{
				respReg("resp", resp),
				pauseReg("pause", &pauseFilter{}),
			}
			s, _ := wantsServer(t, regs, []string{"r"})
			state := newStreamState()

			responses := runRequestHeaders(t, s, state, endOfStream)
			mode := responses[0].GetModeOverride()
			if mode == nil || mode.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
				t.Fatalf("ModeOverride = %v, want ResponseHeaderMode SEND", mode)
			}
			if !endOfStream {
				// The body arrives as its own message; drain it before the response.
				if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
					Body:        []byte("payload"),
					EndOfStream: true,
				}, state); err != nil {
					t.Fatalf("HandleRequestBody: %v", err)
				}
			}
			if _, err := s.HandleResponseHeaders(context.Background(), responseHeaderMsg("200"), state); err != nil {
				t.Fatalf("HandleResponseHeaders: %v", err)
			}
			if resp.respCalls != 1 {
				t.Fatalf("response filter ran %d times, want exactly 1", resp.respCalls)
			}
		})
	}
}

type pauseAndWantFilter struct {
	filter.PassThrough
}

func (pauseAndWantFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func (pauseAndWantFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Continue(), nil
}

func (pauseAndWantFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(), nil
}

// A bypass preserves its own response operations.
func TestHandleResponseHeaders_BypassWithDemandStillDispatches(t *testing.T) {
	f := &wantRespFilter{
		requestAct: filter.Bypass(),
		responseOp: []filter.Mutation{{HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "x-epe-policy", Value: "kept"},
		}}},
	}
	s, _ := wantsServer(t, []filter.Registration{respReg("resp", f)}, []string{"r"})
	state := newStreamState()

	responses := runRequestHeaders(t, s, state, false)
	if mode := responses[0].GetModeOverride(); mode == nil ||
		mode.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
		t.Fatalf("ModeOverride = %v, want a bypass with demand to still open the phase", mode)
	}
	if state.lifecycle == lifecycleFinalizePending {
		t.Fatal("bypass finalized the stream before the response phase could run")
	}
	// Commit whatever finalization the headers reply armed, exactly as Process
	// does after Send.
	s.finishAfterSend(context.Background(), state)
	if state.lifecycle == lifecycleFinalized {
		t.Fatal("stream finalized after the headers send; the response phase can no longer run")
	}

	respMsgs, err := s.HandleResponseHeaders(context.Background(), responseHeaderMsg("200"), state)
	if err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if f.respCalls != 1 {
		t.Fatalf("response phase ran %d times, want 1", f.respCalls)
	}
	hm := respMsgs[0].GetResponseHeaders().GetResponse().GetHeaderMutation()
	if hm == nil || len(hm.GetSetHeaders()) != 1 ||
		hm.GetSetHeaders()[0].GetHeader().GetKey() != "x-epe-policy" {
		t.Fatalf("response HeaderMutation = %v, want x-epe-policy set", hm)
	}
}

// A bypass suppresses response operations from later pairs.
func TestHandleResponseHeaders_BypassSuppressesLaterRulesResponseOps(t *testing.T) {
	bypasser := &wantRespFilter{requestAct: filter.Bypass()}
	later := &wantRespFilter{
		requestAct: filter.Continue(),
		responseOp: []filter.Mutation{{HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "x-epe-late", Value: "must-not-apply"},
		}}},
	}
	regs := []filter.Registration{
		respReg("bypass", bypasser),
		respReg("later", later),
	}
	s, _ := wantsServer(t, regs, []string{"r"})
	state := newStreamState()

	responses := runRequestHeaders(t, s, state, false)
	if mode := responses[0].GetModeOverride(); mode == nil ||
		mode.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
		t.Fatalf("ModeOverride = %v, want the phase opened for the bypassing rule's own subscription", mode)
	}
	s.finishAfterSend(context.Background(), state)

	respMsgs, err := s.HandleResponseHeaders(context.Background(), responseHeaderMsg("200"), state)
	if err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if bypasser.respCalls != 1 {
		t.Errorf("bypassing rule's response phase ran %d times, want 1: bypass does not suppress itself", bypasser.respCalls)
	}
	if later.respCalls != 0 {
		t.Fatalf("suppressed rule's response phase ran %d times, want 0: bypass skips all following rules", later.respCalls)
	}
	if hm := respMsgs[0].GetResponseHeaders().GetResponse().GetHeaderMutation(); len(hm.GetSetHeaders()) != 0 {
		t.Fatalf("response HeaderMutation = %v, want none: the suppressed rule's ops reached the wire", hm)
	}
}

// A blocked request opens nothing and finalizing early stays correct: after an
// ImmediateResponse Envoy closes the stream.
func TestHandleRequestHeaders_BlockedOpensNothing(t *testing.T) {
	f := &wantRespFilter{requestAct: filter.Continue()}
	blocker := &stopFilter{}
	regs := []filter.Registration{
		respReg("resp", f),
		respReg("block", blocker),
	}
	s, _ := wantsServer(t, regs, []string{"r"})
	state := newStreamState()

	responses := runRequestHeaders(t, s, state, false)
	if len(responses) != 1 || responses[0].GetImmediateResponse() == nil {
		t.Fatalf("responses = %+v, want a single ImmediateResponse", responses)
	}
	if responses[0].GetModeOverride() != nil {
		t.Fatal("ModeOverride combined with an ImmediateResponse: Envoy applies it before closing")
	}
	if state.lifecycle != lifecycleFinalizePending {
		t.Fatal("a blocked request must finalize after send")
	}
	if state.awaitResponseHeaders {
		t.Fatal("a blocked request armed a response-headers obligation")
	}
}

type stopFilter struct {
	filter.PassThrough
}

func (stopFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Stop(filter.Reply{Status: 403}), nil
}

// Exactly one ModeOverride site per stream: the body-phase reply never carries
// one, because Envoy ignores it there.
func TestHandleRequestBody_NeverCarriesModeOverride(t *testing.T) {
	regs := []filter.Registration{pauseReg("pause", &pauseFilter{})}
	s, _ := wantsServer(t, regs, []string{"r"})
	state := newStreamState()

	runRequestHeaders(t, s, state, false)
	responses, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("data"),
		EndOfStream: true,
	}, state)
	if err != nil {
		t.Fatalf("HandleRequestBody: %v", err)
	}
	for i, r := range responses {
		if r.GetModeOverride() != nil {
			t.Fatalf("body response %d carries a ModeOverride: Envoy ignores it there", i)
		}
	}
}

// Under FailClosed a response-phase failure replaces the upstream response with
// an ImmediateResponse; Envoy holds the response headers while awaiting us.
func TestHandleResponseHeaders_FailClosedEmitsImmediateResponse(t *testing.T) {
	f := &wantRespFilter{requestAct: filter.Continue(), respErr: errRespBoom}
	s, _ := wantsServer(t, []filter.Registration{respReg("resp", f)}, []string{"r"})
	state := newStreamState()
	runRequestHeaders(t, s, state, false)

	responses, err := s.HandleResponseHeaders(context.Background(), responseHeaderMsg("200"), state)
	if err != nil {
		t.Fatalf("configured FailClosed returned handler error: %v", err)
	}
	if len(responses) != 1 || responses[0].GetImmediateResponse() == nil {
		t.Fatalf("responses = %+v, want a single ImmediateResponse", responses)
	}
	im := responses[0].GetImmediateResponse()
	if im.GetStatus().GetCode() != 500 {
		t.Fatalf("immediate status = %v, want 500", im.GetStatus().GetCode())
	}
	if im.GetDetails() != "epe_response_headers_failed_closed" {
		t.Fatalf("details = %q, want the engine's fail-closed marker", im.GetDetails())
	}
}

var errRespBoom = errRespBoomType{}

type errRespBoomType struct{}

func (errRespBoomType) Error() string { return "response render failed" }

// Process sends the FailClosed ImmediateResponse as a handled policy result.
func TestProcess_FailClosedResponsePhaseSendsImmediateResponse(t *testing.T) {
	f := &wantRespFilter{requestAct: filter.Continue(), respErr: errRespBoom}
	s, _ := wantsServer(t, []filter.Registration{respReg("resp", f)}, []string{"r"})

	headers := makeRequestHeaders("api.example.com", "/x", "GET")
	headers.EndOfStream = true
	stream := &collectingStream{
		ctx: context.Background(),
		msgs: []*extProcPb.ProcessingRequest{
			{
				Request:    &extProcPb.ProcessingRequest_RequestHeaders{RequestHeaders: headers},
				Attributes: makeAttrsWithLabels("default", "pod", testLabelsB64),
			},
			{Request: &extProcPb.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: responseHeaderMsg("200"),
			}},
		},
	}
	if err := s.Process(stream); err != nil {
		t.Fatalf("Process returned a gRPC error for configured FailClosed: %v", err)
	}
	if len(stream.sent) == 0 {
		t.Fatal("Process sent nothing")
	}
	last := stream.sent[len(stream.sent)-1]
	im := last.GetImmediateResponse()
	if im == nil {
		t.Fatalf("last response = %T, want the fail-closed ImmediateResponse", last.GetResponse())
	}
	if im.GetStatus().GetCode() != 500 || im.GetDetails() != "epe_response_headers_failed_closed" {
		t.Fatalf("immediate = status %v details %q, want 500 / epe_response_headers_failed_closed",
			im.GetStatus().GetCode(), im.GetDetails())
	}
}

// A filter contract violation is not a configured failure-policy decision.
// Keep surfacing it as a gRPC error so Envoy's failure_mode_allow still owns
// the compatibility behavior for engine/protocol faults.
func TestProcess_ResponseContractFaultRemainsGRPCError(t *testing.T) {
	invalidStatus := 199
	f := &wantRespFilter{
		requestAct: filter.Continue(),
		responseOp: []filter.Mutation{{StatusCode: &invalidStatus}},
	}
	s, _ := wantsServer(t, []filter.Registration{respReg("resp", f)}, []string{"r"})

	headers := makeRequestHeaders("api.example.com", "/x", "GET")
	headers.EndOfStream = true
	stream := &collectingStream{
		ctx: context.Background(),
		msgs: []*extProcPb.ProcessingRequest{
			{
				Request:    &extProcPb.ProcessingRequest_RequestHeaders{RequestHeaders: headers},
				Attributes: makeAttrsWithLabels("default", "pod", testLabelsB64),
			},
			{Request: &extProcPb.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: responseHeaderMsg("200"),
			}},
		},
	}
	err := s.Process(stream)
	if status.Code(err) != codes.Unknown {
		t.Fatalf("Process error = %v (code %v), want a gRPC Unknown contract error", err, status.Code(err))
	}
	for _, response := range stream.sent {
		if response.GetImmediateResponse() != nil {
			t.Fatalf("contract fault sent ImmediateResponse: %+v", response.GetImmediateResponse())
		}
	}
}

// collectingStream replays a fixed request sequence and records what Process
// sent, so a handler error and its accompanying reply can both be observed.
type collectingStream struct {
	extProcPb.ExternalProcessor_ProcessServer
	ctx  context.Context
	msgs []*extProcPb.ProcessingRequest
	next int
	sent []*extProcPb.ProcessingResponse
}

func (s *collectingStream) Context() context.Context { return s.ctx }

func (s *collectingStream) Recv() (*extProcPb.ProcessingRequest, error) {
	if s.next >= len(s.msgs) {
		return nil, io.EOF
	}
	msg := s.msgs[s.next]
	s.next++
	return msg, nil
}

func (s *collectingStream) Send(resp *extProcPb.ProcessingResponse) error {
	s.sent = append(s.sent, resp)
	return nil
}

// clear_route_cache is a no-op in the response direction, so the adapter must
// never set it — even for a header the request path treats as route-affecting.
func TestTranslateResponseHeadersResult_NeverClearsRouteCache(t *testing.T) {
	res := &engine.ResponseHeadersResult{
		Disposition: engine.DispositionMutated,
		HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "host", Value: "elsewhere"},
			{Kind: filter.HeaderAdd, Name: "set-cookie", Value: "a=1"},
			{Kind: filter.HeaderRemove, Name: "server"},
		},
	}
	responses := translateResponseHeadersResult(res)
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	common := responses[0].GetResponseHeaders().GetResponse()
	if common.GetClearRouteCache() {
		t.Error("clear_route_cache set on the response path, where it is a no-op")
	}
	if common.GetStatus() == extProcPb.CommonResponse_CONTINUE_AND_REPLACE {
		t.Error("CONTINUE_AND_REPLACE on the response path force-disables all further response processing")
	}
	if common.GetBodyMutation() != nil {
		t.Error("body mutation emitted on the response path")
	}
	hm := common.GetHeaderMutation()
	if len(hm.GetSetHeaders()) != 2 || len(hm.GetRemoveHeaders()) != 1 {
		t.Fatalf("HeaderMutation = %v, want two sets and one remove", hm)
	}
	if hm.GetSetHeaders()[1].GetAppendAction() != corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD {
		t.Errorf("set-cookie append action = %v, want APPEND_IF_EXISTS_OR_ADD",
			hm.GetSetHeaders()[1].GetAppendAction())
	}
}

// A passthrough response result acks with the matching oneof arm and nothing
// else.
func TestTranslateResponseHeadersResult_PassthroughIsAnEmptyAck(t *testing.T) {
	responses := translateResponseHeadersResult(&engine.ResponseHeadersResult{
		Disposition: engine.DispositionPassthrough,
	})
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	rh := responses[0].GetResponseHeaders()
	if rh == nil {
		t.Fatalf("response arm = %T, want ResponseHeaders", responses[0].GetResponse())
	}
	if rh.GetResponse().GetHeaderMutation() != nil {
		t.Errorf("passthrough carried a HeaderMutation: %v", rh.GetResponse().GetHeaderMutation())
	}
}
