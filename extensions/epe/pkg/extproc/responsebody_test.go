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
	"strings"
	"testing"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

type responseBodyProbe struct {
	requirement filter.BodyRequirement
	filter.PassThrough
	headerMutations  []filter.Mutation
	bodyAct          filter.Action
	bodyErr          error
	headerCalls      int
	bodyCalls        int
	receivedBody     []byte
	receivedComplete bool
}

func (p *responseBodyProbe) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	p.headerCalls++
	return filter.NeedBody(p.requirement, p.headerMutations...), nil
}

func (p *responseBodyProbe) OnResponseBody(_ context.Context, _ *filter.Stream, body filter.Body) (filter.Action, error) {
	p.bodyCalls++
	p.receivedBody = append([]byte(nil), body.Bytes...)
	p.receivedComplete = body.Complete
	if p.bodyErr != nil {
		return filter.Continue(), p.bodyErr
	}
	if p.bodyAct.Equal(filter.Action{}) {
		return filter.Continue(), nil
	}
	return p.bodyAct, nil
}

func responseBodyReg(name string, p filter.Filter, policy filter.FailurePolicy) filter.Registration {
	return filter.Registration{
		Name:       name,
		Phases:     filter.PhaseRequestHeaders | filter.PhaseResponseHeaders | filter.PhaseResponseBody,
		OnError:    func(any) filter.FailurePolicy { return policy },
		Parse:      func(json.RawMessage) (any, error) { return struct{}{}, nil },
		Subscribes: func(any) filter.Phase { return filter.PhaseResponseHeaders },
		New:        func(filter.ErasedRuleConfig) filter.Filter { return p },
	}
}

func pendingResponseBodyState(t *testing.T, p *responseBodyProbe, policy filter.FailurePolicy) (*Server, *streamState, []*extProcPb.ProcessingResponse) {
	t.Helper()
	s, _ := wantsServer(t, []filter.Registration{responseBodyReg("response-body", p, policy)}, []string{"r"})
	state := newStreamState()
	runRequestHeaders(t, s, state, false)
	responses, err := s.HandleResponseHeaders(context.Background(), responseHeaderMsg("200"), state)
	if err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	return s, state, responses
}

func TestHandleResponseHeaders_ArmsBufferedResponseBodyObligation(t *testing.T) {
	p := &responseBodyProbe{headerMutations: []filter.Mutation{
		filter.SetHeader("x-delayed", "yes"),
		{Body: []byte("pending replacement"), StatusCode: new(202)},
	}}
	_, state, responses := pendingResponseBodyState(t, p, filter.FailClosed)
	if len(responses) != 1 || responses[0].GetResponseHeaders() == nil {
		t.Fatalf("responses = %+v, want one response-headers acknowledgement", responses)
	}
	mode := responses[0].GetModeOverride()
	if mode == nil || mode.GetResponseBodyMode() != extProcV3.ProcessingMode_BUFFERED {
		t.Fatalf("response body mode = %v, want BUFFERED", mode)
	}
	if mutation := responses[0].GetResponseHeaders().GetResponse().GetHeaderMutation(); mutation != nil {
		t.Fatalf("buffered headers leaked mutation: %+v", mutation)
	}
	common := responses[0].GetResponseHeaders().GetResponse()
	if common.GetBodyMutation() != nil || common.GetStatus() != extProcPb.CommonResponse_CONTINUE {
		t.Fatalf("header body replacement bypassed registered body checks: %+v", common)
	}
	if state.responseBodyContinuation == nil || !state.awaitingInput() {
		t.Fatal("response body obligation was not retained")
	}
	if state.awaitResponseHeaders || state.lifecycle == lifecycleFinalizePending {
		t.Fatalf("response headers state = await:%v lifecycle:%v", state.awaitResponseHeaders, state.lifecycle)
	}
}

func TestHandleResponseHeaders_EndOfStreamRunsResponseBodyInline(t *testing.T) {
	p := &responseBodyProbe{bodyAct: filter.Continue(filter.SetHeader("x-inline", "yes"))}
	s, _ := wantsServer(t, []filter.Registration{responseBodyReg("response-body", p, filter.FailClosed)}, []string{"r"})
	state := newStreamState()
	runRequestHeaders(t, s, state, false)
	headers := responseHeaderMsg("204")
	headers.EndOfStream = true
	responses, err := s.HandleResponseHeaders(context.Background(), headers, state)
	if err != nil {
		t.Fatalf("HandleResponseHeaders: %v", err)
	}
	if p.bodyCalls != 1 || len(p.receivedBody) != 0 || !p.receivedComplete {
		t.Fatalf("inline body calls=%d body=%q complete=%v", p.bodyCalls, p.receivedBody, p.receivedComplete)
	}
	if responses[0].GetModeOverride() != nil || state.responseBodyContinuation != nil {
		t.Fatal("bodyless response armed a future response-body delivery")
	}
	if state.lifecycle != lifecycleFinalizePending {
		t.Fatalf("lifecycle = %v, want finalize pending after inline completion", state.lifecycle)
	}
}

func TestHandleResponseBody_ResumesAndTranslatesFinalResult(t *testing.T) {
	statusAccepted := 202
	p := &responseBodyProbe{
		headerMutations: []filter.Mutation{filter.SetHeader("x-header", "delayed")},
		bodyAct: filter.Continue(
			filter.SetHeader("x-body", "done"),
			filter.Mutation{Body: []byte("rewritten"), StatusCode: &statusAccepted},
		),
	}
	s, state, _ := pendingResponseBodyState(t, p, filter.FailClosed)
	responses, err := s.HandleResponseBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("original"),
		EndOfStream: false,
	}, state)
	if err != nil {
		t.Fatalf("HandleResponseBody: %v", err)
	}
	if p.bodyCalls != 1 || string(p.receivedBody) != "original" || !p.receivedComplete {
		t.Fatalf("probe calls=%d body=%q complete=%v", p.bodyCalls, p.receivedBody, p.receivedComplete)
	}
	if state.responseBodyContinuation != nil || state.awaitingInput() {
		t.Fatal("response body obligation was not consumed")
	}
	if state.lifecycle != lifecycleFinalizePending {
		t.Fatalf("lifecycle = %v, want finalize pending", state.lifecycle)
	}
	common := responses[0].GetResponseBody().GetResponse()
	if common == nil || string(common.GetBodyMutation().GetBody()) != "rewritten" {
		t.Fatalf("ResponseBody CommonResponse = %+v", common)
	}
	for name, want := range map[string]string{
		"x-header":       "delayed",
		"x-body":         "done",
		"content-length": "9",
		":status":        "202",
	} {
		if got, ok := mutationSetValue(common.GetHeaderMutation(), name); !ok || got != want {
			t.Errorf("%s = %q present=%v, want %q", name, got, ok, want)
		}
	}
	if _, err := s.HandleResponseBody(context.Background(), &extProcPb.HttpBody{Body: []byte("duplicate")}, state); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("duplicate body error = %v, want FailedPrecondition", err)
	}
	if p.bodyCalls != 1 {
		t.Fatalf("body callback ran %d times, want once", p.bodyCalls)
	}
}

func TestHandleResponseBody_FailClosedReturnsImmediateWithoutHandlerError(t *testing.T) {
	boom := errors.New("webhook unavailable")
	p := &responseBodyProbe{
		headerMutations: []filter.Mutation{filter.SetHeader("x-discard", "yes")},
		bodyErr:         boom,
	}
	s, state, _ := pendingResponseBodyState(t, p, filter.FailClosed)
	responses, err := s.HandleResponseBody(context.Background(), &extProcPb.HttpBody{Body: []byte("body")}, state)
	if err != nil {
		t.Fatalf("configured FailClosed returned handler error: %v", err)
	}
	immediate := responses[0].GetImmediateResponse()
	if immediate == nil || immediate.GetStatus().GetCode() != 500 || immediate.GetDetails() != "epe_response_body_failed_closed" {
		t.Fatalf("ImmediateResponse = %+v", immediate)
	}
	if state.lifecycle != lifecycleFinalizePending {
		t.Fatalf("lifecycle = %v, want finalize pending after send", state.lifecycle)
	}
}

func TestHandleResponseBody_ValidatesMessageOrderAndInput(t *testing.T) {
	s := NewServer(ServerDeps{})
	state := newStreamState()
	state.markRequestSeen()
	if _, err := s.HandleResponseBody(context.Background(), &extProcPb.HttpBody{}, state); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("body without continuation error = %v, want FailedPrecondition", err)
	}

	p := &responseBodyProbe{}
	s, state, _ = pendingResponseBodyState(t, p, filter.FailClosed)
	if _, err := s.HandleResponseBody(context.Background(), nil, state); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil body error = %v, want InvalidArgument", err)
	}
	if state.responseBodyContinuation == nil || !state.awaitingInput() {
		t.Fatal("invalid body input consumed the outstanding obligation")
	}
}

func TestProcess_ResponseBodyObligationAtEOFIsAnError(t *testing.T) {
	p := &responseBodyProbe{}
	cap := &captureLogger{}
	reg := responseBodyReg("response-body", p, filter.FailClosed)
	base, _ := wantsServer(t, []filter.Registration{reg}, []string{"r"})
	base = NewServer(ServerDeps{
		Resolve:       base.resolve,
		Registrations: []filter.Registration{reg},
		AuditLogger:   cap,
	})
	headers := makeRequestHeaders("api.example.com", "/x", "GET")
	headers.EndOfStream = true
	stream := &collectingStream{
		ctx: context.Background(),
		msgs: []*extProcPb.ProcessingRequest{
			{
				Request:    &extProcPb.ProcessingRequest_RequestHeaders{RequestHeaders: headers},
				Attributes: makeAttrsWithLabels("default", "pod", testLabelsB64),
			},
			{Request: &extProcPb.ProcessingRequest_ResponseHeaders{ResponseHeaders: responseHeaderMsg("200")}},
		},
	}
	err := base.Process(stream)
	if err == nil || !strings.Contains(err.Error(), "outstanding processing obligation") {
		t.Fatalf("Process error = %v, want outstanding obligation", err)
	}
	if len(cap.entries) != 1 || cap.entries[0].Outcome != "error" {
		t.Fatalf("access log entries = %+v, want one error", cap.entries)
	}
}
