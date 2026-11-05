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
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func TestHandleRequestBody_ValidatesMessageOrderAndInput(t *testing.T) {
	s := NewServer(ServerDeps{})
	state := newStreamState()
	state.markRequestSeen()
	if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{}, state); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("body without continuation error = %v, want FailedPrecondition", err)
	}

	s, state = pendingBodyState(t, []filter.Registration{fixedReg("fake-body", &bodyProbe{})}, nil)
	if _, err := s.HandleRequestBody(context.Background(), nil, state); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil body error = %v, want InvalidArgument", err)
	}
	if state.requestBodyContinuation == nil || !state.awaitingInput() {
		t.Fatal("invalid body input consumed the outstanding obligation")
	}
}

func TestHandleRequestBody_SetsBodyAndRunsBodyPhase(t *testing.T) {
	fp := &bodyProbe{bodyAct: filter.Continue(filter.SetHeader("x-test", "injected"))}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("fake-body", fp)}, nil)

	res, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("form-data"),
		EndOfStream: true,
	}, state)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fp.bodyCalls == 0 {
		t.Error("expected the body phase to run")
	}
	if string(fp.receivedBody) != "form-data" {
		t.Errorf("expected body 'form-data', got %q", fp.receivedBody)
	}
	if len(res) == 0 {
		t.Fatal("expected mutation response")
	}
	bodyResp := res[0].GetRequestBody()
	if bodyResp == nil {
		t.Fatalf("expected RequestBody response, got %T", res[0].Response)
	}
	hm := bodyResp.Response.GetHeaderMutation()
	if hm == nil || len(hm.SetHeaders) == 0 {
		t.Fatal("expected header mutation in body response")
	}
	if hm.SetHeaders[0].Header.Key != "x-test" {
		t.Errorf("expected header key x-test, got %s", hm.SetHeaders[0].Header.Key)
	}
	if string(hm.SetHeaders[0].Header.RawValue) != "injected" {
		t.Errorf("expected value 'injected', got %q", hm.SetHeaders[0].Header.RawValue)
	}
}

func TestHandleRequestBody_ConsumesPendingEvaluationOnce(t *testing.T) {
	fp := &bodyProbe{}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("fake-body", fp)}, nil)

	if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("data"),
		EndOfStream: true,
	}, state); err != nil {
		t.Fatalf("first body: %v", err)
	}
	if state.requestBodyContinuation != nil {
		t.Fatal("pending header evaluation was not cleared")
	}
	if state.awaitingRequestBody() {
		t.Fatal("request-body obligation was not consumed")
	}

	if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("duplicate"),
		EndOfStream: true,
	}, state); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("duplicate body error = %v, want FailedPrecondition", err)
	}
	if fp.bodyCalls != 1 {
		t.Fatalf("body phase ran %d times, want exactly once", fp.bodyCalls)
	}
}

func TestHandleRequestBody_ArmsOnlyTerminalFinalization(t *testing.T) {
	tests := []struct {
		name          string
		action        filter.Action
		awaitResponse bool
		wantFinalize  bool
	}{
		{
			name:         "blocked",
			action:       filter.Stop(filter.Reply{Status: 403}),
			wantFinalize: true,
		},
		{
			name:          "blocked retires response obligation",
			action:        filter.Stop(filter.Reply{Status: 403}),
			awaitResponse: true,
			wantFinalize:  true,
		},
		{
			name:         "bypassed without response obligation",
			action:       filter.Bypass(),
			wantFinalize: true,
		},
		{
			name:          "bypassed while awaiting response headers",
			action:        filter.Bypass(),
			awaitResponse: true,
			wantFinalize:  false,
		},
		{
			name:         "ordinary passthrough",
			action:       filter.Continue(),
			wantFinalize: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fp := &bodyProbe{bodyAct: tc.action}
			s, state := pendingBodyState(t, []filter.Registration{fixedReg("fake-body", fp)}, nil)
			state.awaitResponseHeaders = tc.awaitResponse

			if _, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
				Body:        []byte("data"),
				EndOfStream: true,
			}, state); err != nil {
				t.Fatalf("HandleRequestBody: %v", err)
			}
			if got := state.lifecycle == lifecycleFinalizePending; got != tc.wantFinalize {
				t.Fatalf("finalize pending = %v (lifecycle %v), want %v", got, state.lifecycle, tc.wantFinalize)
			}
			if tc.action.Kind() == filter.KindStop && state.awaitResponseHeaders {
				t.Fatal("blocked body result left an impossible response obligation")
			}
		})
	}
}

func TestHandleRequestBody_ContinueYieldsPassthrough(t *testing.T) {
	fp := &bodyProbe{}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("fake-body", fp)}, nil)

	res, err := s.HandleRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("data"),
		EndOfStream: true,
	}, state)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fp.bodyCalls == 0 {
		t.Error("expected the body phase to run")
	}
	if res[0].GetRequestBody() == nil {
		t.Fatalf("expected passthrough body response when the filter continues")
	}
}
