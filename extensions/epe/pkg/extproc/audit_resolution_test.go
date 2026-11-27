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

// Stream-end audit invariants: exactly one entry per stream, reflecting
// the final verdict the client actually received — including verdicts
// rendered in the body phase.
package extproc

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	auditlog "github.com/openkruise/agentio/extensions/epe/pkg/audit/log"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/contentguard"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

// captureLogger records every submitted auditlog entry so a test can assert
// how many were submitted and what they say.
type captureLogger struct {
	entries []auditlog.Entry
	content []auditlog.ContentEntry
}

func (c *captureLogger) Submit(r auditlog.Record) {
	switch e := r.(type) {
	case auditlog.Entry:
		c.entries = append(c.entries, e)
	case auditlog.ContentEntry:
		c.content = append(c.content, e)
	}
}

func TestContentGuardBodyDemandAudit(t *testing.T) {
	id := filter.UnitID{Name: "capture"}
	for _, tc := range []struct {
		name   string
		method string
		mode   extProcV3.ProcessingMode_BodySendMode
		early  bool
	}{
		{"streamed", http.MethodPost, extProcV3.ProcessingMode_STREAMED, false},
		{"buffered", http.MethodPost, extProcV3.ProcessingMode_BUFFERED, false},
		{"response finishes before upload", http.MethodPost, extProcV3.ProcessingMode_STREAMED, true},
		{"CONNECT passes without body capture", http.MethodConnect, extProcV3.ProcessingMode_NONE, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			regs, err := filter.Build(contentguard.Definition())
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := regs[0].Parse([]byte(`{"format":"text","response":{"enabled":true,"format":"text"}}`))
			if err != nil {
				t.Fatal(err)
			}
			if tc.mode == extProcV3.ProcessingMode_BUFFERED {
				regs[0].OnError = filter.Always[any](filter.FailOpen)
			}
			logger := &captureLogger{}
			s := NewServer(ServerDeps{
				Registrations: regs,
				AuditLogger:   logger,
				Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
					return engine.Resolution{Units: []engine.Unit{{ID: id, Cfgs: []any{cfg}}}}, nil
				},
			})
			state := newStreamState()
			req := makeRequestHeaders("example.com:443", "/", tc.method)
			media := &corepb.HeaderValue{Key: "content-type", RawValue: []byte("text/plain")}
			req.Headers.Headers = append(req.Headers.Headers, media)
			out, err := s.HandleRequestHeaders(t.Context(), req, makeAttrsWithLabels("test", "pod", ""), state)
			if err != nil || len(out) != 1 || out[0].GetRequestHeaders() == nil ||
				out[0].GetModeOverride().GetRequestBodyMode() != tc.mode {
				t.Fatalf("request headers: %v, %v", out, err)
			}
			if tc.method != http.MethodConnect {
				body := &extProcPb.HttpBody{Body: []byte("hello"), EndOfStream: !tc.early}
				if _, err := s.HandleRequestBody(t.Context(), body, state); err != nil {
					t.Fatal(err)
				}
			}
			resp := responseHeaderMsg("200")
			resp.Headers.Headers = append(resp.Headers.Headers, media)
			out, err = s.HandleResponseHeaders(t.Context(), resp, state)
			if err != nil || len(out) != 1 || out[0].GetResponseHeaders() == nil ||
				out[0].GetModeOverride().GetResponseBodyMode() != tc.mode {
				t.Fatalf("response headers: %v, %v", out, err)
			}
			if tc.method != http.MethodConnect {
				body := &extProcPb.HttpBody{Body: []byte("world"), EndOfStream: true}
				if _, err := s.HandleResponseBody(t.Context(), body, state); err != nil {
					t.Fatal(err)
				}
				record, ok := state.stream.Info.ResponseContent(id)
				if !ok || record.Status != "complete" || record.Content != "world" {
					t.Fatalf("response content: %+v", record)
				}
			}
			s.finishStream(t.Context(), state, nil)
			if tc.method == http.MethodConnect {
				want := filter.ContentRecord{Status: "unsupported_tunnel"}
				if len(logger.content) != 2 || logger.content[0].Direction != "request" ||
					logger.content[1].Direction != "response" || logger.content[0].Record != want ||
					logger.content[1].Record != want {
					t.Fatalf("CONNECT audit: %+v", logger.content)
				}
			}
			var wantSkipped []string
			if tc.early {
				wantSkipped = []string{"contentguard:need-body:" + id.String()}
			}
			if len(logger.entries) != 1 || !slices.Equal(logger.entries[0].Skipped, wantSkipped) {
				t.Fatalf("audit entries: %+v, want skipped %v", logger.entries, wantSkipped)
			}
		})
	}
}

// finishStream is reachable from every teardown path; exactly one entry
// must result, or an operator counting denials double-counts them.
func TestFinishStream_IsIdempotent(t *testing.T) {
	cap := &captureLogger{}
	s := NewServer(ServerDeps{AuditLogger: cap})
	state := newStreamState()
	state.markRequestSeen()

	s.finishStream(context.Background(), state, nil)
	s.finishStream(context.Background(), state, nil)
	s.finishStream(context.Background(), state, nil)

	if len(cap.entries) != 1 {
		t.Fatalf("want exactly 1 entry from 3 calls, got %d", len(cap.entries))
	}
}

// A stream that never carried a request must not produce an empty entry.
func TestFinishStream_NoRequestNoEntry(t *testing.T) {
	cap := &captureLogger{}
	s := NewServer(ServerDeps{AuditLogger: cap})
	s.finishStream(context.Background(), newStreamState(), nil)
	if len(cap.entries) != 0 {
		t.Fatalf("want no entry for a requestless stream, got %d", len(cap.entries))
	}
}

// A verdict rendered in the body phase must be what the audit records: the
// client saw a 403; an entry saying "passthrough" is actively misleading,
// and an operator whose audit `when` filters on result == "blocked" never
// sees the event at all.
func TestStreamEnd_BodyPhaseDenyIsAudited(t *testing.T) {
	cap := &captureLogger{}
	fp := &bodyProbe{bodyAct: filter.Stop(filter.Reply{Status: 403, Body: []byte("denied in body phase")})}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("body-deny-test", fp)}, cap)

	resp, err := sendRequestBody(t, s, state, &extProcPb.HttpBody{
		Body:        []byte(`{"method":"tools/call"}`),
		EndOfStream: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) == 0 || resp[0].GetImmediateResponse() == nil {
		t.Fatalf("want an ImmediateResponse deny, got %v", resp)
	}
	s.finishStream(context.Background(), state, nil)

	if len(cap.entries) != 1 {
		t.Fatalf("want exactly 1 auditlog entry, got %d", len(cap.entries))
	}
	got := cap.entries[0]
	if got.Outcome != "blocked" {
		t.Errorf("Outcome = %q, want blocked — the body-phase verdict must be what is recorded", got.Outcome)
	}
	if len(got.Skipped) != 0 {
		t.Errorf("Skipped = %v, want empty — the filter decided, it was not skipped", got.Skipped)
	}
	if len(got.Actions) == 0 {
		t.Error("Actions is empty; the deciding filter must be attributed")
	}
}

// A body-phase mutation must be attributed to the mutating filter, not
// left in Skipped.
func TestStreamEnd_BodyPhaseMutateIsAudited(t *testing.T) {
	cap := &captureLogger{}
	fp := &bodyProbe{bodyAct: filter.Continue(filter.SetHeader("x-body-phase", "1"))}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("body-mutate-test", fp)}, cap)

	if _, err := sendRequestBody(t, s, state, &extProcPb.HttpBody{
		Body:        []byte(`{}`),
		EndOfStream: true,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.finishStream(context.Background(), state, nil)

	if len(cap.entries) != 1 {
		t.Fatalf("want exactly 1 auditlog entry, got %d", len(cap.entries))
	}
	got := cap.entries[0]
	if got.Outcome != "mutated" {
		t.Errorf("Outcome = %q, want mutated", got.Outcome)
	}
	if len(got.Skipped) != 0 {
		t.Errorf("Skipped = %v, want empty — the filter mutated, it was not skipped", got.Skipped)
	}
}

// A FailClosed error in the body phase is a blocked policy result on the wire,
// while the original failure remains in the audit error field.
func TestStreamEnd_BodyPhaseErrorIsAudited(t *testing.T) {
	cap := &captureLogger{}
	fp := &bodyProbe{bodyErr: errors.New("boom")}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("body-err-test", fp)}, cap)

	responses, err := sendRequestBody(t, s, state, &extProcPb.HttpBody{
		Body:        []byte(`{}`),
		EndOfStream: true,
	})
	if err != nil {
		t.Fatalf("configured FailClosed returned handler error: %v", err)
	}
	if len(responses) != 1 || responses[0].GetImmediateResponse() == nil {
		t.Fatalf("responses = %+v, want local FailClosed response", responses)
	}
	s.finishStream(context.Background(), state, nil)

	if len(cap.entries) != 1 {
		t.Fatalf("want exactly 1 auditlog entry on the error path, got %d", len(cap.entries))
	}
	got := cap.entries[0]
	if got.Error == "" {
		t.Errorf("Error is empty; the body-phase failure must be recorded, entry = %+v", got)
	}
	if got.Outcome != "blocked" {
		t.Errorf("Outcome = %q, want blocked", got.Outcome)
	}
}
