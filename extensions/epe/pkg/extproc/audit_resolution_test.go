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
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	auditlog "github.com/openkruise/agentio/extensions/epe/pkg/audit/log"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// captureLogger records every submitted auditlog entry so a test can assert
// how many were submitted and what they say.
type captureLogger struct{ entries []auditlog.Entry }

func (c *captureLogger) Submit(r auditlog.Record) {
	if e, ok := r.(auditlog.Entry); ok {
		c.entries = append(c.entries, e)
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
