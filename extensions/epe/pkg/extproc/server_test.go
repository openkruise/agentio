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
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// A request carrying HTTP trailers makes Envoy flush the complete buffered
// body as one message with EndOfStream=false (ext_proc.cc onTrailers, "sending
// data left over in the buffer"). Trailer mode is SKIP, so no further body
// message follows. The verdict must be rendered on that message: withholding
// it until an EndOfStream that never comes acknowledges the body, and
// acknowledging releases it upstream unjudged.
func TestProcessRequestBody_TrailerFlushedBodyIsJudged(t *testing.T) {
	fp := &bodyProbe{bodyAct: filter.Stop(filter.Reply{Status: 403})}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("recording-test", fp)}, nil)
	logger := log.FromContext(context.Background())
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"denied"}}`)

	resp, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        body,
		EndOfStream: false,
	}, state, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.bodyCalls == 0 {
		t.Fatal("body phase never ran: the trailer-flushed body was released unjudged")
	}
	if string(fp.receivedBody) != string(body) {
		t.Errorf("body phase received %q, want the complete body %q", fp.receivedBody, body)
	}
	if len(resp) == 0 {
		t.Fatal("expected a response")
	}
	if resp[0].GetImmediateResponse() == nil {
		t.Fatalf("want the deny verdict as an ImmediateResponse, got %T", resp[0].Response)
	}
}

// While a body need is pending, no body message may be answered with a bare
// pass-through acknowledgement: acknowledging is what releases the bytes
// toward the upstream, so an ack without a verdict is a release without a
// verdict. This must hold whatever EndOfStream says.
func TestProcessRequestBody_PendingBodyNeedIsNeverAcknowledgedUnjudged(t *testing.T) {
	for _, eos := range []bool{false, true} {
		fp := &bodyProbe{bodyAct: filter.Stop(filter.Reply{Status: 452})}
		s, state := pendingBodyState(t, []filter.Registration{fixedReg("recording-test", fp)}, nil)
		logger := log.FromContext(context.Background())

		resp, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
			Body:        []byte(`{"jsonrpc":"2.0","method":"tools/call"}`),
			EndOfStream: eos,
		}, state, logger)
		if err != nil {
			t.Fatalf("endOfStream=%v: unexpected error: %v", eos, err)
		}
		if fp.bodyCalls != 1 {
			t.Fatalf("endOfStream=%v: body phase ran %d times, want exactly 1", eos, fp.bodyCalls)
		}
		if len(resp) != 1 {
			t.Fatalf("endOfStream=%v: want exactly one response, got %d", eos, len(resp))
		}
		if resp[0].GetImmediateResponse() == nil {
			t.Fatalf("endOfStream=%v: the filter's deny must reach Envoy, got %T", eos, resp[0].Response)
		}
	}
}

// A message shorter than the complete body is judged on what arrived rather
// than acknowledged. BUFFERED does not produce short messages, so this pins
// the fail-closed direction for the case where one somehow appears.
func TestProcessRequestBody_ShortBodyIsJudgedNotReleased(t *testing.T) {
	fp := &bodyProbe{}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("recording-test", fp)}, nil)
	logger := log.FromContext(context.Background())
	truncated := []byte(`{"jsonrpc":"2.0","met`)

	if _, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        truncated,
		EndOfStream: false,
	}, state, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.bodyCalls != 1 {
		t.Fatalf("body phase ran %d times, want exactly 1", fp.bodyCalls)
	}
	if string(fp.receivedBody) != string(truncated) {
		t.Errorf("body phase received %q, want %q", fp.receivedBody, truncated)
	}
}

// A single chunk with EndOfStream=true still works with body handlers
// present.
func TestProcessRequestBody_SingleChunk_NonStreamingServer(t *testing.T) {
	fp := &bodyProbe{}
	s, state := pendingBodyState(t, []filter.Registration{fixedReg("recording-test", fp)}, nil)
	logger := log.FromContext(context.Background())
	body := []byte(`{"complete":"body"}`)

	resp, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        body,
		EndOfStream: true,
	}, state, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.bodyCalls == 0 {
		t.Fatal("body phase should run on single-chunk EOS")
	}
	if string(fp.receivedBody) != string(body) {
		t.Errorf("body phase received %q, want %q", fp.receivedBody, body)
	}
	if len(resp) == 0 {
		t.Fatal("expected response")
	}
}

// A body message without an outstanding body obligation is a protocol error.
func TestProcessRequestBody_RejectsWithoutObligation(t *testing.T) {
	state := newStreamState()
	s := NewServer(ServerDeps{})
	logger := log.FromContext(context.Background())

	resp, err := s.processRequestBody(context.Background(), &extProcPb.HttpBody{
		Body:        []byte("data"),
		EndOfStream: true,
	}, state, logger)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error = %v, want FailedPrecondition", err)
	}
	if len(resp) != 0 {
		t.Fatalf("responses = %v, want none", resp)
	}
}

// The audit outcome must come from what was sent, not from what the engine
// intended: a stream whose units matched but whose responses changed nothing
// is bypassed, and one where no unit matched at all is passthrough.
func TestFinishStream_OutcomeIsDerivedFromSentResponses(t *testing.T) {
	tests := []struct {
		name    string
		effect  messageEffect
		matched []filter.UnitRecord
		err     error
		want    string
	}{
		{
			name: "no units matched",
			want: "passthrough",
		},
		{
			name:    "units matched but nothing was modified",
			matched: []filter.UnitRecord{{ID: filter.UnitID{Name: "r1"}}},
			want:    "bypassed",
		},
		{
			name:    "a mutation was sent",
			effect:  effectMutated,
			matched: []filter.UnitRecord{{ID: filter.UnitID{Name: "r1"}}},
			want:    "mutated",
		},
		{
			name:    "an immediate response was sent",
			effect:  effectBlocked,
			matched: []filter.UnitRecord{{ID: filter.UnitID{Name: "r1"}}},
			want:    "blocked",
		},
		{
			name:    "an error outranks a block",
			effect:  effectBlocked,
			matched: []filter.UnitRecord{{ID: filter.UnitID{Name: "r1"}}},
			err:     errors.New("send failed"),
			want:    "error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := newStreamState()
			state.lifecycle = lifecycleActive
			state.effect = tc.effect
			state.stream.Info.Matched = tc.matched

			s := &Server{}
			s.finishStream(context.Background(), state, tc.err)

			if got := state.stream.Info.Outcome.String(); got != tc.want {
				t.Errorf("Outcome = %q, want %q", got, tc.want)
			}
		})
	}
}

// A filter that failed closed already recorded why the request was denied. A
// transport error arriving afterwards used to overwrite it, erasing the only
// account of why anything was blocked and leaving the far less useful "the
// stream died" in its place.
func TestFinishStream_StreamErrorDoesNotEraseTheFilterReason(t *testing.T) {
	state := newStreamState()
	state.lifecycle = lifecycleActive
	state.effect = effectBlocked
	state.stream.Info.Matched = []filter.UnitRecord{{ID: filter.UnitID{Name: "r1"}}}
	state.stream.Info.Error = "authz: upstream unreachable"

	s := &Server{}
	s.finishStream(context.Background(), state, errors.New("stream reset"))

	if got := state.stream.Info.Error; got != "authz: upstream unreachable" {
		t.Errorf("Info.Error = %q, want the filter's reason preserved", got)
	}
	// The stream still ended in an error, so the outcome reports that — only the
	// explanation is the filter's.
	if got := state.stream.Info.Outcome.String(); got != "error" {
		t.Errorf("Outcome = %q, want error", got)
	}
}

// With no filter reason recorded, the stream error is the only explanation there
// is, so it must still be reported.
func TestFinishStream_StreamErrorIsRecordedWhenNothingElseExplains(t *testing.T) {
	state := newStreamState()
	state.lifecycle = lifecycleActive

	s := &Server{}
	s.finishStream(context.Background(), state, errors.New("stream reset"))

	if got := state.stream.Info.Error; got != "stream reset" {
		t.Errorf("Info.Error = %q, want \"stream reset\"", got)
	}
}
