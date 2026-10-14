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

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// recordingStreamLogger stands in for the policy layer's per-stream logger.
type recordingStreamLogger struct {
	calls  int
	result string
}

func (l *recordingStreamLogger) Log(_ context.Context, _ *filter.Stream, info *filter.StreamInfo) {
	l.calls++
	l.result = info.Outcome.String()
}

// resolveOnce returns a resolver that hands out logger and one unit on its
// first call and an empty resolution on every later call.
func resolveOnce(logger filter.StreamLogger, regs int) engine.Resolver {
	calls := 0
	return func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
		calls++
		if calls > 1 {
			return engine.Resolution{}, nil
		}
		return engine.Resolution{
			Units: []engine.Unit{{
				ID:   filter.UnitID{Scope: "default/p", Name: "r"},
				Cfgs: make([]any, regs),
			}},
			StreamLogger: logger,
		}, nil
	}
}

// A resolver that fails may still hand back a logger for the rules that
// matched before the failure. Assigning it before honouring the error is what
// keeps a resolve failure as auditable as an engine-eval failure; skipping it
// leaves `when: result == "error"` blind to a whole class of errors.
func TestResolveErrorStillInstallsStreamLogger(t *testing.T) {
	regs := []filter.Registration{fixedRegHeaders("pass", filter.Continue())}
	logger := &recordingStreamLogger{}
	boom := errors.New("projection failed")
	srv := NewServer(ServerDeps{
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{StreamLogger: logger}, boom
		},
		Registrations: regs,
	})

	ctx := context.Background()
	state := newStreamState()
	_, err := srv.HandleRequestHeaders(ctx,
		makeRequestHeaders("api.example.com", "/", "GET"),
		makeAttrsWithLabels("default", "pod", testLabelsB64), state)
	if !errors.Is(err, boom) {
		t.Fatalf("HandleRequestHeaders err = %v, want the resolver error", err)
	}
	if state.streamLogger != filter.StreamLogger(logger) {
		t.Fatal("resolve failure dropped the stream logger; the failed stream would never be audited")
	}

	srv.finishStream(ctx, state, err)
	if logger.calls != 1 {
		t.Fatalf("logger invoked %d times, want exactly 1", logger.calls)
	}
	if logger.result != "error" {
		t.Errorf("audited result = %q, want \"error\"", logger.result)
	}
}

// The per-stream logger runs after finishStream derives the outcome, so it sees
// the outcome the stream actually ended on. Reading it before the derivation
// reports "passthrough" for a failed stream, which makes any audit entry
// filtering on result == "error" silently never fire.
func TestStreamLoggerObservesFinalOutcome(t *testing.T) {
	regs := []filter.Registration{fixedRegHeaders("pass", filter.Continue())}
	logger := &recordingStreamLogger{}
	srv := NewServer(ServerDeps{Resolve: resolveOnce(logger, len(regs)), Registrations: regs})

	ctx := context.Background()
	state := newStreamState()
	if _, err := srv.HandleRequestHeaders(
		ctx,
		makeRequestHeaders("api.example.com", "/", "GET"),
		makeAttrsWithLabels("default", "pod", testLabelsB64),
		state,
	); err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}

	srv.finishStream(ctx, state, context.Canceled)

	if logger.calls != 1 {
		t.Fatalf("logger invoked %d times, want 1", logger.calls)
	}
	if logger.result != "error" {
		t.Fatalf("logger observed result %q, want %q", logger.result, "error")
	}
}

// A successful finishAfterSend is a committed outcome. Later deferred
// cancellation/error teardown must neither log a second entry nor re-derive the
// committed bypass into an error.
func TestFinishAfterSendCommitCannotBeOverwrittenByLaterTeardown(t *testing.T) {
	accesslog := &capturedAuditLogger{}
	policyLogger := &recordingStreamLogger{}
	srv := NewServer(ServerDeps{AuditLogger: accesslog})
	state := newStreamState()
	state.streamLogger = policyLogger
	// A matched unit whose responses changed nothing is what "bypassed" now
	// means, so set up that shape rather than asserting an outcome directly.
	state.stream.Info.Matched = []filter.UnitRecord{{ID: filter.UnitID{Name: "r1"}}}
	state.stream.Info.RecordContent(
		filter.UnitID{Name: "r1"},
		filter.ContentRecord{Status: "complete", Content: "request"},
	)
	state.stream.Info.RecordResponseContent(
		filter.UnitID{Name: "r1"},
		filter.ContentRecord{Status: "complete", Content: "response"},
	)
	state.lifecycle = lifecycleFinalizePending

	srv.finishAfterSend(context.Background(), state)
	srv.finishStream(context.Background(), state, context.Canceled)
	srv.finishStream(context.Background(), state, errors.New("late receive error"))

	if len(accesslog.entries) != 1 {
		t.Fatalf("accesslog entries = %d, want exactly 1", len(accesslog.entries))
	}
	if got := accesslog.entries[0]; got.Outcome != "bypassed" || got.Error != "" {
		t.Errorf("accesslog entry = %+v, want committed bypass without error", got)
	}
	if len(accesslog.content) != 2 || accesslog.content[0].Direction != "request" ||
		accesslog.content[1].Direction != "response" {
		t.Fatalf("content entries=%+v", accesslog.content)
	}
	if policyLogger.calls != 1 {
		t.Fatalf("policy logger calls = %d, want exactly 1", policyLogger.calls)
	}
	if policyLogger.result != "bypassed" {
		t.Errorf("policy logger result = %q, want bypassed", policyLogger.result)
	}
}

// A stream that never resolved carries no logger, and finishStream must not
// trip over the nil.
func TestFinishStreamWithoutResolutionDoesNotPanic(t *testing.T) {
	srv := NewServer(
		ServerDeps{Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{}, nil
		}},
	)

	state := newStreamState()
	state.markRequestSeen()
	srv.finishStream(context.Background(), state, nil)
}
