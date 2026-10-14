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

// Tests for the invoke wrapper. These mutate pluginCallsTotal on the
// process-wide registry; no t.Parallel() here, Reset() at the top of every
// counting test.
package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func TestInvoke_CountsByOutcome(t *testing.T) {
	pluginCallsTotal.Reset()
	e := NewEngine(nil, 0)

	tests := []struct {
		name        string
		call        func(context.Context) (filter.Action, error)
		wantOutcome string
	}{
		{"continue", func(context.Context) (filter.Action, error) { return filter.Continue(), nil }, "continue"},
		{"mutate", func(context.Context) (filter.Action, error) {
			return filter.Continue(filter.SetHeader("x", "1")), nil
		}, "mutate"},
		{"immediate", func(context.Context) (filter.Action, error) { return filter.Stop(filter.Reply{}), nil }, "immediate"},
		{"need-body", func(context.Context) (filter.Action, error) { return filter.NeedBody(filter.CompleteBody), nil }, "record"},
		{"error", func(context.Context) (filter.Action, error) { return filter.Continue(), errors.New("boom") }, "error"},
	}
	for _, tt := range tests {
		if _, err := e.invoke(context.Background(), nil, newFilterMetrics("p", phaseRequestHeaders), tt.call); err != nil && tt.wantOutcome != "error" {
			t.Fatalf("%s: unexpected error: %v", tt.name, err)
		}
		got := testutil.ToFloat64(pluginCallsTotal.WithLabelValues("p", phaseRequestHeaders, tt.wantOutcome))
		if got != 1 {
			t.Errorf("%s: calls{outcome=%q} = %v, want 1", tt.name, tt.wantOutcome, got)
		}
	}
}

// headersFunc adapts a headers-phase func to the Filter contract.
type headersFunc struct {
	filter.PassThrough
	fn func(context.Context, *filter.Stream) (filter.Action, error)
}

func (h headersFunc) OnRequestHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	return h.fn(ctx, st)
}

func filterFunc(fn func(context.Context, *filter.Stream) (filter.Action, error)) filter.Filter {
	return headersFunc{fn: fn}
}

// A filter that outlives the phase budget must observe a cancelled
// context, not keep an outbound call running after Envoy has given up. The
// escape hatch is inside the filter func: if no deadline is applied,
// <-ctx.Done() would block forever, so a select arm after it could not
// help. The budget is installed by the Eval* entry points, so the test
// drives a real evaluation.
func TestEvalRequestHeaders_BudgetCancelsOverrunningFilter(t *testing.T) {
	pluginCallsTotal.Reset()
	observed := make(chan error, 1)
	regs := buildRegs(t, []regSpec{{
		name: "slow",
		make: func(filter.RuleConfig[string]) filter.Filter {
			return filterFunc(func(ctx context.Context, _ *filter.Stream) (filter.Action, error) {
				select {
				case <-ctx.Done():
					observed <- ctx.Err()
					return filter.Continue(), ctx.Err()
				case <-time.After(2 * time.Second):
					err := errors.New("no deadline was applied to the filter context")
					observed <- err
					return filter.Continue(), err
				}
			})
		},
	}})
	e := NewEngine(regs, 50*time.Millisecond)

	res, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"cfg"}}))
	if err != nil {
		t.Fatalf("default FailClosed should resolve the deadline into a local reply: %v", err)
	}
	if res.Disposition != DispositionBlocked || res.Reply.Status != 500 {
		t.Fatalf("deadline result = %+v, want local 500 block", res)
	}
	select {
	case obsErr := <-observed:
		if !errors.Is(obsErr, context.DeadlineExceeded) {
			t.Fatalf("filter observed %v, want context.DeadlineExceeded", obsErr)
		}
	case <-time.After(time.Second):
		t.Fatal("filter did not observe cancellation")
	}
}

func TestEvalRequestHeaders_ZeroBudgetImposesNoDeadline(t *testing.T) {
	pluginCallsTotal.Reset()
	var hadDeadline bool
	regs := buildRegs(t, []regSpec{{
		name: "probe",
		make: func(filter.RuleConfig[string]) filter.Filter {
			return filterFunc(func(ctx context.Context, _ *filter.Stream) (filter.Action, error) {
				_, hadDeadline = ctx.Deadline()
				return filter.Continue(), nil
			})
		},
	}})
	e := NewEngine(regs, 0)

	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"cfg"}})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hadDeadline {
		t.Error("a zero budget must not impose a deadline")
	}
}

// phaseProbe defers to the headers phase and probes the ctx deadline in
// the body and response phases, so the withBudget wiring of each Eval*
// entry point is covered, not just the headers one.
type phaseProbe struct {
	filter.PassThrough
	probe func(ctx context.Context)
}

type responseBodyPhaseProbe struct {
	filter.PassThrough
	probe func(ctx context.Context)
}

func (p responseBodyPhaseProbe) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func (p responseBodyPhaseProbe) OnResponseBody(ctx context.Context, _ *filter.Stream, _ filter.Body) (filter.Action, error) {
	p.probe(ctx)
	return filter.Continue(), nil
}

func (p phaseProbe) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func (p phaseProbe) OnRequestBody(ctx context.Context, _ *filter.Stream, _ filter.Body) (filter.Action, error) {
	p.probe(ctx)
	return filter.Continue(), nil
}

func (p phaseProbe) OnResponseHeaders(ctx context.Context, _ *filter.Stream) (filter.Action, error) {
	p.probe(ctx)
	return filter.Continue(), nil
}

func TestEvalRequestBody_BudgetInstallsDeadline(t *testing.T) {
	pluginCallsTotal.Reset()
	var hadDeadline bool
	regs := buildRegs(t, []regSpec{{
		name: "probe",
		make: func(filter.RuleConfig[string]) filter.Filter {
			return phaseProbe{probe: func(ctx context.Context) { _, hadDeadline = ctx.Deadline() }}
		},
	}})
	e := NewEngine(regs, time.Minute)

	st := &filter.Stream{}
	hr, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"cfg"}}))
	if err != nil {
		t.Fatalf("headers phase: %v", err)
	}
	if !hr.NeedsBody() {
		t.Fatal("probe should have deferred to the body phase")
	}
	if _, err := e.EvalRequestBody(context.Background(), st, hr, filter.Body{Bytes: []byte("x"), Complete: true}); err != nil {
		t.Fatalf("body phase: %v", err)
	}
	if !hadDeadline {
		t.Error("the body phase must run under its own budget deadline")
	}
}

func TestEvalResponseHeaders_BudgetInstallsDeadline(t *testing.T) {
	pluginCallsTotal.Reset()
	var hadDeadline bool
	regs := buildRegs(t, []regSpec{{
		name:       "probe",
		phases:     filter.PhaseRequestHeaders | filter.PhaseRequestBody | filter.PhaseResponseHeaders,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		make: func(filter.RuleConfig[string]) filter.Filter {
			return phaseProbe{probe: func(ctx context.Context) { _, hadDeadline = ctx.Deadline() }}
		},
	}})
	e := NewEngine(regs, time.Minute)

	units := unitsFor([][]string{{"cfg"}})
	if _, err := e.EvalResponseHeaders(context.Background(), &filter.Stream{}, units, ResponseScope{}); err != nil {
		t.Fatalf("response phase: %v", err)
	}
	if !hadDeadline {
		t.Error("the response phase must run under its own budget deadline")
	}
}

func TestEvalResponseBody_BudgetInstallsDeadline(t *testing.T) {
	pluginCallsTotal.Reset()
	var hadDeadline bool
	regs := buildRegs(t, []regSpec{{
		name:       "probe",
		phases:     filter.PhaseResponseHeaders | filter.PhaseResponseBody,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		make: func(filter.RuleConfig[string]) filter.Filter {
			return responseBodyPhaseProbe{probe: func(ctx context.Context) { _, hadDeadline = ctx.Deadline() }}
		},
	}})
	e := NewEngine(regs, time.Minute)
	units := unitsFor([][]string{{"cfg"}})
	st := &filter.Stream{}
	hr, err := e.EvalResponseHeaders(context.Background(), st, units, ResponseScope{})
	if err != nil {
		t.Fatalf("response headers phase: %v", err)
	}
	if !hr.NeedsBody() {
		t.Fatal("probe should have deferred to the response body phase")
	}
	if _, err := e.EvalResponseBody(context.Background(), st, hr, filter.Body{Complete: true}); err != nil {
		t.Fatalf("response body phase: %v", err)
	}
	if !hadDeadline {
		t.Error("the response body phase must run under its own budget deadline")
	}
}
