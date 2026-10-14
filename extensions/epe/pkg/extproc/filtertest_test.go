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

// In-package test scaffolding for driving the body phase directly: a
// hand-built registration around a caller-supplied filter, and a helper
// that produces the (Server, streamState) pair the headers phase would
// have handed off.
package extproc

import (
	"context"
	"encoding/json"
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// bodyProbe asks for the body and records what it saw; the body-phase
// action is configurable per test.
type bodyProbe struct {
	requirement filter.BodyRequirement
	filter.PassThrough
	bodyCalls    int
	receivedBody []byte
	bodyAct      filter.Action
	bodyErr      error
}

func (p *bodyProbe) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(p.requirement), nil
}

func (p *bodyProbe) OnRequestBody(_ context.Context, _ *filter.Stream, b filter.Body) (filter.Action, error) {
	p.bodyCalls++
	p.receivedBody = append([]byte(nil), b.Bytes...)
	if p.bodyErr != nil {
		return filter.Continue(), p.bodyErr
	}
	if p.bodyAct.Equal(filter.Action{}) {
		return filter.Continue(), nil
	}
	return p.bodyAct, nil
}

// fixedReg wraps a single filter instance as a registration that claims
// every unit.
func fixedReg(name string, f filter.Filter) filter.Registration {
	return filter.Registration{
		Name:   name,
		Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		Parse:  func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New:    func(filter.ErasedRuleConfig) filter.Filter { return f },
	}
}

// pendingBodyState builds a Server over regs and the streamState the
// headers phase would hand off: the engine has run against one unit, the
// filters asked for the body, and StreamInfo carries the records.
func pendingBodyState(t *testing.T, regs []filter.Registration, auditLogger *captureLogger) (*Server, *streamState) {
	t.Helper()
	deps := ServerDeps{Registrations: regs}
	if auditLogger != nil {
		deps.AuditLogger = auditLogger
	}
	s := NewServer(deps)

	state := newStreamState()
	state.markRequestSeen()
	unit := engine.Unit{
		ID:   filter.UnitID{Scope: "default/p1", Name: "r", Ordinal: 0},
		Cfgs: make([]any, len(regs)),
	}
	for i := range regs {
		unit.Cfgs[i] = struct{}{}
	}
	er, err := s.eng.EvalRequestHeaders(context.Background(), state.stream, []engine.Unit{unit})
	if err != nil {
		t.Fatalf("engine.EvalRequestHeaders: %v", err)
	}
	if !er.NeedsBody() {
		t.Fatal("test setup: engine did not register a body need")
	}
	state.requestBodyContinuation = er
	return s, state
}

// sendRequestBody calls HandleRequestBody and performs the observation the
// Process send loop would have performed, as one step.
//
// The two are fused deliberately. The audit outcome is derived from what was
// sent, so a test that drives the handler directly and forgets the observation
// audits as inert — and still passes, because effectNone makes the derivation
// report passthrough rather than fail. A green test asserting an outcome the
// product never produced is exactly the false enforcement claim the derived
// outcome exists to prevent, so the observation is not left to the caller.
func sendRequestBody(t *testing.T, s *Server, state *streamState, body *extProcPb.HttpBody) ([]*extProcPb.ProcessingResponse, error) {
	t.Helper()
	responses, err := s.HandleRequestBody(context.Background(), body, state)
	for _, resp := range responses {
		state.effect.observe(classifyResponse(resp))
	}
	return responses, err
}
