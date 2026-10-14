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
package httpcallout

import (
	"context"
	"fmt"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// Filter delegates one rule's enabled phases to the configured endpoint.
//
// It holds no phase state. The engine builds a fresh Filter per direction
// (eval.go calls reg.New inside each walk), so nothing could cross from the
// request phase to the response phase anyway, and the body callbacks are only
// invoked on the instance that returned NeedBody. The presence of cfg.Request and
// cfg.Response is therefore the only guard needed.
//
// Each direction's PhaseConfig.Body decides where its callout runs: with a body
// the headers phase asks for one and the callout runs in the body phase, without
// it the callout runs in the headers phase and nothing is buffered.
type Filter struct {
	filter.PassThrough
	cfg    Config
	id     filter.UnitID
	client Client
}

// NewDescriptor declares httpcallout to the framework. Every phase is declared
// because one Config may enable either direction; which ones actually run is
// decided per config by SubscribesOf and the guards below.
func NewDescriptor(deps Deps) filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name: FilterName,
		Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody |
			filter.PhaseResponseHeaders | filter.PhaseResponseBody,
		// Inverted from tokentransform: a callout is a security control, so the
		// safe default is to deny when it cannot be consulted, and FailOpen is
		// the explicit opt-out.
		OnError: func(cfg Config) filter.FailurePolicy {
			if cfg.FailOpen {
				return filter.FailOpen
			}
			return filter.FailClosed
		},
		// Not optional: without it the response walk skips this pair entirely
		// and the response half never runs. Returning 0 for a request-only
		// config is equally load-bearing — it keeps those requests from paying
		// ResponseHeaderMode SEND for a phase that would do nothing.
		SubscribesOf: func(cfg Config) filter.Phase {
			if cfg.Response == nil {
				return 0
			}
			return filter.PhaseResponseHeaders
		},
		New: func(rule filter.RuleConfig[Config]) filter.Filter {
			return &Filter{cfg: rule.Cfg, id: rule.ID, client: deps.Client}
		},
	}
}

// OnRequestHeaders asks for the body only when the request phase collects one.
// Otherwise it calls out here: returning NeedBody for a callout that never reads
// the body would make Envoy buffer the whole message for nothing, and a
// short-circuit from this phase happens before the body is ever read.
func (f *Filter) OnRequestHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	if f.cfg.Request == nil {
		return filter.Continue(), nil
	}
	if f.cfg.Request.Body {
		return filter.NeedBody(filter.CompleteBody), nil
	}
	return f.requestCallout(ctx, st, filter.Body{})
}

// OnResponseHeaders is the response-direction counterpart.
func (f *Filter) OnResponseHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	if f.cfg.Response == nil {
		return filter.Continue(), nil
	}
	if f.cfg.Response.Body {
		return filter.NeedBody(filter.CompleteBody), nil
	}
	return f.responseCallout(ctx, st, filter.Body{})
}

// OnRequestBody performs the request-phase callout for a body-collecting phase.
func (f *Filter) OnRequestBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	if f.cfg.Request == nil || !f.cfg.Request.Body {
		return filter.Continue(), nil
	}
	return f.requestCallout(ctx, st, body)
}

// OnResponseBody performs the response-phase callout for a body-collecting phase.
func (f *Filter) OnResponseBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	if f.cfg.Response == nil || !f.cfg.Response.Body {
		return filter.Continue(), nil
	}
	return f.responseCallout(ctx, st, body)
}

// requestCallout is shared by the two dispatch points so the phase runs
// identically wherever it was reached from. body is the zero Body in the headers
// phase, which the builder ignores because that phase collects none.
func (f *Filter) requestCallout(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	inv, err := buildRequestInvocation(f.cfg, f.id, st, body)
	if err != nil {
		return filter.Action{}, err
	}
	return f.callout(ctx, PhaseRequest, inv)
}

func (f *Filter) responseCallout(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	inv, err := buildResponseInvocation(f.cfg, f.id, st, body)
	if err != nil {
		return filter.Action{}, err
	}
	return f.callout(ctx, PhaseResponse, inv)
}

// callout sends one invocation and translates the answer. Every failure is
// returned as an error so the framework's OnError policy resolves it; this
// filter never hand-builds a deny, which is also what keeps the endpoint URL and
// the remote's text out of anything the client can see.
func (f *Filter) callout(ctx context.Context, phase Phase, inv Invocation) (filter.Action, error) {
	// Validate what EPE built before spending a network round trip on it: a
	// malformed invocation is an EPE bug, and the endpoint's rejection of it
	// would be a far less specific error.
	if err := inv.Validate(); err != nil {
		return filter.Action{}, err
	}
	if f.client == nil {
		return filter.Action{}, fmt.Errorf("callout client is not configured")
	}
	decision, err := f.client.Call(ctx, f.cfg.Provider, inv)
	if err != nil {
		// Wrapping names the phase for the log; the client already scrubbed the
		// endpoint out, and the client never sees this text because the
		// framework generates the deny from OnError.
		return filter.Action{}, fmt.Errorf("%s-phase callout failed: %w", phase, err)
	}
	// The phase is what the answer's shape is judged against: which object it
	// may mutate depends on the direction being intercepted.
	if err := decision.Validate(phase); err != nil {
		return filter.Action{}, err
	}
	return decisionAction(phase, decision)
}
