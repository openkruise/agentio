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
package engine

import (
	"context"
	"fmt"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// BodyChunkResult is one incremental evaluation's result. Body always contains
// the output to forward, including unchanged input; nil/empty emits no bytes.
// Complete marks the final successful output, including an empty final chunk.
// Blocked terminates the direction without emitting this call's body.
type BodyChunkResult struct {
	Disposition Disposition
	Reply       filter.Reply
	Body        []byte
	Complete    bool
	// ResponseScope preserves the request walk's suppression boundary.
	ResponseScope ResponseScope
}

type bodyStage struct {
	bodyInvocation
	p           pair
	recordIndex int
	mutated     bool
}

type bodyStream struct {
	engine  *Engine
	st      *filter.Stream
	phase   filter.Phase
	stages  []bodyStage
	done    bool
	mutated bool
	scope   ResponseScope
}

// prepareStream selects delivery from callbacks registered by the complete headers phase.
func (b *bodyState) prepareStream(
	e *Engine,
	st *filter.Stream,
	phase filter.Phase,
	scope ResponseScope,
	streaming bool,
) {
	if !streaming || lastBodyMutation(b.pending) != nil {
		return
	}
	session := &bodyStream{engine: e, st: st, phase: phase, scope: scope}
	for _, invocation := range b.bodyFilters {
		p := e.pairAt(b.units, invocation.at)
		// Fail-open cannot reconstruct chunks retained by a failed consumer.
		if invocation.requirement != filter.IncrementalBody || failurePolicy(p.reg, p.cfg) != filter.FailClosed {
			return
		}
		session.stages = append(session.stages,
			bodyStage{bodyInvocation: invocation, p: p, recordIndex: -1})
	}
	b.stream = session
}

// EvalRequestBodyChunk feeds an incremental request consumer. Calls must be
// serialized and use the same engine, stream and headers result. The caller
// must commit the headers result before forwarding any returned output.
func (e *Engine) EvalRequestBodyChunk(
	ctx context.Context,
	st *filter.Stream,
	prior *RequestHeadersResult,
	body filter.Body,
) (*BodyChunkResult, error) {
	if prior == nil || prior.BodyMode() != filter.BodyStreamed {
		return nil, fmt.Errorf("request has no incremental body continuation")
	}
	view := *st
	if prior.Route != nil {
		view.Upstream = prior.Route.Upstream
	}
	return e.evalBodyChunk(ctx, st, &view, prior.stream, body)
}

// EvalResponseBodyChunk is the response-direction counterpart. Complete=true
// denotes the last body input even when HTTP trailers, rather than a DATA EOS,
// end the direction. Translating that distinction belongs to the adapter.
func (e *Engine) EvalResponseBodyChunk(
	ctx context.Context,
	st *filter.Stream,
	prior *ResponseHeadersResult,
	body filter.Body,
) (*BodyChunkResult, error) {
	if prior == nil || prior.BodyMode() != filter.BodyStreamed {
		return nil, fmt.Errorf("response has no incremental body continuation")
	}
	return e.evalBodyChunk(ctx, st, st, prior.stream, body)
}

func (e *Engine) evalBodyChunk(
	ctx context.Context,
	st *filter.Stream,
	view *filter.Stream,
	session *bodyStream,
	body filter.Body,
) (*BodyChunkResult, error) {
	if session.engine != e || session.st != st {
		return nil, fmt.Errorf("incremental body continuation belongs to another engine or stream")
	}
	if session.done {
		return nil, fmt.Errorf("incremental body continuation already finished")
	}
	defer func() {
		if session.done {
			session.stages = nil
		}
	}()
	ctx, cancel := e.withBudget(ctx)
	defer cancel()
	res := &BodyChunkResult{
		Body:          body.Bytes,
		Complete:      body.Complete,
		ResponseScope: session.scope,
	}
	for i := range session.stages {
		stage := &session.stages[i]
		m := e.metrics[stage.at.regIdx].requestBody
		call := stage.f.OnRequestBody
		if session.phase == filter.PhaseResponseBody {
			m = e.metrics[stage.at.regIdx].responseBody
			call = stage.f.OnResponseBody
		}
		act, rec := invokeMeasured(ctx, m, func(ctx context.Context) (filter.Action, error) {
			if err := ctx.Err(); err != nil {
				return filter.Action{}, err
			}
			act, err := call(ctx, view, body)
			if err == nil {
				err = ctx.Err()
			}
			return act, err
		})
		stage.record(st.Info, rec)
		if rec.Err != nil {
			walk := newActionWalk(st)
			walk.filterFailed(stage.p, session.phase, rec.Err)
			res.Disposition, res.Reply = walk.disposition, walk.reply
			res.Body = nil
			res.Complete = false
			session.done = true
			return res, nil
		}
		if err := validateIncrementalAction(stage.p.reg, act); err != nil {
			session.done = true
			return nil, err
		}
		if act.Kind() == filter.KindStop {
			res.Disposition = DispositionBlocked
			res.Reply, _ = act.Reply()
			res.Body = nil
			res.Complete = false
			session.done = true
			st.Info.RecordUnitAction(stage.p.unit.ID, stage.p.reg.Name, filter.ActionBlock)
			return res, nil
		}
		if replacement := lastBodyMutation(act.Mutations()); replacement != nil {
			res.Body = replacement
			session.mutated = true
			if !stage.mutated {
				st.Info.RecordUnitAction(stage.p.unit.ID, stage.p.reg.Name, filter.ActionMutate)
				stage.mutated = true
			}
		}
	}
	if session.mutated {
		res.Disposition = DispositionMutated
	}
	session.done = body.Complete
	return res, nil
}

func validateIncrementalAction(reg filter.Registration, act filter.Action) error {
	if act.Kind() != filter.KindContinue && act.Kind() != filter.KindStop {
		return fmt.Errorf("incremental filter %q must return Continue or Stop", reg.Name)
	}
	for _, m := range act.Mutations() {
		if len(m.HeaderOps) != 0 || m.StatusCode != nil || m.Route != nil {
			return fmt.Errorf("incremental filter %q cannot modify committed headers or routing", reg.Name)
		}
	}
	return nil
}

// record keeps one audit entry per consumer, even for an unbounded SSE stream.
func (s *bodyStage) record(info *filter.StreamInfo, rec filter.FilterRecord) {
	if info == nil {
		return
	}
	if s.recordIndex < 0 {
		s.recordIndex = len(info.Filters)
		info.RecordFilter(rec)
		return
	}
	prior := &info.Filters[s.recordIndex]
	prior.Duration += rec.Duration
	if rec.Outcome != outcomeContinue.String() {
		prior.Outcome = rec.Outcome
	}
	if rec.Err != nil {
		prior.Err = rec.Err
	}
}
