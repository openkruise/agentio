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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

type chunkProbe struct {
	filter.PassThrough
	requirement filter.BodyRequirement
	headers     int
	bodies      int
	header      func() (filter.Action, error)
	body        func(context.Context, filter.Body) (filter.Action, error)
}

func (p *chunkProbe) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	p.headers++
	if p.header != nil {
		return p.header()
	}
	return filter.NeedBody(p.requirement), nil
}

func (p *chunkProbe) OnResponseHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	return p.OnRequestHeaders(ctx, st)
}

func (p *chunkProbe) OnRequestBody(ctx context.Context, _ *filter.Stream, b filter.Body) (filter.Action, error) {
	p.bodies++
	if p.headers != 1 {
		return filter.Action{}, errors.New("body callback did not reuse prepared instance")
	}
	if p.body != nil {
		return p.body(ctx, b)
	}
	return filter.Continue(), nil
}

func (p *chunkProbe) OnResponseBody(ctx context.Context, st *filter.Stream, b filter.Body) (filter.Action, error) {
	return p.OnRequestBody(ctx, st, b)
}

type chunkSpec struct {
	req        filter.BodyRequirement
	probe      *chunkProbe
	failOpen   bool
	headerOnly bool
}

type chunkHarness struct {
	e        *Engine
	st       *filter.Stream
	units    []Unit
	response bool
	scope    ResponseScope
	req      *RequestHeadersResult
	resp     *ResponseHeadersResult
}

func newChunkHarness(t *testing.T, response bool, specs ...chunkSpec) *chunkHarness {
	t.Helper()
	var defs []filter.Definition
	var cfgs []any
	for i, spec := range specs {
		p := spec.probe
		if p == nil {
			p = &chunkProbe{}
		}
		p.requirement = spec.req
		phases := filter.PhaseRequestHeaders | filter.PhaseRequestBody
		if response {
			phases = filter.PhaseResponseHeaders | filter.PhaseResponseBody
		}
		if spec.headerOnly {
			phases &^= filter.PhaseRequestBody | filter.PhaseResponseBody
			if p.header == nil {
				p.header = func() (filter.Action, error) { return filter.Continue(), nil }
			}
		}
		d := filter.Descriptor[string]{
			Name:   fmt.Sprintf("chunk%d", i),
			Phases: phases,
			OnError: func(string) filter.FailurePolicy {
				if spec.failOpen {
					return filter.FailOpen
				}
				return filter.FailClosed
			},
			New: func(filter.RuleConfig[string]) filter.Filter { return p },
		}
		if response {
			d.SubscribesOf = func(string) filter.Phase { return filter.PhaseResponseHeaders }
		}
		defs = append(defs, filter.Define(d, func(json.RawMessage) (string, error) { return "on", nil }))
		cfgs = append(cfgs, "on")
	}
	regs, err := filter.Build(defs...)
	if err != nil {
		t.Fatal(err)
	}
	return &chunkHarness{
		e:        NewEngine(regs, 0),
		st:       &filter.Stream{Info: filter.NewStreamInfo()},
		units:    []Unit{{ID: filter.UnitID{Name: "test"}, Cfgs: cfgs}},
		response: response,
	}
}

func (h *chunkHarness) start() (filter.BodyMode, []filter.HeaderOp, error) {
	var err error
	if h.response {
		h.resp, err = h.e.EvalResponseHeaders(context.Background(), h.st, h.units, h.scope, WithResponseStreaming())
		return h.resp.BodyMode(), h.resp.HeaderOps, err
	}
	h.req, err = h.e.EvalRequestHeaders(context.Background(), h.st, h.units, WithRequestStreaming())
	return h.req.BodyMode(), h.req.HeaderOps, err
}

func (h *chunkHarness) chunk(ctx context.Context, b filter.Body) (*BodyChunkResult, error) {
	if h.response {
		return h.e.EvalResponseBodyChunk(ctx, h.st, h.resp, b)
	}
	return h.e.EvalRequestBodyChunk(ctx, h.st, h.req, b)
}

func (h *chunkHarness) buffered(b filter.Body) ([]byte, error) {
	if h.response {
		res, err := h.e.EvalResponseBody(context.Background(), h.st, h.resp, b)
		if err != nil {
			return nil, err
		}
		return res.Body, nil
	}
	res, err := h.e.EvalRequestBody(context.Background(), h.st, h.req, b)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

func TestBodyModeSelection(t *testing.T) {
	optional := filter.IncrementalBody
	pass := &chunkProbe{header: func() (filter.Action, error) { return filter.Continue(), nil }}
	tests := []struct {
		name  string
		specs []chunkSpec
		want  filter.BodyMode
	}{
		{name: "no-body", specs: []chunkSpec{{probe: pass}}, want: filter.BodyNone},
		{name: "legacy", specs: []chunkSpec{{}}, want: filter.BodyBuffered},
		{name: "incremental", specs: []chunkSpec{{req: optional}}, want: filter.BodyStreamed},
		{name: "mixed", specs: []chunkSpec{{req: optional}, {}}, want: filter.BodyBuffered},
		{name: "mixed-reverse", specs: []chunkSpec{{}, {req: optional}}, want: filter.BodyBuffered},
		{name: "fail-open", specs: []chunkSpec{{req: optional, failOpen: true}}, want: filter.BodyBuffered},
		{name: "later-headers", specs: []chunkSpec{{req: optional}, {headerOnly: true}}, want: filter.BodyStreamed},
	}
	for _, response := range []bool{false, true} {
		for _, tc := range tests {
			t.Run(fmt.Sprintf("response=%t/%s", response, tc.name), func(t *testing.T) {
				h := newChunkHarness(t, response, tc.specs...)
				mode, _, err := h.start()
				want := tc.want
				if err != nil || mode != want {
					t.Fatalf("mode=%v err=%v, want mode=%v", mode, err, want)
				}
			})
		}
	}
}

func TestBodyRequirementFromHeaderAction(t *testing.T) {
	for _, response := range []bool{false, true} {
		for _, requirement := range []filter.BodyRequirement{filter.CompleteBody, filter.IncrementalBody, 255} {
			p := &chunkProbe{}
			h := newChunkHarness(t, response, chunkSpec{probe: p})
			h.st.Request.Headers = map[string]string{"content-type": map[filter.BodyRequirement]string{
				filter.CompleteBody:    "application/json",
				filter.IncrementalBody: "application/octet-stream",
			}[requirement]}
			p.header = func() (filter.Action, error) {
				switch h.st.Request.Headers["content-type"] {
				case "application/json":
					return filter.NeedBody(filter.CompleteBody), nil
				case "application/octet-stream":
					return filter.NeedBody(filter.IncrementalBody), nil
				default:
					return filter.NeedBody(255), nil
				}
			}
			mode, _, err := h.start()
			if requirement == 255 {
				if err == nil || !strings.Contains(err.Error(), "unknown body requirement") {
					t.Fatalf("invalid requirement accepted: %v", err)
				}
				continue
			}
			want := filter.BodyBuffered
			if requirement == filter.IncrementalBody {
				want = filter.BodyStreamed
			}
			if err != nil || mode != want {
				t.Fatalf("response=%t requirement=%v: mode=%v err=%v", response, requirement, mode, err)
			}
		}
	}
}

func TestBufferedFallbackPreservesIncrementalContract(t *testing.T) {
	for _, response := range []bool{false, true} {
		for _, act := range []filter.Action{
			filter.Continue(filter.SetHeader("x-late", "unsafe")),
			filter.Bypass(),
			filter.NeedBody(filter.CompleteBody),
		} {
			p := &chunkProbe{body: func(context.Context, filter.Body) (filter.Action, error) { return act, nil }}
			h := newChunkHarness(t, response, chunkSpec{req: filter.IncrementalBody, probe: p}, chunkSpec{})
			mode, _, err := h.start()
			if err != nil || mode != filter.BodyBuffered {
				t.Fatalf("mode=%v err=%v", mode, err)
			}
			p.requirement = filter.CompleteBody
			if _, err := h.buffered(filter.Body{Bytes: []byte("body"), Complete: true}); err == nil {
				t.Fatalf("response=%t accepted unsafe incremental action after buffered fallback: %+v", response, act)
			}
		}
	}
}

func TestIncrementalDeliveryPreservesOriginalViewAndBoundsAudit(t *testing.T) {
	for _, response := range []bool{false, true} {
		t.Run(fmt.Sprint(response), func(t *testing.T) {
			var finals int
			first := &chunkProbe{
				header: func() (filter.Action, error) {
					return filter.NeedBody(filter.IncrementalBody, filter.SetHeader("x-prepared", "yes")), nil
				},
				body: func(_ context.Context, b filter.Body) (filter.Action, error) {
					return filter.Continue(filter.Mutation{Body: []byte(strings.ToUpper(string(b.Bytes)))}), nil
				},
			}
			second := &chunkProbe{body: func(_ context.Context, b filter.Body) (filter.Action, error) {
				if string(b.Bytes) != "original" && len(b.Bytes) != 0 {
					t.Fatalf("later filter saw a mutation: %q", b.Bytes)
				}
				if b.Complete {
					finals++
				}
				return filter.Continue(), nil
			}}
			req := filter.IncrementalBody
			h := newChunkHarness(t, response, chunkSpec{req: req, probe: first}, chunkSpec{req: req, probe: second})
			mode, headers, err := h.start()
			if err != nil || mode != filter.BodyStreamed || len(headers) != 1 || headers[0].Value != "yes" {
				t.Fatalf("mode=%v headers=%v err=%v", mode, headers, err)
			}
			for i := range 1000 {
				res, err := h.chunk(context.Background(), filter.Body{Bytes: []byte("original")})
				if err != nil || string(res.Body) != "ORIGINAL" || res.Complete ||
					res.Disposition != DispositionMutated {
					t.Fatalf("chunk %d: result=%+v err=%v", i, res, err)
				}
			}
			res, err := h.chunk(context.Background(), filter.Body{Complete: true})
			if err != nil || !res.Complete || len(res.Body) != 0 || finals != 1 {
				t.Fatalf("final=%+v count=%d err=%v", res, finals, err)
			}
			if first.headers != 1 || second.headers != 1 || first.bodies != 1001 || second.bodies != 1001 {
				t.Fatal("callbacks did not reuse their prepared instances")
			}
			if len(h.st.Info.Filters) != 4 || len(h.st.Info.Matched[0].FilterActions) != 3 {
				t.Fatalf("audit grew with chunks: %+v", h.st.Info)
			}
			if _, err := h.chunk(context.Background(), filter.Body{Complete: true}); err == nil {
				t.Fatal("accepted duplicate EOS")
			}
		})
	}
}

func TestBufferedFallbackKeepsBodyAndExecutionOrder(t *testing.T) {
	for _, response := range []bool{false, true} {
		var calls []string
		probe := func(name, replacement string, requirement filter.BodyRequirement) *chunkProbe {
			return &chunkProbe{
				header: func() (filter.Action, error) {
					calls = append(calls, name+".headers")
					return filter.NeedBody(requirement), nil
				},
				body: func(_ context.Context, b filter.Body) (filter.Action, error) {
					calls = append(calls, name+".body")
					if !b.Complete || string(b.Bytes) != "original" {
						t.Fatalf("invalid buffered body: %+v", b)
					}
					return filter.Continue(filter.Mutation{Body: []byte(replacement)}), nil
				},
			}
		}
		h := newChunkHarness(t, response,
			chunkSpec{req: filter.IncrementalBody, probe: probe("incremental", "first", filter.IncrementalBody)},
			chunkSpec{probe: probe("buffered", "last", filter.CompleteBody)})
		mode, _, err := h.start()
		wantHeaders := "incremental.headers,buffered.headers"
		wantCalls := wantHeaders + ",incremental.body,buffered.body"
		if err != nil || mode != filter.BodyBuffered || strings.Join(calls, ",") != wantHeaders {
			t.Fatalf("premature execution: %v mode=%v err=%v", calls, mode, err)
		}
		out, err := h.buffered(filter.Body{Bytes: []byte("original"), Complete: true})
		if err != nil || string(out) != "last" ||
			strings.Join(calls, ",") != wantCalls {
			t.Fatalf("body=%q calls=%v err=%v", out, calls, err)
		}
	}
}

func TestIncrementalRejectsLateHeaderChangesAndUnsafeActions(t *testing.T) {
	status := 201
	acts := []filter.Action{
		filter.Continue(filter.SetHeader("x-late", "unsafe")),
		filter.Continue(filter.Mutation{StatusCode: &status}),
		filter.Continue(filter.Mutation{Route: &filter.RouteMutation{ClearCache: true}}),
		filter.Bypass(),
		filter.NeedBody(filter.CompleteBody),
	}
	for _, response := range []bool{false, true} {
		for i, act := range acts {
			t.Run(fmt.Sprintf("response=%t/action=%d", response, i), func(t *testing.T) {
				p := &chunkProbe{body: func(context.Context, filter.Body) (filter.Action, error) { return act, nil }}
				h := newChunkHarness(t, response, chunkSpec{req: filter.IncrementalBody, probe: p})
				if _, _, err := h.start(); err != nil {
					t.Fatal(err)
				}
				res, err := h.chunk(context.Background(), filter.Body{Bytes: []byte("secret")})
				if err == nil || res != nil {
					t.Fatalf("unsafe output: %+v err=%v", res, err)
				}
				if h.st.Info.Error != "" {
					t.Fatal("contract violation was recorded as a fail-closed invocation")
				}
				if _, err := h.chunk(context.Background(), filter.Body{Complete: true}); err == nil {
					t.Fatal("resumed a failed stream")
				}
				if p.bodies != 1 {
					t.Fatal("called a body consumer after a contract violation")
				}

				p = &chunkProbe{body: func(context.Context, filter.Body) (filter.Action, error) { return act, nil }}
				h = newChunkHarness(t, response, chunkSpec{req: filter.IncrementalBody, probe: p}, chunkSpec{})
				if mode, _, err := h.start(); err != nil || mode != filter.BodyBuffered {
					t.Fatalf("buffered fallback: mode=%v err=%v", mode, err)
				}
				if _, err := h.buffered(filter.Body{Bytes: []byte("secret"), Complete: true}); err == nil {
					t.Fatal("buffered fallback did not return the contract error")
				}
			})
		}
	}
}

func TestIncrementalInvocationErrorStillFailsClosed(t *testing.T) {
	boom := errors.New("body processing failed")
	for _, response := range []bool{false, true} {
		t.Run(fmt.Sprintf("response=%t", response), func(t *testing.T) {
			p := &chunkProbe{body: func(context.Context, filter.Body) (filter.Action, error) {
				return filter.Action{}, boom
			}}
			h := newChunkHarness(t, response, chunkSpec{req: filter.IncrementalBody, probe: p})
			if _, _, err := h.start(); err != nil {
				t.Fatal(err)
			}
			res, err := h.chunk(t.Context(), filter.Body{Bytes: []byte("secret")})
			if err != nil || res.Disposition != DispositionBlocked || res.Reply.Status != 500 || res.Body != nil {
				t.Fatalf("invocation failure: %+v err=%v", res, err)
			}
			if h.st.Info.Error != boom.Error() {
				t.Fatalf("failure attribution = %q", h.st.Info.Error)
			}
		})
	}
}

func TestIncrementalEarlyAndLateRejection(t *testing.T) {
	for _, response := range []bool{false, true} {
		for _, late := range []bool{false, true} {
			p := &chunkProbe{body: func(_ context.Context, b filter.Body) (filter.Action, error) {
				if string(b.Bytes) == "bad" {
					return filter.Stop(filter.Reply{Status: 403}), nil
				}
				return filter.Continue(), nil
			}}
			h := newChunkHarness(t, response, chunkSpec{req: filter.IncrementalBody, probe: p})
			if _, _, err := h.start(); err != nil {
				t.Fatal(err)
			}
			if late {
				res, err := h.chunk(context.Background(), filter.Body{Bytes: []byte("good")})
				if err != nil || string(res.Body) != "good" || res.Disposition != DispositionPassthrough {
					t.Fatalf("passthrough: %+v %v", res, err)
				}
			}
			res, err := h.chunk(context.Background(), filter.Body{Bytes: []byte("bad")})
			if err != nil || res.Disposition != DispositionBlocked || res.Reply.Status != 403 ||
				res.Body != nil {
				t.Fatalf("block: %+v %v", res, err)
			}
			calls := p.bodies
			if next, err := h.chunk(
				context.Background(),
				filter.Body{Bytes: []byte("after deny"), Complete: true},
			); err == nil ||
				next != nil {
				t.Fatalf("continued after block: %+v %v", next, err)
			}
			if p.bodies != calls {
				t.Fatal("called a body consumer after termination")
			}
		}
	}
}

func TestIncrementalBufferingInsideConsumerAndCancellation(t *testing.T) {
	for _, response := range []bool{false, true} {
		var saved []byte
		p := &chunkProbe{body: func(_ context.Context, b filter.Body) (filter.Action, error) {
			saved = append(saved, b.Bytes...)
			if b.Complete {
				return filter.Continue(filter.Mutation{Body: saved}), nil
			}
			return filter.Continue(filter.Mutation{Body: []byte{}}), nil
		}}
		h := newChunkHarness(t, response, chunkSpec{req: filter.IncrementalBody, probe: p})
		if _, _, err := h.start(); err != nil {
			t.Fatal(err)
		}
		res, err := h.chunk(context.Background(), filter.Body{Bytes: []byte("first")})
		if err != nil || len(res.Body) != 0 || res.Complete {
			t.Fatalf("retained chunk: %+v %v", res, err)
		}
		res, err = h.chunk(context.Background(), filter.Body{Bytes: []byte("last"), Complete: true})
		if err != nil || string(res.Body) != "firstlast" || !res.Complete {
			t.Fatalf("final retained chunk: %+v %v", res, err)
		}

		h = newChunkHarness(t, response, chunkSpec{req: filter.IncrementalBody})
		if _, _, err := h.start(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, err = h.chunk(ctx, filter.Body{Bytes: []byte("must not escape")})
		if err != nil || res.Disposition != DispositionBlocked || res.Body != nil {
			t.Fatalf("cancellation: %+v %v", res, err)
		}
	}
}

func TestIncrementalBudgetAndContinuationOwnership(t *testing.T) {
	p := &chunkProbe{body: func(ctx context.Context, _ filter.Body) (filter.Action, error) {
		<-ctx.Done()
		return filter.Continue(), nil
	}}
	h := newChunkHarness(t, false, chunkSpec{req: filter.IncrementalBody, probe: p})
	if _, _, err := h.start(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.e.EvalRequestBodyChunk(context.Background(), &filter.Stream{}, h.req, filter.Body{}); err == nil {
		t.Fatal("accepted another stream")
	}
	if _, err := NewEngine(
		h.e.Registrations(),
		0,
	).EvalRequestBodyChunk(context.Background(), h.st, h.req, filter.Body{}); err == nil {
		t.Fatal("accepted another engine")
	}
	if _, err := h.buffered(filter.Body{Complete: true}); err == nil {
		t.Fatal("accepted complete-body API for an incremental continuation")
	}
	h.e.budget = time.Millisecond
	res, err := h.chunk(context.Background(), filter.Body{Bytes: []byte("secret")})
	if err != nil || res.Disposition != DispositionBlocked || res.Body != nil || p.bodies != 1 {
		t.Fatalf("budget: %+v %v", res, err)
	}
}

func TestResponseBodySelectionHonorsScopeAndSubscriptions(t *testing.T) {
	req := filter.IncrementalBody
	for _, byScope := range []bool{false, true} {
		h := newChunkHarness(t, true, chunkSpec{req: req}, chunkSpec{})
		if byScope {
			h.scope = ResponseScope{bounded: true, last: evalCursor{}}
		} else {
			h.e.regs[1].Subscribes = func(any) filter.Phase { return 0 }
		}
		mode, _, err := h.start()
		if err != nil || mode != filter.BodyStreamed {
			t.Fatalf("excluded consumer affected mode: %v %v", mode, err)
		}
	}
}

func TestIncrementalPreparationFailures(t *testing.T) {
	for _, response := range []bool{false, true} {
		for _, optsOut := range []bool{false, true} {
			first := &chunkProbe{header: func() (filter.Action, error) {
				return filter.NeedBody(filter.IncrementalBody, filter.SetHeader("x-pending", "value")), nil
			}}
			second := &chunkProbe{header: func() (filter.Action, error) {
				if optsOut {
					return filter.Continue(), nil
				}
				return filter.Action{}, errors.New("prepare failed")
			}}
			req := filter.IncrementalBody
			h := newChunkHarness(t, response, chunkSpec{req: req, probe: first}, chunkSpec{req: req, probe: second})
			mode, headers, err := h.start()
			if optsOut {
				// Both directions finish headers before selecting body delivery.
				if err != nil || mode != filter.BodyStreamed || len(headers) != 1 || second.bodies != 0 {
					t.Fatalf("optional consumer: %v %v %v", mode, headers, err)
				}
				continue
			}
			if err != nil || len(headers) != 0 || first.bodies != 0 || second.bodies != 0 {
				t.Fatalf("preparation leaked mutations/body: mode=%v headers=%v err=%v", mode, headers, err)
			}
			if !optsOut {
				disposition := DispositionPassthrough
				if response {
					disposition = h.resp.Disposition
				} else {
					disposition = h.req.Disposition
				}
				if disposition != DispositionBlocked || mode != filter.BodyNone || h.st.Info.Error == "" {
					t.Fatalf("preparation failure was not fail-closed: %v %v %+v", disposition, mode, h.st.Info)
				}
			}
		}
	}
}

func TestBodySelectionAcrossUnitsAndPendingReplacement(t *testing.T) {
	for _, response := range []bool{false, true} {
		req := filter.IncrementalBody
		h := newChunkHarness(t, response, chunkSpec{req: req}, chunkSpec{})
		h.units = []Unit{
			{ID: filter.UnitID{Name: "first"}, Cfgs: []any{"on", nil}},
			{ID: filter.UnitID{Name: "second"}, Cfgs: []any{nil, "on"}},
		}
		mode, _, err := h.start()
		if err != nil || mode != filter.BodyBuffered {
			t.Fatalf("missed later unit: mode=%v err=%v", mode, err)
		}
		p := &chunkProbe{header: func() (filter.Action, error) {
			return filter.NeedBody(filter.IncrementalBody, filter.Mutation{Body: []byte{}}), nil
		}}
		h = newChunkHarness(t, response, chunkSpec{req: req, probe: p})
		mode, _, err = h.start()
		if err != nil || mode != filter.BodyBuffered {
			t.Fatalf("lost pending replacement: mode=%v err=%v", mode, err)
		}
	}
}

func TestRequestStreamingRetainsCallbacksBeforeHeaderBypass(t *testing.T) {
	first := &chunkProbe{body: func(context.Context, filter.Body) (filter.Action, error) {
		return filter.Continue(filter.Mutation{Body: []byte("changed")}), nil
	}}
	bypass := &chunkProbe{header: func() (filter.Action, error) { return filter.Bypass(), nil }}
	later := &chunkProbe{}
	h := newChunkHarness(
		t,
		false,
		chunkSpec{req: filter.IncrementalBody, probe: first},
		chunkSpec{probe: bypass},
		chunkSpec{probe: later},
	)
	mode, _, err := h.start()
	if err != nil || mode != filter.BodyStreamed || later.headers != 0 {
		t.Fatalf("headers: %v %v", mode, err)
	}
	result, err := h.chunk(t.Context(), filter.Body{Bytes: []byte("original"), Complete: true})
	if err != nil || result.Disposition != DispositionMutated || string(result.Body) != "changed" ||
		first.bodies != 1 ||
		later.bodies != 0 {
		t.Fatalf("body: %v %v", result, err)
	}
	if result.ResponseScope.excludes(0, 1) || !result.ResponseScope.excludes(0, 2) {
		t.Fatal("lost request bypass scope")
	}
}

func TestHeaderTerminalActionsPreserveOrDiscardRegisteredBodies(t *testing.T) {
	for _, response := range []bool{false, true} {
		for _, incremental := range []bool{false, true} {
			for _, stop := range []bool{false, true} {
				name := fmt.Sprintf("response=%t/incremental=%t/stop=%t", response, incremental, stop)
				t.Run(name, func(t *testing.T) {
					first, later := &chunkProbe{}, &chunkProbe{}
					terminal := &chunkProbe{header: func() (filter.Action, error) {
						if stop {
							return filter.Stop(filter.Reply{Status: 403}), nil
						}
						return filter.Bypass(), nil
					}}
					req := filter.CompleteBody
					if incremental {
						req = filter.IncrementalBody
					}
					h := newChunkHarness(t, response,
						chunkSpec{req: req, probe: first},
						chunkSpec{headerOnly: true, probe: terminal},
						chunkSpec{req: req, probe: later})
					mode, _, err := h.start()
					if err != nil || first.headers != 1 || first.bodies != 0 || terminal.headers != 1 ||
						later.headers != 0 {
						t.Fatalf("header calls: first=%+v terminal=%+v later=%+v err=%v", first, terminal, later, err)
					}
					if stop {
						if mode != filter.BodyNone {
							t.Fatalf("header Stop retained body delivery: %v", mode)
						}
						return
					}
					body := filter.Body{Bytes: []byte("original"), Complete: true}
					if incremental {
						if mode != filter.BodyStreamed {
							t.Fatalf("header Bypass changed streaming mode: %v", mode)
						}
						_, err = h.chunk(t.Context(), body)
					} else {
						if mode != filter.BodyBuffered {
							t.Fatalf("header Bypass discarded buffered callbacks: %v", mode)
						}
						var disposition Disposition
						if response {
							result, bodyErr := h.e.EvalResponseBody(t.Context(), h.st, h.resp, body)
							disposition, err = result.Disposition, bodyErr
						} else {
							result, bodyErr := h.e.EvalRequestBody(t.Context(), h.st, h.req, body)
							disposition, err = result.Disposition, bodyErr
						}
						if disposition != DispositionBypassed {
							t.Fatalf("lost header bypass: %v", disposition)
						}
					}
					if err != nil || first.bodies != 1 || terminal.bodies != 0 || later.bodies != 0 {
						t.Fatalf("body calls: first=%+v terminal=%+v later=%+v err=%v", first, terminal, later, err)
					}
				})
			}
		}
	}
}

func TestAvailableBodyRunsAfterAllHeaders(t *testing.T) {
	for _, response := range []bool{false, true} {
		for _, terminal := range []string{"continue", "stop", "bypass"} {
			t.Run(fmt.Sprintf("response=%t/%s", response, terminal), func(t *testing.T) {
				var calls []string
				probe := func(name string) *chunkProbe {
					return &chunkProbe{
						header: func() (filter.Action, error) {
							calls = append(calls, name+".header")
							return filter.NeedBody(filter.CompleteBody, filter.Mutation{Body: []byte("header")}), nil
						},
						body: func(_ context.Context, body filter.Body) (filter.Action, error) {
							calls = append(calls, name+".body")
							if !body.Complete || len(body.Bytes) != 0 {
								t.Fatalf("expected original empty final body: %+v", body)
							}
							if name == "first" {
								switch terminal {
								case "stop":
									return filter.Stop(filter.Reply{Status: 403}), nil
								case "bypass":
									return filter.Bypass(), nil
								}
							}
							return filter.Continue(filter.Mutation{Body: []byte(name)}), nil
						},
					}
				}
				h := newChunkHarness(t, response, chunkSpec{probe: probe("first")}, chunkSpec{probe: probe("second")})
				var disposition Disposition
				var output []byte
				var needsBody bool
				var err error
				if response {
					r, e := h.e.EvalResponseHeaders(t.Context(), h.st, h.units, h.scope,
						WithResponseStreaming(), WithAvailableResponseBody(filter.Body{Complete: true}))
					disposition, output, needsBody, err = r.Disposition, r.Body, r.NeedsBody(), e
				} else {
					r, e := h.e.EvalRequestHeaders(t.Context(), h.st, h.units,
						WithRequestStreaming(), WithAvailableRequestBody(filter.Body{Complete: true}))
					disposition, output, needsBody, err = r.Disposition, r.Body, r.NeedsBody(), e
				}
				wantCalls := "first.header,second.header,first.body"
				wantDisposition, wantOutput := DispositionBypassed, "header"
				if terminal == "continue" {
					wantCalls += ",second.body"
					wantDisposition, wantOutput = DispositionMutated, "second"
				} else if terminal == "stop" {
					wantDisposition, wantOutput = DispositionBlocked, ""
				}
				if err != nil || needsBody || disposition != wantDisposition || string(output) != wantOutput ||
					strings.Join(calls, ",") != wantCalls {
					t.Fatalf(
						"calls=%v disposition=%v output=%q needsBody=%t err=%v",
						calls,
						disposition,
						output,
						needsBody,
						err,
					)
				}
			})
		}
	}
}
