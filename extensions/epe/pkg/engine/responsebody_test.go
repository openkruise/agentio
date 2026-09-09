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
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

const responseBodyPhases = filter.PhaseResponseHeaders | filter.PhaseResponseBody

func testStatusCode(v int) *int { return &v }

type observingResponseBodyFilter struct {
	filter.PassThrough
	c            *counters
	headerAct    filter.Action
	bodyAct      filter.Action
	seenBodies   *[]filter.Body
	seenStatuses *[]int
	seenHeaders  *[]string
	prepared     bool
	bodyErr      error
}

func (f *observingResponseBodyFilter) OnResponseHeaders(_ context.Context, st *filter.Stream) (filter.Action, error) {
	f.c.headerCalls++
	f.prepared = true
	if f.seenStatuses != nil {
		*f.seenStatuses = append(*f.seenStatuses, st.Response.Status)
	}
	if f.seenHeaders != nil {
		*f.seenHeaders = append(*f.seenHeaders, st.Response.Headers["x-original"])
	}
	return f.headerAct, nil
}

func (f *observingResponseBodyFilter) OnResponseBody(_ context.Context, _ *filter.Stream, body filter.Body) (filter.Action, error) {
	f.c.bodyCalls++
	if f.seenBodies != nil {
		*f.seenBodies = append(*f.seenBodies, body)
	}
	if !f.prepared {
		return filter.Continue(), errors.New("response body callback used a different filter instance")
	}
	return f.bodyAct, f.bodyErr
}

func TestEvalResponseBody_FoldsPendingAndPreservesOriginalInput(t *testing.T) {
	pausedCounters := &counters{}
	laterCounters := &counters{}
	var pausedBodies, laterBodies []filter.Body
	var seenStatuses []int
	var seenHeaders []string
	regs := buildRegs(t, []regSpec{
		{
			name:       "before",
			phases:     responseBodyPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &respActFilter{act: filter.Continue(filter.SetHeader("x-before", "1"))}
			},
		},
		{
			name:       "paused",
			phases:     responseBodyPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				pausedCounters.constructed++
				return &observingResponseBodyFilter{
					c: pausedCounters,
					headerAct: filter.NeedBody(
						filter.SetHeader("x-paused-header", "1"),
						filter.Mutation{StatusCode: testStatusCode(201)},
					),
					bodyAct: filter.Continue(
						filter.SetHeader("x-paused-body", "1"),
						filter.Mutation{Body: []byte("paused replacement")},
					),
					seenBodies:   &pausedBodies,
					seenStatuses: &seenStatuses,
					seenHeaders:  &seenHeaders,
				}
			},
		},
		{
			name:       "later-body",
			phases:     responseBodyPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				laterCounters.constructed++
				return &observingResponseBodyFilter{
					c:         laterCounters,
					headerAct: filter.NeedBody(filter.SetHeader("x-later-header", "1")),
					bodyAct: filter.Continue(
						filter.SetHeader("x-later-body", "1"),
						filter.Mutation{Body: []byte("final replacement"), StatusCode: testStatusCode(202)},
					),
					seenBodies:   &laterBodies,
					seenStatuses: &seenStatuses,
					seenHeaders:  &seenHeaders,
				}
			},
		},
		{
			name:       "after",
			phases:     responseBodyPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &respActFilter{act: filter.Continue(filter.SetHeader("x-after", "1"))}
			},
		},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	st.Response = httpreq.HTTPResponse{Status: 418, Headers: map[string]string{"x-original": "yes"}}
	units := unitsFor([][]string{{"before", "paused", "later", "after"}})

	headersResult, err := e.EvalResponseHeaders(context.Background(), st, units, ResponseScope{})
	if err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	if !headersResult.NeedsBody() {
		t.Fatal("response headers did not request a body")
	}
	if headersResult.Disposition != DispositionPassthrough || len(headersResult.HeaderOps) != 0 ||
		headersResult.Body != nil || headersResult.StatusCode != nil {
		t.Fatalf("suspended response headers leaked a result: %+v", headersResult)
	}

	original := filter.Body{Bytes: []byte("original response"), Complete: true}
	bodyResult, err := e.EvalResponseBody(context.Background(), st, headersResult, original)
	if err != nil {
		t.Fatalf("EvalResponseBody: %v", err)
	}
	requireDisposition(t, bodyResult.Disposition, DispositionMutated)
	wantNames := []string{"x-before", "x-paused-header", "x-paused-body", "x-later-header", "x-later-body", "x-after"}
	gotNames := make([]string, 0, len(bodyResult.HeaderOps))
	for _, op := range bodyResult.HeaderOps {
		gotNames = append(gotNames, op.Name)
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("header mutation order = %v, want %v", gotNames, wantNames)
	}
	if string(bodyResult.Body) != "final replacement" || bodyResult.StatusCode == nil || *bodyResult.StatusCode != 202 {
		t.Fatalf("body/status result = %q/%v, want final replacement/202", bodyResult.Body, bodyResult.StatusCode)
	}
	if pausedCounters.constructed != 1 || pausedCounters.headerCalls != 1 || pausedCounters.bodyCalls != 1 {
		t.Fatalf("paused calls = %+v, want one instance and one call per phase", *pausedCounters)
	}
	if laterCounters.constructed != 1 || laterCounters.headerCalls != 1 || laterCounters.bodyCalls != 1 {
		t.Fatalf("later calls = %+v, want inline body evaluation once", *laterCounters)
	}
	if len(pausedBodies) != 1 || len(laterBodies) != 1 ||
		!slices.Equal(pausedBodies[0].Bytes, original.Bytes) ||
		!slices.Equal(laterBodies[0].Bytes, original.Bytes) {
		t.Fatalf("observed bodies: paused=%+v later=%+v, want original %+v", pausedBodies, laterBodies, original)
	}
	if !slices.Equal(seenStatuses, []int{418, 418}) || !slices.Equal(seenHeaders, []string{"yes", "yes"}) {
		t.Fatalf("observed original response: statuses=%v headers=%v", seenStatuses, seenHeaders)
	}
}

func TestEvalResponseHeaders_WithAvailableResponseBodyRunsInline(t *testing.T) {
	c := &counters{}
	var seen []filter.Body
	regs := buildRegs(t, []regSpec{{
		name:       "body",
		phases:     responseBodyPhases,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		make: func(filter.RuleConfig[string]) filter.Filter {
			return &observingResponseBodyFilter{
				c:         c,
				headerAct: filter.NeedBody(),
				bodyAct: filter.Continue(
					filter.Mutation{Body: []byte("inline")},
					filter.Mutation{StatusCode: testStatusCode(204)},
				),
				seenBodies: &seen,
			}
		},
	}})
	res, err := NewEngine(regs, 0).EvalResponseHeaders(
		context.Background(),
		&filter.Stream{},
		unitsFor([][]string{{"body"}}),
		ResponseScope{},
		WithAvailableResponseBody(filter.Body{Complete: true}),
	)
	if err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	if res.NeedsBody() || c.bodyCalls != 1 || len(seen) != 1 || !seen[0].Complete || len(seen[0].Bytes) != 0 {
		t.Fatalf("inline result = %+v, calls=%+v seen=%+v", res, *c, seen)
	}
	if string(res.Body) != "inline" || res.StatusCode == nil || *res.StatusCode != 204 {
		t.Fatalf("inline body/status = %q/%v", res.Body, res.StatusCode)
	}
}

// A request-phase bypass must keep suppressing later response pairs across the
// body continuation, so the paused walk's scope has to survive the resume. The
// unbounded case pins that the assertion discriminates: without the scope, the
// later pair does run.
func TestEvalResponseBody_ResumedWalkHonorsBoundedScope(t *testing.T) {
	for _, tc := range []struct {
		name        string
		bypass      bool
		wantInvoked []string
	}{
		{name: "bounded by a request-phase bypass", bypass: true},
		{name: "unbounded", wantInvoked: []string{"later"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var invoked []string
			regs := buildRegs(t, []regSpec{
				{
					name:       "paused",
					phases:     responseBodyPhases,
					subscribes: subscribesTo(filter.PhaseResponseHeaders),
					make: func(filter.RuleConfig[string]) filter.Filter {
						return &observingResponseBodyFilter{
							c:         &counters{},
							headerAct: filter.NeedBody(),
							bodyAct:   filter.Continue(filter.SetHeader("x-paused-body", "1")),
						}
					},
				},
				{
					name: "bypasser",
					make: func(filter.RuleConfig[string]) filter.Filter {
						return &actionFilter{act: filter.Bypass(), c: &counters{}}
					},
				},
				{
					name:       "later",
					phases:     responseBodyPhases,
					subscribes: subscribesTo(filter.PhaseResponseHeaders),
					make: func(filter.RuleConfig[string]) filter.Filter {
						return &recordingRespFilter{onResp: func() { invoked = append(invoked, "later") }}
					},
				},
			})
			e := NewEngine(regs, 0)
			st := &filter.Stream{Info: filter.NewStreamInfo()}
			// The pausing pair precedes the bypass point, so it stays in scope
			// while "later" falls after it.
			units := unitsFor([][]string{{"paused", "bypass", "later"}})

			var scope ResponseScope
			if tc.bypass {
				rh, err := e.EvalRequestHeaders(context.Background(), st, units)
				if err != nil {
					t.Fatalf("EvalRequestHeaders: %v", err)
				}
				requireDisposition(t, rh.Disposition, DispositionBypassed)
				if !rh.ResponseScope.bounded {
					t.Fatal("the request bypass did not bound the response scope")
				}
				scope = rh.ResponseScope
			}

			hr, err := e.EvalResponseHeaders(context.Background(), st, units, scope)
			if err != nil {
				t.Fatalf("EvalResponseHeaders: %v", err)
			}
			if !hr.NeedsBody() {
				t.Fatal("the response walk did not pause for the body")
			}
			br, err := e.EvalResponseBody(context.Background(), st, hr,
				filter.Body{Bytes: []byte("response"), Complete: true})
			if err != nil {
				t.Fatalf("EvalResponseBody: %v", err)
			}
			if len(br.HeaderOps) != 1 || br.HeaderOps[0].Name != "x-paused-body" {
				t.Fatalf("HeaderOps = %+v, want the resumed pair's single mutation", br.HeaderOps)
			}
			if !slices.Equal(invoked, tc.wantInvoked) {
				t.Fatalf("invoked = %v, want %v: the resumed walk must replay the paused walk's scope",
					invoked, tc.wantInvoked)
			}
		})
	}
}

func TestEvalResponseBody_StopAndBypassReducePendingConsistently(t *testing.T) {
	tests := []struct {
		name            string
		bodyAct         filter.Action
		wantDisposition Disposition
		wantPending     bool
	}{
		{name: "stop discards", bodyAct: filter.Stop(filter.Reply{Status: 409}), wantDisposition: DispositionBlocked},
		{name: "bypass preserves", bodyAct: filter.Bypass(), wantDisposition: DispositionBypassed, wantPending: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			laterCalls := 0
			regs := buildRegs(t, []regSpec{
				{
					name:       "body",
					phases:     responseBodyPhases,
					subscribes: subscribesTo(filter.PhaseResponseHeaders),
					make: func(filter.RuleConfig[string]) filter.Filter {
						return &observingResponseBodyFilter{
							c:         &counters{},
							headerAct: filter.NeedBody(filter.SetHeader("x-before", "1")),
							bodyAct:   tc.bodyAct,
						}
					},
				},
				{
					name:       "later",
					phases:     responseBodyPhases,
					subscribes: subscribesTo(filter.PhaseResponseHeaders),
					make: func(filter.RuleConfig[string]) filter.Filter {
						laterCalls++
						return &respActFilter{act: filter.Continue()}
					},
				},
			})
			e := NewEngine(regs, 0)
			units := unitsFor([][]string{{"body", "later"}})
			hr, err := e.EvalResponseHeaders(context.Background(), &filter.Stream{}, units, ResponseScope{})
			if err != nil {
				t.Fatalf("EvalResponseHeaders: %v", err)
			}
			br, err := e.EvalResponseBody(context.Background(), &filter.Stream{}, hr, filter.Body{Complete: true})
			if err != nil {
				t.Fatalf("EvalResponseBody: %v", err)
			}
			requireDisposition(t, br.Disposition, tc.wantDisposition)
			if got := len(br.HeaderOps) > 0; got != tc.wantPending {
				t.Fatalf("pending mutation present = %v, want %v", got, tc.wantPending)
			}
			if laterCalls != 0 {
				t.Fatalf("later filter constructed %d times after terminal body action", laterCalls)
			}
		})
	}
}

func TestEvalResponseBody_FailClosedSynthesizesBlocked(t *testing.T) {
	boom := errors.New("webhook failed")
	regs := buildRegs(t, []regSpec{{
		name:       "strict",
		phases:     responseBodyPhases,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		onError:    filter.Always[string](filter.FailClosed),
		make: func(filter.RuleConfig[string]) filter.Filter {
			return &observingResponseBodyFilter{
				c:         &counters{},
				headerAct: filter.NeedBody(filter.SetHeader("x-discard", "1")),
				bodyAct:   filter.Continue(),
				bodyErr:   boom,
			}
		},
	}})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	units := unitsFor([][]string{{"cfg"}})
	hr, err := e.EvalResponseHeaders(context.Background(), st, units, ResponseScope{})
	if err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	br, err := e.EvalResponseBody(context.Background(), st, hr, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("configured FailClosed returned engine error: %v", err)
	}
	requireDisposition(t, br.Disposition, DispositionBlocked)
	if br.Reply.Status != 500 || br.Reply.Details != "epe_response_body_failed_closed" {
		t.Fatalf("Reply = %+v, want response-body local 500", br.Reply)
	}
	if len(br.HeaderOps) != 0 {
		t.Fatalf("FailClosed leaked pending mutations: %+v", br.HeaderOps)
	}
	if len(st.Info.Filters) != 2 || !errors.Is(st.Info.Filters[1].Err, boom) {
		t.Fatalf("filter records = %+v, want original body error", st.Info.Filters)
	}
}

func TestEvalRejectsPhaseIncompatibleMutations(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T) error
		want string
	}{
		{
			name: "request headers status",
			want: "status",
			run: func(t *testing.T) error {
				regs := buildRegs(t, []regSpec{{name: "request", make: func(filter.RuleConfig[string]) filter.Filter {
					return &actionFilter{c: &counters{}, act: filter.Continue(filter.Mutation{StatusCode: testStatusCode(200)})}
				}}})
				_, err := NewEngine(regs, 0).EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"cfg"}}))
				return err
			},
		},
		{
			name: "response headers invalid status",
			want: "200..599",
			run: func(t *testing.T) error {
				regs := responseActionRegs(t, filter.Continue(filter.Mutation{StatusCode: testStatusCode(199)}), responseBodyPhases)
				_, err := NewEngine(regs, 0).EvalResponseHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"cfg"}}), ResponseScope{})
				return err
			},
		},
		{
			name: "response headers clear route cache",
			want: "route cache",
			run: func(t *testing.T) error {
				regs := responseActionRegs(t, filter.Continue(filter.Mutation{Route: &filter.RouteMutation{ClearCache: true}}), responseBodyPhases)
				_, err := NewEngine(regs, 0).EvalResponseHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"cfg"}}), ResponseScope{})
				return err
			},
		},
		{
			name: "response headers cannot bypass StatusCode validation",
			want: "StatusCode",
			run: func(t *testing.T) error {
				regs := responseActionRegs(t, filter.Continue(filter.SetHeader(":status", "199")), responseBodyPhases)
				_, err := NewEngine(regs, 0).EvalResponseHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"cfg"}}), ResponseScope{})
				return err
			},
		},
		{
			name: "response headers need body without capability",
			want: "response-body support",
			run: func(t *testing.T) error {
				regs := responseActionRegs(t, filter.NeedBody(), filter.PhaseResponseHeaders)
				_, err := NewEngine(regs, 0).EvalResponseHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"cfg"}}), ResponseScope{})
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want text %q", err, tc.want)
			}
		})
	}
}

func responseActionRegs(t *testing.T, act filter.Action, phases filter.Phase) []filter.Registration {
	t.Helper()
	return buildRegs(t, []regSpec{{
		name:       "response",
		phases:     phases,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		make: func(filter.RuleConfig[string]) filter.Filter {
			return &respActFilter{act: act}
		},
	}})
}
