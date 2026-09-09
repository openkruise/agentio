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
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// --- test filters ------------------------------------------------------

type counters struct {
	constructed int
	headerCalls int
	bodyCalls   int
}

type actionFilter struct {
	filter.PassThrough
	act filter.Action
	c   *counters
}

func (f *actionFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.c.headerCalls++
	return f.act, nil
}

type mutatingFilter struct {
	filter.PassThrough
	c    *counters
	muts []filter.Mutation
	// seen collects the unit names this instance was constructed with.
	seen []string
}

func (f *mutatingFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.c.headerCalls++
	return filter.Continue(f.muts...), nil
}

type bodyFilter struct {
	filter.PassThrough
	c       *counters
	bodyAct filter.Action
}

func (f *bodyFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.c.headerCalls++
	return filter.NeedBody(), nil
}

func (f *bodyFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	f.c.bodyCalls++
	return f.bodyAct, nil
}

type observingBodyFilter struct {
	filter.PassThrough
	c         *counters
	headerAct filter.Action
	bodyAct   filter.Action
	seen      *[]filter.Body
	prepared  bool
}

func (f *observingBodyFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.c.headerCalls++
	f.prepared = true
	return f.headerAct, nil
}

func (f *observingBodyFilter) OnRequestBody(_ context.Context, _ *filter.Stream, body filter.Body) (filter.Action, error) {
	f.c.bodyCalls++
	if f.seen != nil {
		*f.seen = append(*f.seen, body)
	}
	if !f.prepared {
		return filter.Continue(), errors.New("body callback used a different filter instance")
	}
	return f.bodyAct, nil
}

type errFilter struct {
	filter.PassThrough
	err error
}

func (f *errFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(), f.err
}

// --- registration helpers ----------------------------------------------

type regSpec struct {
	name    string
	onError func(cfg string) filter.FailurePolicy
	make    func(cfg filter.RuleConfig[string]) filter.Filter
	// phases overrides the default request-headers|request-body mask.
	phases filter.Phase
	// subscribes returns the conditional phases required by a config.
	subscribes func(cfg string) filter.Phase
}

// subscribesTo returns a config-independent subscription, for the common case
// where every rule carrying the filter needs the same phases.
func subscribesTo(p filter.Phase) func(string) filter.Phase {
	return func(string) filter.Phase { return p }
}

func buildRegs(t testing.TB, specs []regSpec) []filter.Registration {
	t.Helper()
	definitions := make([]filter.Definition, 0, len(specs))
	for _, sp := range specs {
		phases := sp.phases
		if phases == 0 {
			phases = filter.PhaseRequestHeaders | filter.PhaseRequestBody
		}
		d := filter.Descriptor[string]{
			Name:         sp.name,
			Phases:       phases,
			OnError:      sp.onError,
			SubscribesOf: sp.subscribes,
			New:          sp.make,
		}
		// Parse is never invoked: engine tests build units with pre-parsed
		// configs (unitsFor), so the JSON seam stays a stub.
		definitions = append(definitions, filter.Define(d, func(json.RawMessage) (string, error) {
			return "", nil
		}))
	}
	regs, err := filter.Build(definitions...)
	if err != nil {
		t.Fatalf("build registrations: %v", err)
	}
	return regs
}

// unitsFor builds units where cfgRow[i][j] is the config for unit i /
// registration j; "" means the unit doesn't carry that filter's config.
func unitsFor(cfgRows [][]string) []Unit {
	units := make([]Unit, len(cfgRows))
	for i, row := range cfgRows {
		cfgs := make([]any, len(row))
		for j, v := range row {
			if v != "" {
				cfgs[j] = v
			}
		}
		units[i] = Unit{
			ID:   filter.UnitID{Scope: "ns/p", Name: "r" + strconv.Itoa(i), Ordinal: i},
			Cfgs: cfgs,
		}
	}
	return units
}

func requireDisposition(t *testing.T, got, want Disposition) {
	t.Helper()
	if got != want {
		t.Fatalf("Disposition = %v, want %v", got, want)
	}
}

func TestEngineCopiesRegistrations(t *testing.T) {
	regs := buildRegs(t, []regSpec{{
		name: "original",
		make: func(filter.RuleConfig[string]) filter.Filter {
			return filter.PassThrough{}
		},
	}})
	e := NewEngine(regs, 0)
	regs[0].Name = "caller-mutated"
	got := e.Registrations()
	if got[0].Name != "original" {
		t.Fatalf("engine retained caller slice: %#v", got)
	}
	got[0].Name = "accessor-mutated"
	if e.Registrations()[0].Name != "original" {
		t.Fatal("Registrations exposed engine storage")
	}
}

func TestEvalRejectsMisalignedUnitConfigs(t *testing.T) {
	regs := buildRegs(t, []regSpec{{
		name: "one",
		make: func(filter.RuleConfig[string]) filter.Filter {
			return filter.PassThrough{}
		},
	}})
	e := NewEngine(regs, 0)
	_, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, []Unit{{
		ID:   filter.UnitID{Scope: "ns/p", Name: "r"},
		Cfgs: nil,
	}})
	if err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("misaligned configs error = %v", err)
	}
}

// Subscription entry points validate Unit.Cfgs before indexing it.
func TestSubscriptionEntryPointsRejectMisalignedUnitConfigs(t *testing.T) {
	regs := buildRegs(t, []regSpec{{
		name:       "one",
		phases:     bothHeaderPhases,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		make:       func(filter.RuleConfig[string]) filter.Filter { return filter.PassThrough{} },
	}})
	e := NewEngine(regs, 0)
	// Cfgs is nil where the engine has one registration, so any Cfgs[0] read panics.
	bad := []Unit{{ID: filter.UnitID{Scope: "ns/p", Name: "r"}, Cfgs: nil}}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"ValidateSubscriptions", func() error { _, err := e.ValidateSubscriptions(bad); return err }},
		{"EvalResponseHeaders", func() error {
			_, err := e.EvalResponseHeaders(context.Background(), &filter.Stream{}, bad, ResponseScope{})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil || !strings.Contains(err.Error(), "config") {
				t.Fatalf("misaligned configs error = %v, want one naming the config count", err)
			}
		})
	}
}

func TestEval_StrictRuleOrderRunsEarlierWorkBeforeLaterBlock(t *testing.T) {
	earlier := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "earlier", make: func(filter.RuleConfig[string]) filter.Filter {
			return &mutatingFilter{c: earlier, muts: []filter.Mutation{filter.SetHeader("x-earlier", "1")}}
		}},
		{name: "block", make: func(filter.RuleConfig[string]) filter.Filter {
			return &actionFilter{act: filter.Stop(filter.Reply{Status: 403}), c: &counters{}}
		}},
	})

	res, err := NewEngine(regs, 0).EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{
		{"run", ""},
		{"", "block"},
	}))
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionBlocked)
	if earlier.headerCalls != 1 {
		t.Fatalf("earlier rule ran %d times, want 1 before the later block", earlier.headerCalls)
	}
}

func TestEval_BypassStopsOnlyFollowingRules(t *testing.T) {
	earlier := &counters{}
	later := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "body", make: func(cfg filter.RuleConfig[string]) filter.Filter {
			if cfg.Cfg == "earlier" {
				return &bodyFilter{c: earlier, bodyAct: filter.Continue()}
			}
			return &bodyFilter{c: later, bodyAct: filter.Continue()}
		}},
		{name: "bypass", make: func(filter.RuleConfig[string]) filter.Filter {
			return &actionFilter{act: filter.Bypass(), c: &counters{}}
		}},
	})

	res, err := NewEngine(regs, 0).EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{
		{"earlier", ""},
		{"", "bypass"},
		{"later", ""},
	}))
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	if !res.NeedsBody() {
		t.Fatal("NeedsBody = false, want the earlier rule to pause before bypass is reached")
	}
	if earlier.headerCalls != 1 || later.headerCalls != 0 {
		t.Fatalf("header calls: earlier=%d later=%d, want 1 and 0", earlier.headerCalls, later.headerCalls)
	}
}

// --- the verification table -------------------------------------------

func TestEval_OrderedRulesTable(t *testing.T) {
	ctx := context.Background()
	st := &filter.Stream{}

	// Bespoke action order used to exercise each action kind.
	newChain := func() (regs []filter.Registration, bypassC, blockC, mcpC, ttC *counters) {
		bypassC, blockC, mcpC, ttC = &counters{}, &counters{}, &counters{}, &counters{}
		regs = buildRegs(t, []regSpec{
			{name: "bypass", make: func(c filter.RuleConfig[string]) filter.Filter {
				bypassC.constructed++
				return &actionFilter{act: filter.Bypass(), c: bypassC}
			}},
			{name: "mcp", make: func(c filter.RuleConfig[string]) filter.Filter {
				mcpC.constructed++
				return &bodyFilter{c: mcpC, bodyAct: filter.Continue()}
			}},
			{name: "block", make: func(c filter.RuleConfig[string]) filter.Filter {
				blockC.constructed++
				return &actionFilter{act: filter.Stop(filter.Reply{Status: 451}), c: blockC}
			}},
			{name: "tt", make: func(c filter.RuleConfig[string]) filter.Filter {
				ttC.constructed++
				f := &mutatingFilter{c: ttC, muts: []filter.Mutation{filter.SetHeader("x-token", "1")}}
				f.seen = append(f.seen, c.ID.Name)
				return f
			}},
		})
		return
	}
	// column order: bypass, mcp, block, tt
	t.Run("block rule then bypass rule -> blocked and remaining actions skipped", func(t *testing.T) {
		regs, _, _, _, ttC := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"", "", "b", "t"},
			{"y", "", "", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBlocked)
		if res.Reply.Status != 451 {
			t.Errorf("Reply.Status = %d, want 451", res.Reply.Status)
		}
		if ttC.constructed != 0 {
			t.Errorf("mutation filter constructed %d times; block must skip remaining work", ttC.constructed)
		}
	})

	t.Run("same unit bypass+block -> bypassed (action order in unit)", func(t *testing.T) {
		regs, _, blockC, _, _ := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"y", "", "b", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBypassed)
		if blockC.headerCalls != 0 {
			t.Errorf("block ran %d times; bypass precedes it in action order", blockC.headerCalls)
		}
	})

	t.Run("tt rule then bypass rule -> mutation preserved", func(t *testing.T) {
		regs, _, _, _, ttC := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"", "", "", "t"},
			{"y", "", "", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBypassed)
		if ttC.headerCalls != 1 {
			t.Errorf("tt ran %d times, want 1", ttC.headerCalls)
		}
		if len(res.HeaderOps) != 1 || res.HeaderOps[0].Name != "x-token" {
			t.Errorf("HeaderOps = %+v, want preserved x-token", res.HeaderOps)
		}
	})

	t.Run("bypass rule then tt rule -> no injection", func(t *testing.T) {
		regs, _, _, _, ttC := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"y", "", "", ""},
			{"", "", "", "t"},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBypassed)
		if ttC.constructed != 0 {
			t.Errorf("tt constructed %d times; its unit is after the stopping action", ttC.constructed)
		}
		if len(res.HeaderOps) != 0 {
			t.Errorf("HeaderOps = %+v, want none", res.HeaderOps)
		}
	})

	t.Run("mcp rule then bypass rule -> body work completes before bypass", func(t *testing.T) {
		regs, _, _, mcpC, _ := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"", "m", "", ""},
			{"y", "", "", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionPassthrough)
		if mcpC.headerCalls != 1 {
			t.Errorf("earlier body filter ran %d times, want 1", mcpC.headerCalls)
		}
		if !res.NeedsBody() {
			t.Fatal("NeedsBody = false; the earlier rule must complete before bypass")
		}
		bodyRes, err := e.EvalRequestBody(ctx, st, res, filter.Body{Complete: true})
		if err != nil {
			t.Fatalf("EvalRequestBody: %v", err)
		}
		requireDisposition(t, bodyRes.Disposition, DispositionBypassed)
		if mcpC.bodyCalls != 1 {
			t.Errorf("earlier body filter finalized %d times, want 1", mcpC.bodyCalls)
		}
	})

	t.Run("tt rule then block rule -> earlier work runs before block", func(t *testing.T) {
		regs, _, _, _, ttC := newChain()
		e := NewEngine(regs, 0)
		res, err := e.EvalRequestHeaders(ctx, st, unitsFor([][]string{
			{"", "", "", "t"},
			{"", "", "b", ""},
		}))
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		requireDisposition(t, res.Disposition, DispositionBlocked)
		if ttC.constructed != 1 {
			t.Errorf("tt constructed %d times, want 1 before later block", ttC.constructed)
		}
	})
}

func TestEval_NewNeverCalledWithEmptyConfigs(t *testing.T) {
	var newCalls []int
	regs := buildRegs(t, []regSpec{
		{name: "m", make: func(filter.RuleConfig[string]) filter.Filter {
			newCalls = append(newCalls, 1)
			return &mutatingFilter{c: &counters{}}
		}},
	})
	e := NewEngine(regs, 0)
	// No unit carries m's config.
	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{""}})); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	for _, n := range newCalls {
		if n == 0 {
			t.Fatal("New called with empty config slice")
		}
	}
	if len(newCalls) != 0 {
		t.Fatalf("New called %d times, want 0", len(newCalls))
	}
}

func TestEval_EachRuleConfigRunsOnce(t *testing.T) {
	c := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "action", make: func(filter.RuleConfig[string]) filter.Filter {
			c.constructed++
			return &actionFilter{act: filter.Continue(), c: c}
		}},
	})
	e := NewEngine(regs, 0)
	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"a"}, {"b"}})); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if c.headerCalls != 2 {
		t.Fatalf("filter ran %d times, want once for each of 2 rules", c.headerCalls)
	}
}

func TestEval_FilterRunsOncePerConfiguredUnit(t *testing.T) {
	var got []string
	regs := buildRegs(t, []regSpec{
		{name: "m", make: func(c filter.RuleConfig[string]) filter.Filter {
			f := &mutatingFilter{c: &counters{}}
			got = append(got, c.Cfg)
			return f
		}},
	})
	e := NewEngine(regs, 0)
	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"a"}, {""}, {"c"}})); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("configs = %v, want [a c]", got)
	}
}

func TestEvalBody_StopShortCircuits(t *testing.T) {
	stopC, contC := &counters{}, &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "deny", make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: stopC, bodyAct: filter.Stop(filter.Reply{Status: 452})}
		}},
		{name: "later", make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: contC, bodyAct: filter.Continue()}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{}
	hr, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"d", "l"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !hr.NeedsBody() {
		t.Fatal("NeedsBody = false, want true")
	}
	br, err := e.EvalRequestBody(context.Background(), st, hr, filter.Body{Bytes: []byte("{}"), Complete: true})
	if err != nil {
		t.Fatalf("EvalRequestBody: %v", err)
	}
	requireDisposition(t, br.Disposition, DispositionBlocked)
	if br.Reply.Status != 452 {
		t.Errorf("Reply.Status = %d, want 452", br.Reply.Status)
	}
	if contC.bodyCalls != 0 {
		t.Errorf("later body filter ran %d times after a Stop", contC.bodyCalls)
	}
}

func TestEvalBody_LaterBypassPreservesEarlierMutationAndSkipsFollowingRule(t *testing.T) {
	earlier := &counters{}
	later := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "body", make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: earlier, bodyAct: filter.Continue(filter.SetHeader("x-body", "1"))}
		}},
		{name: "bypass", make: func(filter.RuleConfig[string]) filter.Filter {
			return &actionFilter{act: filter.Bypass(), c: &counters{}}
		}},
		{name: "later", make: func(filter.RuleConfig[string]) filter.Filter {
			return &mutatingFilter{c: later, muts: []filter.Mutation{filter.SetHeader("x-later", "1")}}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{}
	hr, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{
		{"body", "", ""},
		{"", "bypass", ""},
		{"", "", "later"},
	}))
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	br, err := e.EvalRequestBody(context.Background(), st, hr, filter.Body{Complete: true})
	if err != nil {
		t.Fatalf("EvalRequestBody: %v", err)
	}
	requireDisposition(t, br.Disposition, DispositionBypassed)
	if len(br.HeaderOps) != 1 || br.HeaderOps[0].Name != "x-body" {
		t.Fatalf("HeaderOps = %+v, want preserved earlier body mutation", br.HeaderOps)
	}
	if later.headerCalls != 0 {
		t.Fatalf("following rule ran %d times after bypass", later.headerCalls)
	}
}

func TestEvalRequestBody_FoldsAllPendingMutationsAfterResume(t *testing.T) {
	pausedCounters := &counters{}
	laterCounters := &counters{}
	var pausedBodies, laterBodies []filter.Body
	regs := buildRegs(t, []regSpec{
		{name: "before", make: func(filter.RuleConfig[string]) filter.Filter {
			return &mutatingFilter{c: &counters{}, muts: []filter.Mutation{filter.SetHeader("x-before", "1")}}
		}},
		{name: "paused", make: func(filter.RuleConfig[string]) filter.Filter {
			pausedCounters.constructed++
			return &observingBodyFilter{
				c:         pausedCounters,
				headerAct: filter.NeedBody(filter.SetHeader("x-paused-header", "1")),
				bodyAct: filter.Continue(
					filter.SetHeader("x-paused-body", "1"),
					filter.Mutation{Body: []byte("paused replacement")},
				),
				seen: &pausedBodies,
			}
		}},
		{name: "later-body", make: func(filter.RuleConfig[string]) filter.Filter {
			laterCounters.constructed++
			return &observingBodyFilter{
				c:         laterCounters,
				headerAct: filter.NeedBody(filter.SetHeader("x-later-header", "1")),
				bodyAct: filter.Continue(
					filter.SetHeader("x-later-body", "1"),
					filter.Mutation{Body: []byte("final replacement")},
				),
				seen: &laterBodies,
			}
		}},
		{name: "after", make: func(filter.RuleConfig[string]) filter.Filter {
			return &mutatingFilter{c: &counters{}, muts: []filter.Mutation{filter.SetHeader("x-after", "1")}}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	units := unitsFor([][]string{{"before", "paused", "later", "after"}})

	headersResult, err := e.EvalRequestHeaders(context.Background(), st, units)
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	if !headersResult.NeedsBody() {
		t.Fatal("request headers did not request a body")
	}
	if headersResult.Disposition != DispositionPassthrough || len(headersResult.HeaderOps) != 0 || headersResult.Body != nil {
		t.Fatalf("suspended headers leaked a result: %+v", headersResult)
	}

	original := filter.Body{Bytes: []byte("original"), Complete: true}
	bodyResult, err := e.EvalRequestBody(context.Background(), st, headersResult, original)
	if err != nil {
		t.Fatalf("EvalRequestBody: %v", err)
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
	if string(bodyResult.Body) != "final replacement" {
		t.Fatalf("Body = %q, want last replacement", bodyResult.Body)
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
}

func TestEvalRequestHeaders_WithAvailableRequestBodyRunsInline(t *testing.T) {
	c := &counters{}
	regs := buildRegs(t, []regSpec{{
		name: "body",
		make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: c, bodyAct: filter.Continue(filter.SetHeader("x-inline", "1"))}
		},
	}})
	res, err := NewEngine(regs, 0).EvalRequestHeaders(
		context.Background(),
		&filter.Stream{},
		unitsFor([][]string{{"body"}}),
		WithAvailableRequestBody(filter.Body{Complete: true}),
	)
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	if res.NeedsBody() || c.bodyCalls != 1 || len(res.HeaderOps) != 1 {
		t.Fatalf("inline result = %+v, body calls = %d", res, c.bodyCalls)
	}
}

func TestEvalBody_NeedRejected(t *testing.T) {
	regs := buildRegs(t, []regSpec{
		{name: "greedy", make: func(filter.RuleConfig[string]) filter.Filter {
			return &bodyFilter{c: &counters{}, bodyAct: filter.NeedBody()}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{}
	hr, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"g"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if _, err := e.EvalRequestBody(context.Background(), st, hr, filter.Body{Complete: true}); err == nil {
		t.Fatal("want error: Need from the body phase would be silently ignored by Envoy")
	}
}

func TestInvoke_FailOpenSkips(t *testing.T) {
	mutC := &counters{}
	regs := buildRegs(t, []regSpec{
		{name: "flaky", onError: filter.Always[string](filter.FailOpen), make: func(filter.RuleConfig[string]) filter.Filter {
			return &errFilter{err: errors.New("boom")}
		}},
		{name: "after", make: func(filter.RuleConfig[string]) filter.Filter {
			return &mutatingFilter{c: mutC, muts: []filter.Mutation{filter.SetHeader("x", "1")}}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	res, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"f", "a"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionMutated)
	if mutC.headerCalls != 1 {
		t.Errorf("later filter ran %d times, want 1 — fail-open must not stop the chain", mutC.headerCalls)
	}
	if !slices.Contains(unitActions(st.Info), "flaky:error-open") {
		t.Error("no error-open record for the failing filter")
	}
}

func TestInvoke_FailClosedSynthesizesBlocked(t *testing.T) {
	regs := buildRegs(t, []regSpec{
		{name: "strict", onError: filter.Always[string](filter.FailClosed), make: func(filter.RuleConfig[string]) filter.Filter {
			return &errFilter{err: errors.New("boom")}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	res, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"s"}}))
	if err != nil {
		t.Fatalf("configured FailClosed returned engine error: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionBlocked)
	if res.Reply.Status != 500 || res.Reply.Details != "epe_request_headers_failed_closed" {
		t.Fatalf("Reply = %+v, want phase-specific local 500", res.Reply)
	}
	// error-closed, not block: the filter never chose to deny, so an audit that
	// called this a block would present a broken enforcement path as a working one.
	if got := unitActions(st.Info); !slices.Equal(got, []string{"strict:error-closed"}) {
		t.Errorf("unit actions = %v, want [strict:error-closed]", got)
	}
	if st.Info.Error != "boom" {
		t.Errorf("Info.Error = %q, want the filter's error", st.Info.Error)
	}
}

func TestInvoke_OnErrorConsultsConfig(t *testing.T) {
	mk := func(filter.RuleConfig[string]) filter.Filter { return &errFilter{err: errors.New("boom")} }
	policy := func(cfg string) filter.FailurePolicy {
		if cfg == "open" {
			return filter.FailOpen
		}
		return filter.FailClosed
	}
	regs := buildRegs(t, []regSpec{{name: "fr", onError: policy, make: mk}})
	e := NewEngine(regs, 0)

	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"open"}})); err != nil {
		t.Fatalf("open policy: Eval err = %v, want fail-open", err)
	}
	closed, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"closed"}}))
	if err != nil {
		t.Fatalf("closed policy: Eval err = %v, want handled block", err)
	}
	requireDisposition(t, closed.Disposition, DispositionBlocked)
}

// bodyErrFilter asks for the body on headers, then fails in the body phase.
type bodyErrFilter struct {
	filter.PassThrough
	err error
}

func (f *bodyErrFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(), nil
}

func (f *bodyErrFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Continue(), f.err
}

// The body phase applies the failure policy resolved from the rule config.
func TestEvalBody_OnErrorConsultsConfig(t *testing.T) {
	mk := func(filter.RuleConfig[string]) filter.Filter {
		return &bodyErrFilter{err: errors.New("boom")}
	}
	policy := func(cfg string) filter.FailurePolicy {
		if cfg == "open" {
			return filter.FailOpen
		}
		return filter.FailClosed
	}
	regs := buildRegs(t, []regSpec{{
		name: "fr-body", onError: policy, make: mk,
	}})
	e := NewEngine(regs, 0)

	run := func(cfg string) (*RequestBodyResult, error) {
		st := &filter.Stream{}
		res, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{cfg}}))
		if err != nil {
			t.Fatalf("headers phase erred unexpectedly: %v", err)
		}
		if !res.NeedsBody() {
			t.Fatal("filter did not request the body")
		}
		return e.EvalRequestBody(context.Background(), st, res, filter.Body{Bytes: []byte("x"), Complete: true})
	}

	if _, err := run("open"); err != nil {
		t.Errorf("FailOpen policy: EvalRequestBody err = %v, want fail-open (nil)", err)
	}
	closed, err := run("closed")
	if err != nil {
		t.Fatalf("FailClosed policy returned engine error: %v", err)
	}
	requireDisposition(t, closed.Disposition, DispositionBlocked)
	if closed.Reply.Status != 500 || closed.Reply.Details != "epe_request_body_failed_closed" {
		t.Fatalf("Reply = %+v, want request-body local 500", closed.Reply)
	}
}

// respMutFilter declares the response-headers phase and returns a mutation.
type respMutFilter struct {
	filter.PassThrough
}

func (respMutFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(filter.SetHeader("x-resp", "v")), nil
}

// TestEvalResponseHeaders verifies response-header mutation folding and no-op handling.
func TestEvalResponseHeaders(t *testing.T) {
	tests := []struct {
		name         string
		make         func(filter.RuleConfig[string]) filter.Filter
		wantOps      []filter.HeaderOp
		wantDisp     Disposition
		wantUnitActs []string
	}{
		{
			name:     "mutations are folded into HeaderOps",
			make:     func(filter.RuleConfig[string]) filter.Filter { return respMutFilter{} },
			wantOps:  []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "x-resp", Value: "v"}},
			wantDisp: DispositionMutated,
			// Mutating in the response phase is a recordable unit action.
			wantUnitActs: []string{"resp:mutate"},
		},
		{
			name:     "observation-only is fine",
			make:     func(filter.RuleConfig[string]) filter.Filter { return filter.PassThrough{} },
			wantDisp: DispositionPassthrough,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			regs := buildRegs(t, []regSpec{{
				name:       "resp",
				phases:     filter.PhaseRequestHeaders | filter.PhaseResponseHeaders,
				subscribes: subscribesTo(filter.PhaseResponseHeaders),
				make:       tc.make,
			}})
			e := NewEngine(regs, 0)
			st := &filter.Stream{Info: filter.NewStreamInfo()}
			units := unitsFor([][]string{{"cfg"}})

			res, err := e.EvalResponseHeaders(context.Background(), st, units, ResponseScope{})
			if err != nil {
				t.Fatalf("EvalResponseHeaders: %v", err)
			}
			requireDisposition(t, res.Disposition, tc.wantDisp)
			if !equalOps(res.HeaderOps, tc.wantOps) {
				t.Errorf("HeaderOps = %+v, want %+v", res.HeaderOps, tc.wantOps)
			}
			if got := unitActions(st.Info); !slices.Equal(got, tc.wantUnitActs) {
				t.Errorf("unit actions = %v, want %v", got, tc.wantUnitActs)
			}
		})
	}
}

// --- response-phase subscription ---------------------------------------

// unitActions renders every recorded action as "<filter>:<kind>", which is a
// compact shape to assert against; the recorded form is a struct.
func unitActions(info *filter.StreamInfo) []string {
	var out []string
	for _, u := range info.Matched {
		for _, a := range u.FilterActions {
			out = append(out, a.Filter+":"+string(a.Kind))
		}
	}
	return out
}

func equalOps(got, want []filter.HeaderOp) bool {
	return slices.Equal(got, want)
}

// wantRespFilter returns its configured request action and optionally mutates response headers.
type wantRespFilter struct {
	filter.PassThrough
	requestAct filter.Action
	respValue  string
}

func (f *wantRespFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return f.requestAct, nil
}

func (f *wantRespFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	if f.respValue == "" {
		return filter.Continue(), nil
	}
	return filter.Continue(filter.SetHeader("x-resp", f.respValue)), nil
}

const bothHeaderPhases = filter.PhaseRequestHeaders | filter.PhaseResponseHeaders

// Unsupported config subscriptions are rejected before response dispatch.
func TestSubscription_RejectsAPhaseItCannotOpen(t *testing.T) {
	regs := buildRegs(t, []regSpec{{
		name:   "greedy",
		phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		// The request body is subscribed at runtime via NeedBody, never from
		// config, so declaring it here is a filter-authoring error.
		subscribes: subscribesTo(filter.PhaseRequestBody),
		make:       func(filter.RuleConfig[string]) filter.Filter { return filter.PassThrough{} },
	}})
	e := NewEngine(regs, 0)
	units := unitsFor([][]string{{"cfg"}})

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"ValidateSubscriptions", func() error { _, err := e.ValidateSubscriptions(units); return err }},
		{"EvalResponseHeaders", func() error {
			_, err := e.EvalResponseHeaders(context.Background(), &filter.Stream{}, units, ResponseScope{})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("accepted a phase the engine cannot open; the declaration would vanish silently")
			}
			if !strings.Contains(err.Error(), "greedy") {
				t.Errorf("err = %q, want it to name the filter", err)
			}
		})
	}
	if _, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, units); err != nil {
		t.Fatalf("EvalRequestHeaders inspected response subscriptions: %v", err)
	}
}

// Only response headers are config-subscribable.
func TestSubscribablePhasesIsNarrowerThanDispatched(t *testing.T) {
	if SubscribablePhases&^filter.DispatchedPhases != 0 {
		t.Fatal("SubscribablePhases must be a subset of DispatchedPhases")
	}
	if SubscribablePhases&filter.PhaseRequestHeaders != 0 {
		t.Error("request headers arrive unconditionally; nothing should subscribe to them")
	}
	if SubscribablePhases&filter.PhaseRequestBody != 0 {
		t.Error("the request body is subscribed at runtime via NeedBody, not from config")
	}
}

// ValidateSubscriptions derives demand from config without constructing filters.
func TestValidateSubscriptions_DerivesDemandWithoutRunningFilters(t *testing.T) {
	ran := &counters{}
	regs := buildRegs(t, []regSpec{{
		name:       "resp",
		phases:     bothHeaderPhases,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		make: func(filter.RuleConfig[string]) filter.Filter {
			ran.constructed++
			return &actionFilter{act: filter.Continue(), c: ran}
		},
	}})
	e := NewEngine(regs, 0)
	units := unitsFor([][]string{{"quiet"}, {"want"}})

	subscriptions, err := e.ValidateSubscriptions(units)
	if err != nil {
		t.Fatalf("ValidateSubscriptions: %v", err)
	}
	if subscriptions&filter.PhaseResponseHeaders == 0 {
		t.Fatal("response headers missing from subscriptions")
	}
	if ran.constructed != 0 || ran.headerCalls != 0 {
		t.Fatalf("constructed %d filters and made %d calls; it must run none",
			ran.constructed, ran.headerCalls)
	}
}

// Configs with no response demand must not open the phase.
func TestValidateSubscriptions_NoDemand(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  regSpec
		units []Unit
		why   string
	}{
		{
			name: "config does not ask",
			spec: regSpec{
				name:   "resp",
				phases: bothHeaderPhases,
				// Capable of running there, this config does not need it. Zero
				// rather than nil, because Build rejects a nil SubscribesOf on a
				// filter declaring the phase; zero is also the shape production
				// takes, where a request-only config returns it.
				subscribes: subscribesTo(0),
				make:       func(filter.RuleConfig[string]) filter.Filter { return filter.PassThrough{} },
			},
			units: unitsFor([][]string{{"cfg"}}),
			why:   "no config asks",
		},
		{
			name: "unit carries no config for this filter",
			spec: regSpec{
				name:       "resp",
				phases:     bothHeaderPhases,
				subscribes: subscribesTo(filter.PhaseResponseHeaders),
				make:       func(filter.RuleConfig[string]) filter.Filter { return filter.PassThrough{} },
			},
			units: unitsFor([][]string{{""}}),
			why:   "the unit does not carry this filter's config",
		},
		{
			name: "subscribes beyond declared capability",
			spec: regSpec{
				name:       "reqonly",
				phases:     filter.PhaseRequestHeaders,
				subscribes: subscribesTo(filter.PhaseResponseHeaders),
				make:       func(filter.RuleConfig[string]) filter.Filter { return filter.PassThrough{} },
			},
			units: unitsFor([][]string{{"cfg"}}),
			why:   "the filter cannot run in the response phase, so Build narrows the declaration away",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subscriptions, err := NewEngine(buildRegs(t, []regSpec{tc.spec}), 0).ValidateSubscriptions(tc.units)
			if err != nil {
				t.Fatalf("ValidateSubscriptions: %v", err)
			}
			if subscriptions&filter.PhaseResponseHeaders != 0 {
				t.Fatalf("subscriptions = %08b, want no response headers: %s", subscriptions, tc.why)
			}
		})
	}
}

// Response-header subscription remains stable when request evaluation pauses for a body.
func TestValidateSubscriptions_UnaffectedByAnEarlierPause(t *testing.T) {
	regs := buildRegs(t, []regSpec{
		{
			name:   "pauser",
			phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &bodyFilter{c: &counters{}, bodyAct: filter.Continue()}
			},
		},
		{
			name:       "resp",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make:       func(filter.RuleConfig[string]) filter.Filter { return filter.PassThrough{} },
		},
	})
	e := NewEngine(regs, 0)
	units := unitsFor([][]string{{"pause", "want"}})

	before, err := e.ValidateSubscriptions(units)
	if err != nil {
		t.Fatalf("ValidateSubscriptions: %v", err)
	}
	if before&filter.PhaseResponseHeaders == 0 {
		t.Fatal("the post-pause rule subscribes to response headers")
	}

	// Running the walk — which pauses at the first registration and never reaches
	// the second in this phase — must not change the answer.
	res, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, units)
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	if !res.NeedsBody() {
		t.Fatal("expected the walk to pause, so this exercises the old failure")
	}
	after, err := e.ValidateSubscriptions(units)
	if err != nil {
		t.Fatalf("ValidateSubscriptions after the pause: %v", err)
	}
	if after != before {
		t.Fatalf("answer changed across the pause: %v then %v", before, after)
	}
}

// Response dispatch includes only subscribed pairs.
func TestEvalResponseHeaders_DispatchesOnlySubscribedPairs(t *testing.T) {
	var invoked []string
	regs := buildRegs(t, []regSpec{{
		name:   "resp",
		phases: bothHeaderPhases,
		subscribes: func(cfg string) filter.Phase {
			if cfg == "want" {
				return filter.PhaseResponseHeaders
			}
			return 0
		},
		make: func(c filter.RuleConfig[string]) filter.Filter {
			cfg := c.Cfg
			return &recordingRespFilter{onResp: func() { invoked = append(invoked, cfg) }}
		},
	}})
	e := NewEngine(regs, 0)
	units := unitsFor([][]string{{"quiet"}, {"want"}})
	if _, err := e.EvalResponseHeaders(context.Background(), &filter.Stream{}, units, ResponseScope{}); err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	if !slices.Equal(invoked, []string{"want"}) {
		t.Fatalf("invoked = %v, want only the subscribing rule", invoked)
	}
}

// Response evaluation is a no-op when no config subscribes.
func TestEvalResponseHeaders_InvokesNobodyWhenNothingSubscribed(t *testing.T) {
	var invoked []string
	regs := buildRegs(t, []regSpec{{
		name:   "resp",
		phases: bothHeaderPhases,
		// Zero demand, not a nil SubscribesOf: Build rejects nil on a filter that
		// declares the phase, and zero is what a request-only config returns.
		subscribes: subscribesTo(0),
		make: func(c filter.RuleConfig[string]) filter.Filter {
			cfg := c.Cfg
			return &recordingRespFilter{onResp: func() { invoked = append(invoked, cfg) }}
		},
	}})
	res, err := NewEngine(regs, 0).EvalResponseHeaders(context.Background(), &filter.Stream{},
		unitsFor([][]string{{"cfg"}}), ResponseScope{})
	if err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	if len(invoked) != 0 {
		t.Fatalf("invoked = %v, want none: no config subscribed", invoked)
	}
	requireDisposition(t, res.Disposition, DispositionPassthrough)
}

type recordingRespFilter struct {
	filter.PassThrough
	onResp func()
}

func (f *recordingRespFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.onResp()
	return filter.Continue(), nil
}

// bypassRespFilter bypasses on request headers and records response dispatch,
// so a test can pin that the bypassing pair itself stays in scope.
type bypassRespFilter struct {
	filter.PassThrough
	onResp func()
}

func (f *bypassRespFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Bypass(), nil
}

func (f *bypassRespFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.onResp()
	return filter.Continue(), nil
}

// A bypass suppresses later response pairs while preserving its own subscription.
func TestEvalResponseHeaders_BypassSuppressesLaterPairs(t *testing.T) {
	var invoked []string
	recordAs := func(name string) filter.Filter {
		return &recordingRespFilter{onResp: func() { invoked = append(invoked, name) }}
	}
	regs := buildRegs(t, []regSpec{
		{
			name:       "gate",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(c filter.RuleConfig[string]) filter.Filter {
				if c.Cfg == "bypass" {
					return &bypassRespFilter{onResp: func() { invoked = append(invoked, "bypass") }}
				}
				return recordAs("gate:" + c.Cfg)
			},
		},
		{
			name:       "resp",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make:       func(c filter.RuleConfig[string]) filter.Filter { return recordAs("resp:" + c.Cfg) },
		},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	// Unit 0 bypasses at registration 0; its own registration 1 and everything
	// in unit 1 lie after the bypass point.
	units := unitsFor([][]string{{"bypass", "same-unit"}, {"later", "later"}})

	res, err := e.EvalRequestHeaders(context.Background(), st, units)
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionBypassed)

	if _, err := e.EvalResponseHeaders(context.Background(), st, units, res.ResponseScope); err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	if !slices.Equal(invoked, []string{"bypass"}) {
		t.Fatalf("invoked = %v, want only the bypassing pair: bypass suppresses what follows, not itself", invoked)
	}
}

// A bypass from the resumed body walk also suppresses later response pairs.
func TestEvalResponseHeaders_BodyPhaseBypassSuppressesLaterPairs(t *testing.T) {
	var invoked []string
	regs := buildRegs(t, []regSpec{
		{
			name: "pauser",
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &bodyFilter{c: &counters{}, bodyAct: filter.Bypass()}
			},
		},
		{
			name:       "resp",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(c filter.RuleConfig[string]) filter.Filter {
				cfg := c.Cfg
				return &recordingRespFilter{onResp: func() { invoked = append(invoked, cfg) }}
			},
		},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	units := unitsFor([][]string{{"pause", "later"}})

	hr, err := e.EvalRequestHeaders(context.Background(), st, units)
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	if !hr.NeedsBody() {
		t.Fatal("expected the walk to pause for the body")
	}
	br, err := e.EvalRequestBody(context.Background(), st, hr, filter.Body{Bytes: []byte("b"), Complete: true})
	if err != nil {
		t.Fatalf("EvalRequestBody: %v", err)
	}
	requireDisposition(t, br.Disposition, DispositionBypassed)

	if _, err := e.EvalResponseHeaders(context.Background(), st, units, br.ResponseScope); err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	if len(invoked) != 0 {
		t.Fatalf("invoked = %v, want none: the body-phase bypass suppressed the later pair", invoked)
	}
}

// The inline body phase must bound the response scope exactly as the resumed
// one does. This is the WithAvailableRequestBody path, where the body action
// runs inside walkRequest instead of through EvalRequestBody — a separate call
// site, and the one that folds through requestWalk.apply rather than the base
// actionWalk.apply.
func TestEvalRequestHeaders_InlineBodyBypassBoundsResponseScope(t *testing.T) {
	var invoked []string
	regs := buildRegs(t, []regSpec{
		{
			name: "pauser",
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &bodyFilter{c: &counters{}, bodyAct: filter.Bypass()}
			},
		},
		{
			name:       "resp",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(c filter.RuleConfig[string]) filter.Filter {
				cfg := c.Cfg
				return &recordingRespFilter{onResp: func() { invoked = append(invoked, cfg) }}
			},
		},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	units := unitsFor([][]string{{"pause", "later"}})

	// No continuation: the body is in hand, so NeedBody is satisfied inline and
	// the Bypass is returned from inside walkRequest.
	hr, err := e.EvalRequestHeaders(context.Background(), st, units,
		WithAvailableRequestBody(filter.Body{Bytes: []byte("b"), Complete: true}))
	if err != nil {
		t.Fatalf("EvalRequestHeaders: %v", err)
	}
	if hr.NeedsBody() {
		t.Fatal("the walk paused despite an available body")
	}
	requireDisposition(t, hr.Disposition, DispositionBypassed)
	if !hr.ResponseScope.bounded {
		t.Fatal("the inline body-phase bypass did not bound the response scope")
	}

	if _, err := e.EvalResponseHeaders(context.Background(), st, units, hr.ResponseScope); err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	if len(invoked) != 0 {
		t.Fatalf("invoked = %v, want none: the inline body-phase bypass suppressed the later pair", invoked)
	}
}

// --- response-phase actions and failure policy -------------------------

type respActFilter struct {
	filter.PassThrough
	act filter.Action
	err error
}

func (f *respActFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return f.act, f.err
}

// Response headers cannot request an undeclared body phase or clear a
// request-side route cache.
func TestEvalResponseHeaders_RejectsUnsupportedActions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		act     filter.Action
		wantMsg string
	}{
		{name: "needbody", act: filter.NeedBody(), wantMsg: "response-body support"},
		{
			name:    "continue carrying clear-route-cache",
			act:     filter.Continue(filter.Mutation{Route: &filter.RouteMutation{ClearCache: true}}),
			wantMsg: "route cache",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			act := tc.act
			regs := buildRegs(t, []regSpec{{
				name:       "resp",
				phases:     bothHeaderPhases,
				subscribes: subscribesTo(filter.PhaseResponseHeaders),
				make: func(filter.RuleConfig[string]) filter.Filter {
					return &respActFilter{act: act}
				},
			}})
			e := NewEngine(regs, 0)
			units := unitsFor([][]string{{"cfg"}})
			res, err := e.EvalResponseHeaders(context.Background(), &filter.Stream{}, units, ResponseScope{})
			if err == nil || !strings.Contains(err.Error(), "resp") {
				t.Fatalf("err = %v, want an error naming the filter", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %q, want it to explain %q", err, tc.wantMsg)
			}
			// A rejected action must not leak a partially folded result.
			if len(res.HeaderOps) != 0 {
				t.Errorf("HeaderOps = %v, want none from a rejected action", res.HeaderOps)
			}
		})
	}
}

func TestEvalResponseHeaders_StopBlocksAndDiscardsPending(t *testing.T) {
	invokedLater := false
	regs := buildRegs(t, []regSpec{
		{
			name:       "mutator",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &respActFilter{act: filter.Continue(filter.SetHeader("x-before", "one"))}
			},
		},
		{
			name:       "blocker",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &respActFilter{act: filter.Stop(filter.Reply{Status: 403, Body: []byte("denied")})}
			},
		},
		{
			name:       "later",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &recordingRespFilter{onResp: func() { invokedLater = true }}
			},
		},
	})
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	res, err := NewEngine(regs, 0).EvalResponseHeaders(context.Background(), st,
		unitsFor([][]string{{"cfg", "cfg", "cfg"}}), ResponseScope{})
	if err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionBlocked)
	if res.Reply.Status != 403 || string(res.Reply.Body) != "denied" {
		t.Errorf("Reply = %+v, want 403 denied", res.Reply)
	}
	if len(res.HeaderOps) != 0 {
		t.Errorf("HeaderOps = %v, want pending mutations discarded", res.HeaderOps)
	}
	if invokedLater {
		t.Fatal("filter after Stop was invoked")
	}
	if got := unitActions(st.Info); !slices.Equal(got, []string{"mutator:mutate", "blocker:block"}) {
		t.Errorf("unit actions = %v", got)
	}
}

func TestEvalResponseHeaders_BypassPreservesPendingAndSkipsLater(t *testing.T) {
	invokedLater := false
	regs := buildRegs(t, []regSpec{
		{
			name:       "mutator",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &respActFilter{act: filter.Continue(filter.SetHeader("x-before", "one"))}
			},
		},
		{
			name:       "bypass",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &respActFilter{act: filter.Bypass()}
			},
		},
		{
			name:       "later",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &recordingRespFilter{onResp: func() { invokedLater = true }}
			},
		},
	})
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	res, err := NewEngine(regs, 0).EvalResponseHeaders(context.Background(), st,
		unitsFor([][]string{{"cfg", "cfg", "cfg"}}), ResponseScope{})
	if err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionBypassed)
	wantOps := []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "x-before", Value: "one"}}
	if !equalOps(res.HeaderOps, wantOps) {
		t.Errorf("HeaderOps = %v, want %v", res.HeaderOps, wantOps)
	}
	if invokedLater {
		t.Fatal("filter after Bypass was invoked")
	}
	if got := unitActions(st.Info); !slices.Equal(got, []string{"mutator:mutate", "bypass:bypass"}) {
		t.Errorf("unit actions = %v", got)
	}
}

func TestEvalResponseHeaders_BodyMutationLastWriterWins(t *testing.T) {
	regs := buildRegs(t, []regSpec{
		{
			name:       "first",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &respActFilter{act: filter.Continue(filter.Mutation{Body: []byte("one")})}
			},
		},
		{
			name:       "second",
			phases:     bothHeaderPhases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return &respActFilter{act: filter.Continue(filter.Mutation{Body: []byte("two")})}
			},
		},
	})
	res, err := NewEngine(regs, 0).EvalResponseHeaders(context.Background(), &filter.Stream{},
		unitsFor([][]string{{"cfg", "cfg"}}), ResponseScope{})
	if err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionMutated)
	if string(res.Body) != "two" {
		t.Errorf("Body = %q, want last writer's replacement", res.Body)
	}
}

// Fail-closed in the response phase synthesises a blocked result with a
// Reply, which the adapter turns into an ImmediateResponse replacing the
// upstream response.
func TestEvalResponseHeaders_FailClosedSynthesisesBlocked(t *testing.T) {
	regs := buildRegs(t, []regSpec{{
		name:       "strict",
		phases:     bothHeaderPhases,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		onError:    filter.Always[string](filter.FailClosed),
		make: func(filter.RuleConfig[string]) filter.Filter {
			return &respActFilter{act: filter.Continue(), err: errors.New("boom")}
		},
	}})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	units := unitsFor([][]string{{"cfg"}})
	res, err := e.EvalResponseHeaders(context.Background(), st, units, ResponseScope{})
	if err != nil {
		t.Fatalf("configured FailClosed returned engine error: %v", err)
	}
	requireDisposition(t, res.Disposition, DispositionBlocked)
	if res.Reply.Status != 500 || res.Reply.Details != "epe_response_headers_failed_closed" {
		t.Errorf("Reply = %+v, want response-headers local 500", res.Reply)
	}
	if len(res.HeaderOps) != 0 {
		t.Errorf("HeaderOps = %+v, want none on a blocked response", res.HeaderOps)
	}
	// The fail-closed error must also reach the audit record; the outcome
	// itself is derived by extproc from the response it sends.
	if st.Info.Error != "boom" {
		t.Errorf("stream error = %q, want the filter's error retained", st.Info.Error)
	}
}

// Fail-open in the response phase must be recorded, symmetrically with the
// request path's resolveFailure, and must not stop the remaining rules.
func TestEvalResponseHeaders_FailOpenIsRecorded(t *testing.T) {
	regs := buildRegs(t, []regSpec{{
		name:       "flaky",
		phases:     bothHeaderPhases,
		subscribes: subscribesTo(filter.PhaseResponseHeaders),
		onError:    filter.Always[string](filter.FailOpen),
		make: func(c filter.RuleConfig[string]) filter.Filter {
			if c.Cfg == "boom" {
				return &respActFilter{act: filter.Continue(), err: errors.New("boom")}
			}
			return respMutFilter{}
		},
	}})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	units := unitsFor([][]string{{"boom"}, {"ok"}})
	res, err := e.EvalResponseHeaders(context.Background(), st, units, ResponseScope{})
	if err != nil {
		t.Fatalf("EvalResponseHeaders: %v", err)
	}
	if len(res.HeaderOps) != 1 {
		t.Errorf("HeaderOps = %+v; fail-open must not stop the later rule", res.HeaderOps)
	}
	acts := unitActions(st.Info)
	if !slices.Contains(acts, "flaky:error-open") {
		t.Errorf("unit actions = %v, want the fail-open skip recorded", acts)
	}
	requireDisposition(t, res.Disposition, DispositionMutated)
}

func TestEval_BypassDoesNotInvokeOrRecordFollowingBlock(t *testing.T) {
	regs, _, _, _, _ := func() ([]filter.Registration, *counters, *counters, *counters, *counters) {
		bypassC, blockC := &counters{}, &counters{}
		regs := buildRegs(t, []regSpec{
			{name: "bypass", make: func(filter.RuleConfig[string]) filter.Filter {
				bypassC.constructed++
				return &actionFilter{act: filter.Bypass(), c: bypassC}
			}},
			{name: "block", make: func(filter.RuleConfig[string]) filter.Filter {
				blockC.constructed++
				return &actionFilter{act: filter.Stop(filter.Reply{Status: 451}), c: blockC}
			}},
		})
		return regs, bypassC, blockC, nil, nil
	}()
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	// unit 0: bypass; unit 1: block (skipped, never evaluated)
	res, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{
		{"y", ""},
		{"", "b"},
	}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if res.Disposition != DispositionBypassed {
		t.Fatalf("Disposition = %v, want Bypassed", res.Disposition)
	}
	var blockSeen, winner bool
	for _, u := range st.Info.Matched {
		for _, a := range u.FilterActions {
			if a.Filter == "block" {
				blockSeen = true
			}
			if a.Filter == "bypass" && a.Kind == filter.ActionBypass {
				winner = true
			}
		}
	}
	if !winner || blockSeen {
		t.Errorf("Matched = %+v; want bypass recorded and following block absent", st.Info.Matched)
	}
}

// Every invocation lands in StreamInfo.Filters — including a fail-open
// error, whose Err must survive the swallow.
func TestEval_FilterRecordsIncludeFailOpenErr(t *testing.T) {
	regs := buildRegs(t, []regSpec{
		{name: "flaky", onError: filter.Always[string](filter.FailOpen), make: func(filter.RuleConfig[string]) filter.Filter {
			return &errFilter{err: errors.New("boom")}
		}},
	})
	e := NewEngine(regs, 0)
	st := &filter.Stream{Info: filter.NewStreamInfo()}
	res, err := e.EvalRequestHeaders(context.Background(), st, unitsFor([][]string{{"f"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if len(st.Info.Filters) != 1 {
		t.Fatalf("Filters = %d records, want 1", len(st.Info.Filters))
	}
	rec := st.Info.Filters[0]
	if rec.Filter != "flaky" || rec.Outcome != "error" || rec.Err == nil {
		t.Errorf("record = %+v; the swallowed error must be visible", rec)
	}
	if res.Disposition != DispositionPassthrough {
		t.Errorf("Disposition = %v; fail-open must not fail the stream", res.Disposition)
	}
}

// A filter that pauses for the request body must surface that need on the
// headers result so the adapter requests the body from Envoy.
func TestEval_PausedFilterNeedsBody(t *testing.T) {
	mk := func(name string) filter.Registration {
		regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
			Name:   name,
			Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
			New: func(filter.RuleConfig[string]) filter.Filter {
				return &bodyFilter{c: &counters{}, bodyAct: filter.Continue()}
			},
		}, func(json.RawMessage) (string, error) { return "", nil }))
		if err != nil {
			t.Fatalf("build %s: %v", name, err)
		}
		return regs[0]
	}
	e := NewEngine([]filter.Registration{mk("complete")}, 0)
	res, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, unitsFor([][]string{{"a"}}))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !res.NeedsBody() {
		t.Fatal("NeedsBody = false, want true after a body pause")
	}
}
