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
	"strconv"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// The benchmarks here measure the dispatch framework itself, not filter
// logic: every stub returns immediately, so what is left on the clock is
// what the engine spends per unit and per registration.
//
// Two costs are deliberately left inside the measurement because production
// pays them on the same path: the Prometheus observations in invoke, and the
// StreamInfo records the engine writes. BenchmarkEvalRequestHeaders_Info
// prices the second one by comparison rather than by removing it.

// benchSink defeats dead-code elimination for benchmarks whose result is
// otherwise unused.
var benchSink any

// --- benchmark filters -------------------------------------------------
//
// These carry no bookkeeping, unlike the test filters in eval_test.go: a
// benchmark of the dispatch path must not also measure a stub's counters.

// benchNoop continues without mutating. The embedded PassThrough already
// returns Continue() on every phase, so no override is needed.
type benchNoop struct{ filter.PassThrough }

// benchMutate emits one header op, so fold has real work to fold.
type benchMutate struct {
	filter.PassThrough
	mut filter.Mutation
}

func (f *benchMutate) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(f.mut), nil
}

// benchStop always blocks.
type benchStop struct{ filter.PassThrough }

func (benchStop) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Stop(filter.Reply{Status: 403}), nil
}

type benchResponseMutate struct {
	filter.PassThrough
	mut filter.Mutation
}

func (f *benchResponseMutate) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(f.mut), nil
}

type benchResponseStop struct{ filter.PassThrough }

func (benchResponseStop) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Stop(filter.Reply{Status: 403}), nil
}

// benchNeedBody defers to the body phase and continues once it arrives.
type benchNeedBody struct{ filter.PassThrough }

func (benchNeedBody) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func (benchNeedBody) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Continue(), nil
}

type benchResponseNeedBody struct{ filter.PassThrough }

func (benchResponseNeedBody) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func (benchResponseNeedBody) OnResponseBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Continue(), nil
}

// --- chain shapes ------------------------------------------------------

// benchShape names the disposition the chain is rigged to produce. Each one
// walks a different amount of the engine:
//
//   - passthrough: no mutations, so fold folds an empty list — the cost floor.
//   - mutated: every filter emits a distinct header and fold does real work.
//   - blocked: the first action blocks, measuring the short-circuit floor.
//   - needbody: the first body-needing action pauses and resumes the cursor.
type benchShape string

const (
	shapePassthrough benchShape = "passthrough"
	shapeMutated     benchShape = "mutated"
	shapeBlocked     benchShape = "blocked"
	shapeNeedBody    benchShape = "needbody"
)

// benchChain builds nFilters registrations, preceded by a blocking action for
// the blocked shape.
func benchChain(b testing.TB, shape benchShape, nFilters int) []filter.Registration {
	b.Helper()
	specs := make([]regSpec, 0, nFilters+1)
	switch shape {
	case shapeBlocked:
		specs = append(specs, regSpec{
			name: "block",
			make: func(filter.RuleConfig[string]) filter.Filter { return benchStop{} },
		})
	}
	for i := 0; i < nFilters; i++ {
		spec := regSpec{name: "f" + strconv.Itoa(i)}
		switch shape {
		case shapeMutated:
			mut := filter.SetHeader("x-bench-"+strconv.Itoa(i), "v")
			spec.make = func(filter.RuleConfig[string]) filter.Filter {
				return &benchMutate{mut: mut}
			}
		case shapeNeedBody:
			spec.make = func(filter.RuleConfig[string]) filter.Filter { return benchNeedBody{} }
		default:
			spec.make = func(filter.RuleConfig[string]) filter.Filter { return benchNoop{} }
		}
		specs = append(specs, spec)
	}
	return buildRegs(b, specs)
}

func benchResponseChain(b testing.TB, shape benchShape, nFilters int) []filter.Registration {
	b.Helper()
	specs := make([]regSpec, 0, nFilters+1)
	if shape == shapeBlocked {
		specs = append(specs, regSpec{
			name:       "block",
			phases:     filter.PhaseResponseHeaders,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
			make: func(filter.RuleConfig[string]) filter.Filter {
				return benchResponseStop{}
			},
		})
	}
	for i := 0; i < nFilters; i++ {
		phases := filter.PhaseResponseHeaders
		if shape == shapeNeedBody {
			phases |= filter.PhaseResponseBody
		}
		spec := regSpec{
			name:       "f" + strconv.Itoa(i),
			phases:     phases,
			subscribes: subscribesTo(filter.PhaseResponseHeaders),
		}
		switch shape {
		case shapeMutated:
			mut := filter.SetHeader("x-bench-"+strconv.Itoa(i), "v")
			spec.make = func(filter.RuleConfig[string]) filter.Filter {
				return &benchResponseMutate{mut: mut}
			}
		case shapeNeedBody:
			spec.make = func(filter.RuleConfig[string]) filter.Filter { return benchResponseNeedBody{} }
		default:
			spec.make = func(filter.RuleConfig[string]) filter.Filter { return benchNoop{} }
		}
		specs = append(specs, spec)
	}
	return buildRegs(b, specs)
}

// benchUnits builds nUnits units that each carry a config for every
// registration — the shape that maximizes dispatch work, since no unit is
// skipped for any filter.
func benchUnits(nUnits, nRegs int) []Unit {
	rows := make([][]string, nUnits)
	for i := range rows {
		row := make([]string, nRegs)
		for j := range row {
			row[j] = "cfg"
		}
		rows[i] = row
	}
	return unitsFor(rows)
}

// benchAxes are the (units, filters) points every shape is measured at. The
// 1x1 point is the floor; 16x8 exposes any cost that grows with the product
// rather than the sum.
var benchAxes = []struct{ units, filters int }{
	{1, 1},
	{1, 8},
	{4, 4},
	{16, 8},
}

// --- headers phase -----------------------------------------------------

func BenchmarkEvalRequestHeaders(b *testing.B) {
	for _, shape := range []benchShape{
		shapePassthrough, shapeMutated, shapeBlocked, shapeNeedBody,
	} {
		for _, a := range benchAxes {
			regs := benchChain(b, shape, a.filters)
			units := benchUnits(a.units, len(regs))
			name := "units=" + strconv.Itoa(a.units) +
				"/filters=" + strconv.Itoa(a.filters) +
				"/" + string(shape)
			b.Run(name, func(b *testing.B) {
				e := NewEngine(regs, 0)
				ctx := context.Background()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// A fresh StreamInfo per iteration is mandatory, not
					// hygiene: RecordUnitAction appends to Matched and scans
					// it linearly, so a reused Info would grow without bound
					// and report a quadratic cost the engine does not have.
					st := &filter.Stream{Info: filter.NewStreamInfo()}
					res, err := e.EvalRequestHeaders(ctx, st, units)
					if err != nil {
						b.Fatal(err)
					}
					benchSink = res
				}
			})
		}
	}
}

func BenchmarkEvalResponseHeaders(b *testing.B) {
	for _, shape := range []benchShape{shapePassthrough, shapeMutated, shapeBlocked} {
		for _, a := range benchAxes {
			regs := benchResponseChain(b, shape, a.filters)
			units := benchUnits(a.units, len(regs))
			name := "units=" + strconv.Itoa(a.units) +
				"/filters=" + strconv.Itoa(a.filters) +
				"/" + string(shape)
			b.Run(name, func(b *testing.B) {
				e := NewEngine(regs, 0)
				ctx := context.Background()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					st := &filter.Stream{Info: filter.NewStreamInfo()}
					res, err := e.EvalResponseHeaders(ctx, st, units, ResponseScope{})
					if err != nil {
						b.Fatal(err)
					}
					benchSink = res
				}
			})
		}
	}
}

// BenchmarkStreamSetup prices the per-iteration harness the benchmarks above
// allocate, so it can be subtracted rather than mistaken for engine cost.
func BenchmarkStreamSetup(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = &filter.Stream{Info: filter.NewStreamInfo()}
	}
}

// BenchmarkEvalRequestHeaders_Budget isolates the per-phase
// context.WithTimeout the budget installs. The chain is identical in both
// arms, so the delta is one timer plus cancelCtx per evaluation phase.
func BenchmarkEvalRequestHeaders_Budget(b *testing.B) {
	regs := benchChain(b, shapePassthrough, 8)
	units := benchUnits(4, len(regs))
	for _, bc := range []struct {
		name   string
		budget time.Duration
	}{
		{"budget=off", 0},
		// Far above anything a no-op stub can hit, so no arm ever cancels.
		{"budget=on", time.Minute},
	} {
		b.Run(bc.name, func(b *testing.B) {
			e := NewEngine(regs, bc.budget)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				st := &filter.Stream{Info: filter.NewStreamInfo()}
				res, err := e.EvalRequestHeaders(ctx, st, units)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = res
			}
		})
	}
}

// BenchmarkEvalRequestHeaders_Info prices the observability tax. The engine
// skips record and promote entirely when Info is nil, so the delta between
// the arms is the FilterRecord appends plus the per-unit action strings.
// The mutated shape invokes and records every (rule, action) pair, making it
// the recording-heaviest path.
// Production always attaches an Info; info=nil is a measurement probe, not
// a configuration.
func BenchmarkEvalRequestHeaders_Info(b *testing.B) {
	regs := benchChain(b, shapeMutated, 8)
	units := benchUnits(16, len(regs))
	for _, withInfo := range []bool{false, true} {
		name := "info=nil"
		if withInfo {
			name = "info=attached"
		}
		b.Run(name, func(b *testing.B) {
			e := NewEngine(regs, 0)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				st := &filter.Stream{}
				if withInfo {
					st.Info = filter.NewStreamInfo()
				}
				res, err := e.EvalRequestHeaders(ctx, st, units)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = res
			}
		})
	}
}

// --- body phase --------------------------------------------------------

// BenchmarkEvalRequestBody measures body continuation. The prior headers
// result is computed once and reused so headers work stays off the clock.
func BenchmarkEvalRequestBody(b *testing.B) {
	for _, a := range benchAxes {
		regs := benchChain(b, shapeNeedBody, a.filters)
		units := benchUnits(a.units, len(regs))
		name := "units=" + strconv.Itoa(a.units) + "/filters=" + strconv.Itoa(a.filters)
		b.Run(name, func(b *testing.B) {
			e := NewEngine(regs, 0)
			ctx := context.Background()
			prior, err := e.EvalRequestHeaders(ctx, &filter.Stream{Info: filter.NewStreamInfo()}, units)
			if err != nil {
				b.Fatal(err)
			}
			body := filter.Body{Bytes: []byte(`{"jsonrpc":"2.0","method":"tools/call"}`), Complete: true}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				st := &filter.Stream{Info: filter.NewStreamInfo()}
				res, err := e.EvalRequestBody(ctx, st, prior, body)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = res
			}
		})
	}
}

// BenchmarkEvalResponseBody measures the symmetric response continuation. The
// response-headers result is prepared outside the timed loop.
func BenchmarkEvalResponseBody(b *testing.B) {
	for _, a := range benchAxes {
		regs := benchResponseChain(b, shapeNeedBody, a.filters)
		units := benchUnits(a.units, len(regs))
		name := "units=" + strconv.Itoa(a.units) + "/filters=" + strconv.Itoa(a.filters)
		b.Run(name, func(b *testing.B) {
			e := NewEngine(regs, 0)
			ctx := context.Background()
			prior, err := e.EvalResponseHeaders(ctx, &filter.Stream{Info: filter.NewStreamInfo()}, units, ResponseScope{})
			if err != nil {
				b.Fatal(err)
			}
			body := filter.Body{Bytes: []byte(`{"result":{"content":"ok"}}`), Complete: true}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				st := &filter.Stream{Info: filter.NewStreamInfo()}
				res, err := e.EvalResponseBody(ctx, st, prior, body)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = res
			}
		})
	}
}

// --- fold --------------------------------------------------------------

// BenchmarkFold covers the mutation net-effect fold. The empty case is not
// a degenerate input: EvalRequestHeaders calls fold unconditionally, so every
// passthrough request in production walks it with nothing to fold.
func BenchmarkFold(b *testing.B) {
	distinct := make([]filter.Mutation, 8)
	for i := range distinct {
		distinct[i] = filter.SetHeader("x-bench-"+strconv.Itoa(i), "v")
	}

	sameKey := make([]filter.Mutation, 8)
	for i := range sameKey {
		// Alternating append and remove on one key is the case that cannot
		// collapse to a single op, so the keyState bookkeeping is exercised.
		if i%2 == 0 {
			sameKey[i] = filter.AddHeader("x-bench", strconv.Itoa(i))
		} else {
			sameKey[i] = filter.RemoveHeader("x-bench")
		}
	}

	// upperDistinct pairs with distinct: same key count and shape, differing
	// only in case. Envoy lowercases inbound header names, but a filter is
	// free to emit "X-Foo", and fold lowercases every key it sees — so this
	// arm isolates whether that costs an allocation per op.
	upperDistinct := make([]filter.Mutation, 8)
	for i := range upperDistinct {
		upperDistinct[i] = filter.SetHeader("X-Bench-"+strconv.Itoa(i), "v")
	}

	mixedCase := make([]filter.Mutation, 8)
	for i := range mixedCase {
		// Eight ops over four keys, so the fold collapses them and the
		// per-key bookkeeping is reused rather than allocated fresh.
		mixedCase[i] = filter.SetHeader("X-Bench-"+strconv.Itoa(i%4), "v")
	}

	for _, bc := range []struct {
		name string
		muts []filter.Mutation
	}{
		{"empty", nil},
		{"1op", distinct[:1]},
		{"8ops-distinct", distinct},
		{"8ops-distinct-uppercase", upperDistinct},
		{"8ops-samekey", sameKey},
		{"8ops-mixedcase", mixedCase},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSink = fold(bc.muts)
			}
		})
	}
}
