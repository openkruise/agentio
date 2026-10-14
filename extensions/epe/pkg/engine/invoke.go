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
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// invoke is the single place every filter call goes through: timing, then
// outcome accounting. It returns the filter's action and error unchanged;
// failure-policy translation happens in the engine, and the evaluation
// budget is installed once per phase by the Eval* entry points.
// m carries the filter name, phase label, and the Prometheus children, all
// resolved once at Engine construction.
func (e *Engine) invoke(
	ctx context.Context,
	st *filter.Stream,
	m *filterMetrics,
	call func(context.Context) (filter.Action, error),
) (filter.Action, error) {
	act, rec := invokeMeasured(ctx, m, call)
	if st != nil {
		st.Info.RecordFilter(rec)
	}
	return act, rec.Err
}

// invokeMeasured also serves incremental callbacks, whose audit records are
// aggregated per consumer rather than retained once per chunk.
func invokeMeasured(
	ctx context.Context,
	m *filterMetrics,
	call func(context.Context) (filter.Action, error),
) (filter.Action, filter.FilterRecord) {
	start := time.Now()
	act, err := call(ctx)
	elapsed := time.Since(start)
	oc := classifyOutcome(act, err)
	m.observe(elapsed, oc)
	return act, filter.FilterRecord{
		Filter:   m.filter,
		Phase:    m.phase,
		Outcome:  oc.String(),
		Duration: elapsed,
		Err:      err,
	}
}

// classifyOutcome maps a filter's return to its low-cardinality outcome.
func classifyOutcome(act filter.Action, err error) outcome {
	if err != nil {
		return outcomeError
	}
	switch act.Kind() {
	case filter.KindStop, filter.KindBypass:
		return outcomeImmediate
	case filter.KindNeedBody:
		return outcomeNeedBody
	default:
		if len(act.Mutations()) > 0 {
			return outcomeMutate
		}
		return outcomeContinue
	}
}
