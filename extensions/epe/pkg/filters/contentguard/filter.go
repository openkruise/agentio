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
// Package contentguard captures bounded content views without changing traffic.
package contentguard

import (
	"context"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// FilterName is the registry name used for attribution.
const FilterName = "contentguard"

// Definition accepts incremental or complete input; the engine chooses delivery.
func Definition() filter.Definition {
	return filter.Define(filter.Descriptor[config]{
		Name: FilterName,
		Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody |
			filter.PhaseResponseHeaders | filter.PhaseResponseBody,
		SubscribesOf: func(cfg config) filter.Phase {
			if cfg.response != nil {
				return filter.PhaseResponseHeaders
			}
			return 0
		},
		New: func(rule filter.RuleConfig[config]) filter.Filter { return &guard{rule: rule} },
	}, parse)
}

type guard struct {
	filter.PassThrough
	rule    filter.RuleConfig[config]
	capture *capture
}

func (g *guard) OnRequestHeaders(_ context.Context, st *filter.Stream) (filter.Action, error) {
	g.capture = newCapture(g.rule.Cfg.request, st.Request.Headers)
	return filter.NeedBody(filter.IncrementalBody), nil
}

func (g *guard) OnResponseHeaders(_ context.Context, st *filter.Stream) (filter.Action, error) {
	if g.rule.Cfg.response == nil {
		return filter.Continue(), nil
	}
	g.capture = newCapture(*g.rule.Cfg.response, st.Response.Headers)
	return filter.NeedBody(filter.IncrementalBody), nil
}

func (g *guard) OnRequestBody(_ context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	g.capture.observe(body.Bytes, body.Complete, g.rule.Scope)
	st.Info.RecordContent(g.rule.ID, g.capture.record)
	return filter.Continue(), nil
}

func (g *guard) OnResponseBody(_ context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	if g.rule.Cfg.response != nil {
		g.capture.observe(body.Bytes, body.Complete, g.rule.Scope)
		st.Info.RecordResponseContent(g.rule.ID, g.capture.record)
	}
	return filter.Continue(), nil
}
