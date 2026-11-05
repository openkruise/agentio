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

package enginetest

import (
	"context"
	"encoding/json"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// BodyGate returns a Definition for a fake filter that suspends at request
// headers, forcing a buffered headers/body exchange in a scenario. The unit's
// bool config is the deny switch: true stops the body phase with 403, false
// lets the body through, and a nil config skips the gate entirely.
func BodyGate() filter.Definition {
	return filter.Define(filter.Descriptor[bool]{
		Name:   "bodycheck",
		Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		New:    func(cfg filter.RuleConfig[bool]) filter.Filter { return &bodyGate{deny: cfg.Cfg} },
	}, func(json.RawMessage) (bool, error) { return false, nil })
}

type bodyGate struct {
	filter.PassThrough
	deny bool
}

func (*bodyGate) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(), nil
}

func (g *bodyGate) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	if g.deny {
		return filter.Stop(filter.Reply{Status: 403}), nil
	}
	return filter.Continue(), nil
}
