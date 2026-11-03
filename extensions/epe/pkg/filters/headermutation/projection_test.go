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
package headermutation_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// Projects request header mutations through filter construction and engine
// evaluation without importing a policy API.
func TestProjectedPayloadRunsThroughEngine(t *testing.T) {
	regs, err := filter.Build(headermutation.Definition())
	if err != nil {
		t.Fatalf("build registration: %v", err)
	}
	cfgs, errs := filter.Project(regs, map[string]json.RawMessage{
		headermutation.FilterName: json.RawMessage(`{
			"request": {
				"set":[{"name":"X-Policy","value":"{{ .Profile.Name }}"}],
				"add":[{"name":"X-Tag","value":"{{ index .Inputs \"tag\" }}"}],
				"remove":["X-Legacy"]
			}
		}`),
	})
	if errs[0] != nil {
		t.Fatalf("project payload: %v", errs[0])
	}
	scope := inputs.NewScope(
		inputs.Request{}, inputs.Workload{}, inputs.Profile{Name: "outbound"}, inputs.Rule{Name: "mutate"},
		map[string]any{"tag": "trusted"},
	)
	units := []engine.Unit{{ID: filter.UnitID{Scope: "default/profile", Name: "mutate"}, Scope: scope, Cfgs: cfgs}}
	e := engine.NewEngine(regs, 0)
	res, err := e.EvalRequestHeaders(
		context.Background(),
		&filter.Stream{StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()}},
		units,
	)
	if err != nil {
		t.Fatalf("evaluate request headers: %v", err)
	}
	want := []filter.HeaderOp{
		{Kind: filter.HeaderSet, Name: "x-policy", Value: "outbound"},
		{Kind: filter.HeaderAdd, Name: "x-tag", Value: "trusted"},
		{Kind: filter.HeaderRemove, Name: "x-legacy"},
	}
	if !reflect.DeepEqual(res.HeaderOps, want) {
		t.Errorf("HeaderOps = %+v, want %+v", res.HeaderOps, want)
	}
	if res.Disposition != engine.DispositionMutated {
		t.Errorf("Disposition = %v, want mutated", res.Disposition)
	}
	// Request-only payloads do not subscribe to response headers.
	subscriptions, err := e.ValidateSubscriptions(units)
	if err != nil {
		t.Fatalf("ValidateSubscriptions: %v", err)
	}
	if subscriptions&filter.PhaseResponseHeaders != 0 {
		t.Error("a request-only payload opened the response-headers phase")
	}
}

// Response payloads subscribe to response headers.
func TestProjectedResponsePayloadDeclaresDemand(t *testing.T) {
	regs, err := filter.Build(headermutation.Definition())
	if err != nil {
		t.Fatalf("build registration: %v", err)
	}
	for _, tc := range []struct {
		name      string
		payload   string
		ruleWants bool
		wantOps   []filter.HeaderOp
	}{
		{
			name:      "response only",
			payload:   `{"response":{"add":[{"name":"X-Epe","value":"{{ .Rule.Name }}"}],"remove":["Server"]}}`,
			ruleWants: true,
		},
		{
			name:      "request with empty response object",
			payload:   `{"request":{"set":[{"name":"X-Policy","value":"{{ .Profile.Name }}"}]},"response":{}}`,
			ruleWants: false,
			wantOps:   []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "x-policy", Value: "outbound"}},
		},
		{
			name:      "both phases",
			payload:   `{"request":{"set":[{"name":"X-Policy","value":"{{ .Profile.Name }}"}]},"response":{"remove":["Server"]}}`,
			ruleWants: true,
			wantOps:   []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "x-policy", Value: "outbound"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgs, errs := filter.Project(regs, map[string]json.RawMessage{
				headermutation.FilterName: json.RawMessage(tc.payload),
			})
			if errs[0] != nil {
				t.Fatalf("project payload: %v", errs[0])
			}
			scope := inputs.NewScope(
				inputs.Request{}, inputs.Workload{},
				inputs.Profile{Name: "outbound"}, inputs.Rule{Name: "mutate"}, nil,
			)
			id := filter.UnitID{Scope: "default/profile", Name: "mutate"}
			res, err := engine.NewEngine(regs, 0).EvalRequestHeaders(
				context.Background(),
				&filter.Stream{StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()}},
				[]engine.Unit{{ID: id, Scope: scope, Cfgs: cfgs}},
			)
			if err != nil {
				t.Fatalf("evaluate request headers: %v", err)
			}
			// Response demand comes from the compiled config.
			subscriptions, subErr := engine.NewEngine(regs, 0).ValidateSubscriptions(
				[]engine.Unit{{ID: id, Scope: scope, Cfgs: cfgs}},
			)
			if subErr != nil {
				t.Fatalf("ValidateSubscriptions: %v", subErr)
			}
			gotWants := subscriptions&filter.PhaseResponseHeaders != 0
			if gotWants != tc.ruleWants {
				t.Errorf("subscribed = %v, want %v", gotWants, tc.ruleWants)
			}
			if len(tc.wantOps) == 0 && len(res.HeaderOps) != 0 {
				t.Errorf("HeaderOps = %+v, want none", res.HeaderOps)
			}
			if len(tc.wantOps) > 0 && !reflect.DeepEqual(res.HeaderOps, tc.wantOps) {
				t.Errorf("HeaderOps = %+v, want %+v", res.HeaderOps, tc.wantOps)
			}
		})
	}
}
