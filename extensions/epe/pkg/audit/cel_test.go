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
package audit

import (
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// baseScope builds an empty inputs.Scope for the fixtures that need a working
// Activation: audit.Scope embeds it by value, and inputs.Scope must come from
// NewScope for Activation() not to panic. TestEvalWhen_NilProgSkipsActivation
// deliberately uses a literal instead, because the panic is what it detects.
func baseScope() inputs.Scope {
	return *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil)
}

// TestEvalWhen_NilProgSkipsActivation pins what EvalWhen's nil check is for.
// The Scope is deliberately a literal rather than a NewScope result, so its
// memoisation cache is nil and Activation panics: this passes only if the nil
// program returns before the activation is touched. Asserting the `true` alone
// would prove nothing — eval.EvalBool returns true for a nil program too, so
// the assertion would survive deleting the check this test exists to protect.
func TestEvalWhen_NilProgSkipsActivation(t *testing.T) {
	got, err := EvalWhen(nil, &Scope{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("an entry with no when should fire")
	}
}

func TestEvalWhen_TrueExpression(t *testing.T) {
	prog, err := eval.CompileBool(`result == "blocked"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := &Scope{Scope: baseScope(), Result: "blocked"}
	got, err := EvalWhen(prog, s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected true for matching result")
	}
}

func TestEvalWhen_FalseExpression(t *testing.T) {
	prog, err := eval.CompileBool(`result == "blocked"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := &Scope{Scope: baseScope(), Result: "passthrough"}
	got, err := EvalWhen(prog, s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected false for non-matching result")
	}
}

func TestEvalWhen_RequestFieldAccess(t *testing.T) {
	tests := []struct {
		name  string
		expr  string
		scope Scope
		want  bool
	}{
		{
			name:  "request method matches",
			expr:  `request.method == "POST"`,
			scope: Scope{Scope: *inputs.NewScope(inputs.RequestFrom(httpreq.HTTPRequest{Method: "POST"}), inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil)},
			want:  true,
		},
		{
			name:  "request host matches",
			expr:  `request.host == "example.com"`,
			scope: Scope{Scope: *inputs.NewScope(inputs.RequestFrom(httpreq.HTTPRequest{Host: "example.com"}), inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil)},
			want:  true,
		},
		{
			name:  "request port matches",
			expr:  `request.port == 443`,
			scope: Scope{Scope: *inputs.NewScope(inputs.RequestFrom(httpreq.HTTPRequest{Port: 443}), inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil)},
			want:  true,
		},
		{
			name:  "pod namespace matches",
			expr:  `pod.namespace == "production"`,
			scope: Scope{Scope: *inputs.NewScope(inputs.Request{}, inputs.Workload{Namespace: "production"}, inputs.Profile{}, inputs.Rule{}, nil)},
			want:  true,
		},
		{
			name:  "profile name matches",
			expr:  `profile.name == "strict"`,
			scope: Scope{Scope: *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{Name: "strict"}, inputs.Rule{}, nil)},
			want:  true,
		},
		{
			name:  "rule name matches",
			expr:  `rule.name == "deny-admin"`,
			scope: Scope{Scope: *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{}, inputs.Rule{Name: "deny-admin"}, nil)},
			want:  true,
		},
		{
			name: "complex expression with headers",
			expr: `result == "blocked" && request.headers["x-priority"] == "high"`,
			scope: Scope{
				Scope:  *inputs.NewScope(inputs.RequestFrom(httpreq.HTTPRequest{Headers: map[string]string{"x-priority": "high"}}), inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil),
				Result: "blocked",
			},
			want: true,
		},
		{
			name:  "complex expression with labels",
			expr:  `pod.labels["team"] == "fraud"`,
			scope: Scope{Scope: *inputs.NewScope(inputs.Request{}, inputs.Workload{Labels: map[string]string{"team": "fraud"}}, inputs.Profile{}, inputs.Rule{}, nil)},
			want:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := eval.CompileBool(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := EvalWhen(prog, &tc.scope)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if got != tc.want {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestEvalWhen_QueryParams(t *testing.T) {
	prog, err := eval.CompileBool(`request.queryParams["tag"] == "urgent"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := &Scope{
		Scope: *inputs.NewScope(inputs.RequestFrom(httpreq.HTTPRequest{Query: map[string][]string{"tag": {"urgent", "extra"}}}), inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil),
	}
	got, err := EvalWhen(prog, s)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !got {
		t.Error("expected true when query param matches")
	}
}

func TestEvalWhen_ProfileInputs(t *testing.T) {
	prog, err := eval.CompileBool(`inputs["routing"]["tenant-a"] == "provider-a"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := &Scope{Scope: *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{}, inputs.Rule{},
		map[string]any{"routing": map[string]string{"tenant-a": "provider-a"}},
	)}
	got, err := EvalWhen(prog, s)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !got {
		t.Fatal("expected profile input to be visible to audit CEL")
	}
}
