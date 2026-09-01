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
package eval

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"

	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

// layerAuditOnly layers audit-only variables over a scope activation as a
// hierarchical child, exactly the way audit.Scope.Activation does. eval
// cannot import audit (audit imports eval), so the tests rebuild the two-line
// layering themselves.
func layerAuditOnly(tb testing.TB, base cel.Activation, vars map[string]any) cel.Activation {
	tb.Helper()
	top, err := cel.NewActivation(vars)
	if err != nil {
		// Unreachable: NewActivation rejects only nil and non-map bindings.
		tb.Fatalf("audit-only layer: %v", err)
	}
	return interpreter.NewHierarchicalActivation(base, top)
}

func TestCompileBool(t *testing.T) {
	tests := []struct {
		name        string
		expr        string
		wantNil     bool
		expectError string
	}{
		{"empty", "", true, ""},
		{"valid bool", `pod.namespace == "ns"`, false, ""},
		{"non-bool", `pod.namespace`, false, "must return bool"},
		{"syntax error", `pod.`, false, "compile when"},
		{"unsupported response", `response.status == 503`, false, "undeclared reference to 'response'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog, err := CompileBool(tt.expr)
			if tt.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectError) {
					t.Fatalf("expected error containing %q, got %v", tt.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil != (prog == nil) {
				t.Errorf("prog nil = %v, want %v", prog == nil, tt.wantNil)
			}
		})
	}
}

func TestCompileValueRejectsAuditOnlyVariables(t *testing.T) {
	_, err := CompileValue(`result`)
	if err == nil || !strings.Contains(err.Error(), "undeclared reference to 'result'") {
		t.Fatalf("CompileValue(result) error = %v, want undeclared-reference error", err)
	}
}

func TestNewRequestEnvHeaderSelector(t *testing.T) {
	env, err := NewRequestEnv()
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile(`request.headers.filter(name, name.startsWith("x-"))`)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile selector: %v", issues.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	act, _ := cel.NewActivation(map[string]any{
		"request": map[string]any{"headers": map[string]string{
			"authorization": "client",
			"x-first":       "one",
			"x-second":      "two",
		}},
		"pod": map[string]any{}, "profile": map[string]string{},
		"rule": map[string]string{}, "inputs": map[string]any{},
	})
	got, err := EvalValue(prog, act)
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := got.([]any)
	if !ok {
		t.Fatalf("selector result = %T, want []any", got)
	}
	gotKeys := make([]string, 0, len(keys))
	for _, key := range keys {
		gotKeys = append(gotKeys, key.(string))
	}
	sort.Strings(gotKeys)
	if want := []string{"x-first", "x-second"}; !reflect.DeepEqual(gotKeys, want) {
		t.Fatalf("selector keys = %v, want %v", gotKeys, want)
	}
}

func TestNewRequestEnvConsumerVariables(t *testing.T) {
	env, err := NewRequestEnv(
		cel.Variable("token", cel.StringType),
		cel.Variable("header", cel.MapType(cel.StringType, cel.StringType)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile(`token + ":" + header.name`)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile consumer expression: %v", issues.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	act, _ := cel.NewActivation(map[string]any{
		"token": "client", "header": map[string]string{"name": "authorization"},
	})
	got, err := EvalValue(prog, act)
	if err != nil || got != "client:authorization" {
		t.Fatalf("consumer expression = %v (%v), want client:authorization", got, err)
	}
	if _, err := CompileValue("token"); err == nil || !strings.Contains(err.Error(), "undeclared reference to 'token'") {
		t.Fatalf("CompileValue(token) error = %v, want undeclared-reference error", err)
	}
}

func TestRestrictedRequestEnv(t *testing.T) {
	withConsumer, err := NewRestrictedRequestEnv(cel.Variable("consumer", cel.StringType))
	if err != nil {
		t.Fatal(err)
	}
	if _, issues := withConsumer.Compile(`consumer == "token" && request.method == "POST"`); issues != nil && issues.Err() != nil {
		t.Fatalf("compile common and consumer variables: %v", issues.Err())
	}
	if _, issues := withConsumer.Compile(`lists.range(10)`); issues == nil || issues.Err() == nil {
		t.Fatal("lists.range compiled in restricted request environment")
	}

	withoutConsumer, err := NewRestrictedRequestEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, issues := withoutConsumer.Compile(`consumer`); issues == nil || issues.Err() == nil {
		t.Fatal("consumer declaration leaked into a separate restricted environment")
	}
}

func TestEvalBool(t *testing.T) {
	if ok, err := EvalBool(nil, nil); err != nil || !ok {
		t.Fatalf("nil program should return true, got (%v, %v)", ok, err)
	}
	// `result` is deliberately not in an inputs.Scope activation — audit.Scope
	// layers it as a hierarchical child (audit/scope.go), which this package
	// cannot import. layerAuditOnly rebuilds that layering so the expression
	// exercises both halves of the real audit shape.
	prog, err := CompileBool(`pod.labels["app"] == "sleep" && result == "blocked"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	act := layerAuditOnly(t,
		inputs.NewScope(
			inputs.RequestFrom(httpreq.HTTPRequest{Host: "h", Port: 80, Path: "/", Scheme: "http", Method: "GET"}),
			inputs.Pod{Namespace: "ns", Labels: map[string]string{"app": "sleep"}},
			inputs.Profile{Name: "p"}, inputs.Rule{Name: "r"}, nil).Activation(),
		map[string]any{"result": "blocked"})
	ok, err := EvalBool(prog, act)
	if err != nil || !ok {
		t.Fatalf("expected true, got (%v, %v)", ok, err)
	}
}

// valueActivation builds an activation whose every projected slot carries tag,
// so a value that still points at the scope's own storage is identifiable by
// the tag it carries.
func valueActivation(tag string, in map[string]any) cel.Activation {
	return inputs.NewScope(
		inputs.RequestFrom(httpreq.HTTPRequest{
			Host: "api.example.com", Port: 443, Path: "/v1", Scheme: "https", Method: "POST",
			Headers: map[string]string{"x-tenant": tag},
			Query:   map[string][]string{"q": {tag}},
		}),
		inputs.Pod{Name: "pod-" + tag, Namespace: "ns", IP: "10.0.0.1", Labels: map[string]string{"tenant": tag}},
		inputs.Profile{Name: tag, Namespace: "ns"},
		inputs.Rule{Name: "rule-" + tag},
		in,
	).Activation()
}

func mustCompileValue(t *testing.T, expr string) cel.Program {
	t.Helper()
	prog, err := CompileValue(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return prog
}

// TestEvalValueResultIsJSONNative pins the contract the only caller depends
// on: renderParams marshals the result, so every container EvalValue returns
// must be a JSON-native shape. cel-go's ConvertToNative(any) yields
// map[any]any for a map result, which json.Marshal rejects outright.
func TestEvalValueResultIsJSONNative(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want any
	}{
		{"string", `pod.namespace`, "ns"},
		{"int", `request.port`, int64(443)},
		{"bool", `request.path.startsWith("/v1")`, true},
		{"double", `1.5`, 1.5},
		{"list", `[request.host, request.path]`, []any{"api.example.com", "/v1"}},
		{"string-keyed map slot", `request.headers`, map[string]any{"x-tenant": "a"}},
		{"pod labels", `pod.labels`, map[string]any{"tenant": "a"}},
		{"whole string map slot", `profile`, map[string]any{"name": "a", "namespace": "ns"}},
		{"map literal", `{"tenant": pod.labels["tenant"]}`, map[string]any{"tenant": "a"}},
		{"map nested in list", `[request.headers]`, []any{map[string]any{"x-tenant": "a"}}},
		{"map nested in map", `pod`, map[string]any{
			"name": "pod-a", "namespace": "ns", "ip": "10.0.0.1",
			"labels": map[string]any{"tenant": "a"},
		}},
		{"non-string map key", `{1: "one"}`, map[string]any{"1": "one"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act := valueActivation("a", nil)
			got, err := EvalValue(mustCompileValue(t, tt.expr), act)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EvalValue = %#v, want %#v", got, tt.want)
			}
			if _, err := json.Marshal(got); err != nil {
				t.Errorf("result is not JSON-marshalable: %v", err)
			}
		})
	}
}

// TestEvalValueResultIsOwned pins the one aliasing hazard that survives the
// pool's removal: a container reached through the caller-supplied `inputs` map
// is handed back by reference, and that map's owner is free to mutate it after
// EvalValue returned.
func TestEvalValueResultIsOwned(t *testing.T) {
	// A []any reachable through `inputs` is handed back by reference by
	// cel-go's assignability shortcut, so this aliases regardless of how
	// maps happen to convert in the current cel-go release.
	t.Run("value reached through inputs", func(t *testing.T) {
		src := []any{"one", map[string]any{"k": "v"}}
		act := valueActivation("a", map[string]any{"list": src})
		got, err := EvalValue(mustCompileValue(t, `inputs["list"]`), act)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		before := fmt.Sprint(got)
		src[0] = "mutated"
		src[1].(map[string]any)["k"] = "mutated"
		if after := fmt.Sprint(got); after != before {
			t.Errorf("result tracks the source container: before=%s after=%s", before, after)
		}
	})
}
