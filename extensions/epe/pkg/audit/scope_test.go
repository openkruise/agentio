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
	"bytes"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// TestAuditScopeActivationShadowsResult is the shadow guard: audit.Scope
// MUST override the embedded inputs.Scope.Activation so the audit-only
// `result` variable is exposed to CEL, and the base variables must survive the
// layering rather than being replaced by it.
//
// Asserted through CEL rather than through act.ResolveName so it pins what
// expressions observe, not how the bag is represented. Presence is expressed as
// has() on a field of the slot: a slot that failed to resolve makes has() error,
// which is exactly the production symptom (an erroring audit `when` silently
// drops the event).
func TestAuditScopeActivationShadowsResult(t *testing.T) {
	s := &Scope{
		Scope:  *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil),
		Result: "blocked",
	}
	tests := []struct {
		name string
		expr string
	}{
		// The audit-only variable the shadowing exists to add.
		{name: "result present and carries the value", expr: `result == "blocked"`},
		// The base variables the layering must not shadow away. has() on a
		// known field resolves the slot without depending on its contents.
		{name: "request survives layering", expr: `has(request.host)`},
		{name: "pod survives layering", expr: `has(pod.name)`},
		{name: "profile survives layering", expr: `has(profile.name)`},
		{name: "rule survives layering", expr: `has(rule.name)`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evalBoolOnAuditScope(t, s, tc.expr)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.expr, err)
			}
			if !got {
				t.Errorf("%s = false, want true", tc.expr)
			}
		})
	}

	// Deliberately not covered here: that the child wins a name collision with
	// the base. No collision is reachable through Activation — the base's keys
	// come from inputs.buildBag, which this package cannot influence — so a test
	// would have to build its own NewHierarchicalActivation call, which asserts
	// cel-go's documented semantics rather than this code's use of them and
	// keeps passing when Activation's own arguments are swapped. The ordering
	// constraint is recorded at the call site instead.

	// `matched` is deliberately not a CEL variable: the when-env declares only
	// result/request/pod/profile/rule, so an expression referencing it
	// fails to compile. That is a stronger guarantee than the old
	// ResolveName("matched") check, which only proved the bag lacked the key --
	// this proves no profile can even reference it. Match reaches templates via
	// the MatchedCriteria accessor instead.
	if _, err := eval.CompileBool(`matched.host == "x"`); err == nil {
		t.Error("`matched` must not be a declared CEL variable")
	}
}

// populatedAuditScope is the fixture with every projected field populated. It is
// shared by the shape test and the template-render test so both describe the
// same scope.
func populatedAuditScope() *Scope {
	return &Scope{
		Scope: *inputs.NewScope(
			inputs.RequestFrom(httpreq.HTTPRequest{Host: "example.com", Port: 443, Path: "/api/v1/data", Scheme: "https", Method: "POST", Query: map[string][]string{"tag": {"urgent"}}, Headers: map[string]string{"x-request-id": "abc"}}),
			inputs.Workload{
				Name:      "agent-1",
				Namespace: "default",
				IP:        "10.0.0.5",
				Labels:    map[string]string{"app": "ai"},
			},
			inputs.Profile{Name: "p1", Namespace: "ns"},
			inputs.Rule{Name: "r1"},
			nil,
		),
		Result: "blocked",
	}
}

// TestScopeActivation_AllFieldsPopulated proves the audit activation exposes
// every projected field with the value and type an expression needs.
//
// Every assertion goes through CEL rather than through act.ResolveName plus a
// concrete type assertion, so a change to the bag's representation — the slot
// container types, the map key types — does not break it, while a change to what
// expressions can observe does. That is deliberate about the port arm too: see
// the comment on it for what it does and does not pin.
func TestScopeActivation_AllFieldsPopulated(t *testing.T) {
	s := populatedAuditScope()
	tests := []struct {
		name string
		expr string
	}{
		{name: "result", expr: `result == "blocked"`},

		{
			name: "request scalars",
			expr: `request.host == "example.com" && request.path == "/api/v1/data" && request.method == "POST" && request.scheme == "https"`,
		},
		// This pins that `port` is projected as an integer kind at all: a
		// string or an absent projection fails it. It does not pin the Go
		// width — cel-go normalises every Go integer kind to types.Int, so
		// int, int32 and int64 are indistinguishable through CEL. A float64
		// projection is caught, but by eval's TestEvalValueResultIsJSONNative
		// (its `int` case expects int64(443) under reflect.DeepEqual), not here.
		{name: "request port is an integer", expr: `request.port == 443`},
		{name: "request headers", expr: `request.headers["x-request-id"] == "abc"`},
		{name: "request queryParams", expr: `request.queryParams["tag"] == "urgent"`},

		{name: "pod scalars", expr: `pod.name == "agent-1" && pod.namespace == "default" && pod.ip == "10.0.0.5"`},
		{name: "pod labels", expr: `pod.labels["app"] == "ai"`},

		{name: "profile", expr: `profile.name == "p1" && profile.namespace == "ns"`},
		{name: "rule", expr: `rule.name == "r1"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evalBoolOnAuditScope(t, s, tc.expr)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.expr, err)
			}
			if !got {
				t.Errorf("%s = false, want true", tc.expr)
			}
		})
	}
}

// TestAuditScopeRendersTemplatePaths pins that the documented template paths
// resolve against an audit.Scope root, through the embedded inputs.Scope's
// promoted accessor methods.
//
// The value-root arm is the point. inputs.Scope's accessors take value
// receivers, so they promote through the embedded value on both a *Scope and a
// Scope value. Switching them to pointer receivers would keep the *Scope arm
// green and break only the value root — and it would break at render time,
// where text/template reports a missing field by failing the execute, so the
// symptom is a webhook body that silently stops carrying its request context.
func TestAuditScopeRendersTemplatePaths(t *testing.T) {
	const tmpl = `{{ .Request.Host }}|{{ .Request.Header "X-Request-Id" }}|{{ .Pod.Label "app" }}|{{ .Profile.Name }}|{{ .Rule.Name }}|{{ .Result }}`
	const want = `example.com|abc|ai|p1|r1|blocked`

	tp, err := eval.CompileTemplate("audit-scope", tmpl)
	if err != nil {
		t.Fatalf("CompileTemplate: %v", err)
	}

	ptr := populatedAuditScope()
	roots := []struct {
		name string
		root any
	}{
		{name: "pointer root", root: ptr},
		// The uncovered case: audit renderers receive whatever the caller
		// passes, and a Scope value is a legitimate root.
		{name: "value root", root: *ptr},
	}
	for _, r := range roots {
		t.Run(r.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tp.Execute(&buf, r.root); err != nil {
				t.Fatalf("template Execute on %s: %v", r.name, err)
			}
			if buf.String() != want {
				t.Errorf("render on %s: want %q, got %q", r.name, want, buf.String())
			}
		})
	}
}

// TestScopeMatchedCriteriaRendersTemplatePaths verifies the compatibility
// accessor through the same template renderer used by webhooks.
func TestScopeMatchedCriteriaRendersTemplatePaths(t *testing.T) {
	tmpl, err := eval.CompileTemplate(
		"matched-criteria",
		`{{ .MatchedCriteria.Host }}|{{ .MatchedCriteria.Method }}|{{ .MatchedCriteria.Path }}|{{ .MatchedCriteria.Port }}|{{ index .MatchedCriteria.Headers "x-user" }}|{{ index .MatchedCriteria.QueryParams "q" }}`,
	)
	if err != nil {
		t.Fatalf("CompileTemplate: %v", err)
	}
	s := &Scope{Matched: Match{
		Host:        "example.com",
		Method:      "GET",
		Path:        "/v1/items",
		Port:        443,
		Headers:     map[string]string{"x-user": "alice"},
		QueryParams: map[string]string{"q": "agent"},
	}}

	got, err := eval.RenderToString(tmpl, s)
	if err != nil {
		t.Fatalf("RenderToString: %v", err)
	}
	const want = "example.com|GET|/v1/items|443|alice|agent"
	if got != want {
		t.Errorf("rendered template = %q, want %q", got, want)
	}
}

// evalBoolOnAuditScope is the audit-side counterpart of the inputs-side helper:
// the only place in this file that knows the activation's shape.
func evalBoolOnAuditScope(t *testing.T, s *Scope, expr string) (bool, error) {
	t.Helper()
	prog, err := eval.CompileBool(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return eval.EvalBool(prog, s.Activation())
}

// TestAuditScopeResolvesResult verifies that the audit-only result variable is
// layered over the base request scope.
func TestAuditScopeResolvesResult(t *testing.T) {
	s := &Scope{
		Scope: *inputs.NewScope(
			inputs.RequestFrom(httpreq.HTTPRequest{Host: "h", Port: 443, Path: "/", Scheme: "https", Method: "GET"}),
			inputs.Workload{Namespace: "ns"},
			inputs.Profile{}, inputs.Rule{}, nil,
		),
		Result: "blocked",
	}
	tests := []struct {
		name string
		expr string
	}{
		{name: "result resolves", expr: `result == "blocked"`},
		{name: "base variables still resolve", expr: `request.host == "h" && pod.namespace == "ns"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evalBoolOnAuditScope(t, s, tc.expr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got {
				t.Errorf("%s = false, want true", tc.expr)
			}
		})
	}
}
