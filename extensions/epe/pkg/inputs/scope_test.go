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
package inputs_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// TestScopeRendersTemplatePaths pins the documented text/template paths against
// the Scope root. Every path resolves through an exported accessor method rather
// than a field (the fields are unexported), which text/template treats
// identically — so this is the test that would catch the accessors being
// renamed, removed, or given pointer receivers.
func TestScopeRendersTemplatePaths(t *testing.T) {
	scope := inputs.NewScope(
		inputs.RequestFrom(httpreq.HTTPRequest{Host: "api.example.com", Port: 443, Path: "/v1", Scheme: "https", Method: "GET", Query: map[string][]string{"q": {"1"}}, Headers: map[string]string{"x-id": "abc"}}),
		inputs.Workload{Name: "p", Namespace: "ns", IP: "10.0.0.1", Labels: map[string]string{"app": "a"}},
		inputs.Profile{Name: "sp", Namespace: "ns"},
		inputs.Rule{Name: "r"},
		map[string]any{"tier": "gold"},
	)

	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{
			name: "host",
			tmpl: "{{ .Request.Host }}",
			want: "api.example.com",
		},
		{
			name: "header lowercase lookup",
			tmpl: `{{ .Request.Header "X-Id" }}`,
			want: "abc",
		},
		{
			name: "query param first value",
			tmpl: `{{ .Request.QueryParam "q" }}`,
			want: "1",
		},
		{
			name: "pod label",
			tmpl: `{{ .Pod.Label "app" }}`,
			want: "a",
		},
		{
			name: "profile name",
			tmpl: "{{ .Profile.Name }}",
			want: "sp",
		},
		{
			name: "rule name",
			tmpl: "{{ .Rule.Name }}",
			want: "r",
		},
		{
			// {{ .Inputs.<key> }} is a documented path for profile-supplied
			// inputs: text/template indexes the returned map[string]any by
			// field-like syntax. Nothing else pins it, and the Inputs accessor
			// is the only thing making it resolve now that `inputs` is
			// unexported.
			name: "inputs key",
			tmpl: "{{ .Inputs.tier }}",
			want: "gold",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tp, err := eval.CompileTemplate("p", tc.tmpl)
			if err != nil {
				t.Fatalf("CompileTemplate(%q): %v", tc.tmpl, err)
			}
			var buf bytes.Buffer
			if err := tp.Execute(&buf, scope); err != nil {
				t.Fatalf("template Execute: %v", err)
			}
			if buf.String() != tc.want {
				t.Errorf("template output: want %q, got %q", tc.want, buf.String())
			}
		})
	}
}

// TestScopeNeverExposesSecrets covers the two halves reachable from outside the
// package: the struct carries no secret field, and no banned name is a declared
// CEL variable so an expression referencing one fails to compile rather than
// resolving.
//
// Neither half says anything about what the projected bag actually holds — a
// future slot named "token" would pass both. That third half needs buildBag and
// therefore lives in package inputs, as TestBuildBagCarriesNoSecretKey. The env
// check is kept anyway because it guards a different failure: a `token` variable
// declared in eval's env would be a compile-time exposure even with an empty
// bag.
func TestScopeNeverExposesSecrets(t *testing.T) {
	// Structural guarantee: Scope has no SandboxToken / RequestBody field.
	st := reflect.TypeOf(inputs.Scope{})
	for i := 0; i < st.NumField(); i++ {
		name := st.Field(i).Name
		if name == "SandboxToken" || name == "RequestBody" {
			t.Errorf("Scope must not carry secret field %q", name)
		}
	}
	// No banned name resolves as a CEL variable.
	for _, banned := range []string{"sandboxToken", "requestBody", "token"} {
		if _, err := eval.CompileBool(banned + ` == ""`); err == nil {
			t.Errorf("%q must not be a declared CEL variable", banned)
		}
	}
}

// evalBoolOnScope compiles and evaluates expr against scope. It is the only
// place in this file that touches the activation's representation, so an
// activation API change lands here and nowhere else.
func evalBoolOnScope(t *testing.T, scope *inputs.Scope, expr string) (bool, error) {
	t.Helper()
	prog, err := eval.CompileBool(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return eval.EvalBool(prog, scope.Activation())
}

func TestDNSCandidatesInScope(t *testing.T) {
	scope := inputs.NewScope(inputs.RequestFrom(httpreq.HTTPRequest{DNSCandidates: []string{"api.example.com"}}), inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil)
	got, err := evalBoolOnScope(t, scope, `"api.example.com" in request.dnsCandidates`)
	if err != nil || !got {
		t.Fatalf("got=%v err=%v", got, err)
	}
	tmpl, err := eval.CompileTemplate("dns", `{{ index .Request.DNSCandidates 0 }}`)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, scope); err != nil || out.String() != "api.example.com" {
		t.Fatalf("output=%q err=%v", out.String(), err)
	}
}

// evalBoolOnAuditScope mirrors evalBoolOnScope for the audit projection. The
// helper of the same name in package audit is unexported and in a different
// package, so the names do not collide.
func evalBoolOnAuditScope(t *testing.T, s *audit.Scope, expr string) (bool, error) {
	t.Helper()
	prog, err := eval.CompileBool(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return eval.EvalBool(prog, s.Activation())
}

// invariantScope is the fixture the invariant tests share: every projected
// field populated, Inputs deliberately nil.
func invariantScope() *inputs.Scope {
	return inputs.NewScope(
		inputs.RequestFrom(httpreq.HTTPRequest{
			Host:    "api.example.com",
			Port:    8080,
			Path:    "/v1/chat",
			Scheme:  "https",
			Method:  "POST",
			Headers: map[string]string{"x-tenant": "a"},
			Query:   map[string][]string{"q": {"first", "second"}, "empty": {}},
		}),
		inputs.Workload{Name: "pn", Namespace: "pns", IP: "1.2.3.4", Labels: map[string]string{"app": "sleep"}},
		inputs.Profile{Name: "sp", Namespace: "spns"},
		inputs.Rule{Name: "r"},
		nil,
	)
}

// TestScopeInvariants pins the observable CEL behaviour of the projected
// scope. Every assertion goes through CEL rather than through the activation's
// keys, so it survives a change of activation representation.
func TestScopeInvariants(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		want    bool
		wantErr string
	}{
		// I1: a profile with no inputs must make has() false, not an error.
		// An erroring audit `when` silently drops the event.
		{name: "I1 has(inputs) absent is false not error", expr: `has(inputs.missing)`, want: false},
		{name: "I1 inputs lookup errors", expr: `inputs.missing == "x"`, wantErr: "no such key"},

		// I3: port must arrive as an integer kind, or integer comparison
		// breaks. The Go width is not pinned here and cannot be: cel-go
		// normalises int, int32 and int64 alike to types.Int, so the width is
		// not observable through CEL. A float64 projection is caught by eval's
		// TestEvalValueResultIsJSONNative, whose `int` case expects int64(443)
		// under reflect.DeepEqual.
		{name: "I3 port is an integer", expr: `request.port == 8080`, want: true},

		// I4: profile and rule are string-valued maps.
		{name: "I4 profile is a string map", expr: `profile.name == "sp" && profile.namespace == "spns"`, want: true},
		{name: "I4 rule is a string map", expr: `rule.name == "r"`, want: true},

		// I5: a missing key errors; has() on it is false.
		{name: "I5 missing header errors", expr: `request.headers["nope"] == "x"`, wantErr: "no such key"},
		{name: "I5 has(missing field) is false", expr: `has(request.nope)`, want: false},
		{name: "I5 present header", expr: `request.headers["x-tenant"] == "a"`, want: true},
		{name: "I5 label lookup", expr: `pod.labels["app"] == "sleep"`, want: true},

		// I6: queryParams takes the first value and skips empty slices.
		{name: "I6 queryParams first value", expr: `request.queryParams["q"] == "first"`, want: true},
		{name: "I6 empty slice skipped", expr: `has(request.queryParams.empty)`, want: false},

		// Scalars.
		{name: "scalars", expr: `request.host == "api.example.com" && request.path == "/v1/chat" && request.method == "POST" && request.scheme == "https" && pod.name == "pn" && pod.namespace == "pns" && pod.ip == "1.2.3.4"`, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evalBoolOnScope(t, invariantScope(), tc.expr)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("%s = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}

// TestScopeHidesAuditResult verifies that `result` is declared in the shared
// environment but only an audit scope provides its value.
//
// The layering arm matters most. Audit exposes `result` by wrapping the base
// activation in a hierarchical child (audit/scope.go), so
// its absence from a plain scope is structural: nothing is written into the
// shared base and therefore nothing has to be deleted from it.
func TestScopeHidesAuditResult(t *testing.T) {
	const expr = `result == "blocked"`
	if _, err := evalBoolOnScope(t, invariantScope(), expr); err == nil || !strings.Contains(err.Error(), "no such attribute") {
		t.Fatalf("err = %v, want a no-such-attribute error", err)
	}

	base := invariantScope()
	as := &audit.Scope{Scope: *base, Result: "blocked"}
	if got, err := evalBoolOnAuditScope(t, as, expr); err != nil || !got {
		t.Fatalf("audit scope must resolve %s: (%v, %v)", expr, got, err)
	}
	// The audit layer must not write the result into the shared base.
	if _, err := evalBoolOnScope(t, base, expr); err == nil || !strings.Contains(err.Error(), "no such attribute") {
		t.Fatalf("audit layering contaminated the shared base: err = %v, want a no-such-attribute error", err)
	}
}

// TestScopeWithInputsErrorPoisonsBothEngines pins the degraded-inputs
// contract: with WithInputsError set, every CEL expression and template that
// touches inputs fails with the recorded reason — including has(inputs.x),
// which would otherwise silently report false — while expressions that never
// read inputs are unaffected.
func TestScopeWithInputsErrorPoisonsBothEngines(t *testing.T) {
	poisoned := inputs.NewScope(
		inputs.RequestFrom(httpreq.HTTPRequest{Host: "api.example.com"}),
		inputs.Workload{Namespace: "ns"},
		inputs.Profile{Name: "sp"},
		inputs.Rule{Name: "r"},
		nil,
		inputs.WithInputsError(`input "routing" from ConfigMap ns/missing: not found`),
	)

	for _, expr := range []string{
		`inputs.routing.target == "x"`,
		`has(inputs.routing)`,
	} {
		if _, err := evalBoolOnScope(t, poisoned, expr); err == nil ||
			!strings.Contains(err.Error(), "inputs unavailable") {
			t.Errorf("CEL %q: err = %v, want inputs-unavailable error", expr, err)
		}
	}

	// Expressions that never read inputs evaluate normally.
	if got, err := evalBoolOnScope(t, poisoned, `request.host == "api.example.com"`); err != nil || !got {
		t.Fatalf("non-inputs CEL must be unaffected: (%v, %v)", got, err)
	}

	// The template accessor errors, aborting execution instead of rendering a
	// zero value under missingkey=zero.
	if _, err := poisoned.Inputs(); err == nil || !strings.Contains(err.Error(), "inputs unavailable") {
		t.Fatalf("Inputs() = %v, want inputs-unavailable error", err)
	}
	tmpl, err := eval.CompileTemplate("t", `{{ .Inputs.routing }}`)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, poisoned); err == nil || !strings.Contains(err.Error(), "inputs unavailable") {
		t.Fatalf("template execute err = %v, want inputs-unavailable error", err)
	}
	// A template that never reads inputs renders normally.
	okTmpl, err := eval.CompileTemplate("t2", `{{ .Request.Host }}`)
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := okTmpl.Execute(&buf, poisoned); err != nil || buf.String() != "api.example.com" {
		t.Fatalf("non-inputs template = (%q, %v), want api.example.com", buf.String(), err)
	}
}
