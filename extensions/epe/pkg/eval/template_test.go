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
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

func TestCompileTemplateAndRender(t *testing.T) {
	tokenValueTemplate := `{{- $json := fromJson .Token -}}Bearer {{ if kindIs "map" $json }}{{ first (values $json) }}{{ else }}{{ .Token }}{{ end }}`
	tests := []struct {
		name        string
		raw         string
		data        any
		want        string
		expectError string // compile error substring
	}{
		{"literal", "sk-abc123", nil, "sk-abc123", ""},
		{"pod field", "{{ .Pod.Namespace }}", struct{ Pod inputs.Pod }{inputs.Pod{Namespace: "ns"}}, "ns", ""},
		{
			"label helper",
			"{{ .Pod.Label \"app\" }}",
			struct{ Pod inputs.Pod }{inputs.Pod{Labels: map[string]string{"app": "x"}}},
			"x",
			"",
		},
		{
			"missingkey zero",
			"{{ .Pod.Labels.absent }}",
			struct{ Pod inputs.Pod }{inputs.Pod{Labels: map[string]string{}}},
			"",
			"",
		},
		{"default helper", "{{ default \"fb\" .V }}", struct{ V string }{""}, "fb", ""},
		{"json helper", "{{ json .V }}", struct{ V []string }{[]string{"a"}}, `["a"]`, ""},
		{
			"fromJson map helper",
			"{{ range fromJson .V }}{{ . }}{{ end }}",
			struct{ V string }{`{"key":"value"}`},
			"value",
			"",
		},
		{"kindIs helper", `{{ kindIs "map" (fromJson .V) }}`, struct{ V string }{`{"key":"value"}`}, "true", ""},
		{"trim helper", `{{ trim .V }}`, struct{ V string }{"  value\n"}, "value", ""},
		{"hasPrefix helper", `{{ hasPrefix "Bearer " .V }}`, struct{ V string }{"Bearer value"}, "true", ""},
		{
			"values and first helpers",
			`{{ first (values (fromJson .V)) }}`,
			struct{ V string }{`{"only":"value"}`},
			"value",
			"",
		},
		{
			"token template with raw value",
			tokenValueTemplate,
			struct{ Token string }{"raw-token"},
			"Bearer raw-token",
			"",
		},
		{
			"token template with JSON value",
			tokenValueTemplate,
			struct{ Token string }{`{"arbitrary-key":"json-token"}`},
			"Bearer json-token",
			"",
		},
		{"syntax error", "{{ .Token", nil, "", "unclosed action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, err := CompileTemplate("t", tt.raw)
			if tt.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectError) {
					t.Fatalf("expected error containing %q, got %v", tt.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected compile error: %v", err)
			}
			got, err := RenderToString(tmpl, tt.data)
			if err != nil {
				t.Fatalf("unexpected render error: %v", err)
			}
			if got != tt.want {
				t.Errorf("render = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestProbeRenderNeutralizesDataDependentHelpers pins the compile-time probe's
// contract: a template whose helpers only fail because the probe has no request
// must not read as an authoring error. Rejecting one rejects the whole profile
// version, so a false positive here unenforces every rule beside it.
func TestProbeRenderNeutralizesDataDependentHelpers(t *testing.T) {
	// A guard that calls fail when the request does not carry a bearer token.
	guard, err := CompileTemplate("guard",
		`{{ if not (hasPrefix "Bearer " .Token) }}{{ fail "not a bearer token" }}{{ end }}{{ .Token }}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeRender(guard, struct{ Token string }{}); err != nil {
		t.Fatalf("ProbeRender(guarded fail) = %v, want no error", err)
	}
	// The guard still fires at request time, where the data is real.
	if _, err := RenderToString(guard, struct{ Token string }{"opaque"}); err == nil ||
		!strings.Contains(err.Error(), "not a bearer token") {
		t.Fatalf("RenderToString(guarded fail) = %v, want the fail message", err)
	}
	if got, err := RenderToString(guard, struct{ Token string }{"Bearer t"}); err != nil || got != "Bearer t" {
		t.Fatalf("RenderToString(satisfied guard) = (%q, %v), want Bearer t", got, err)
	}

	// fromJson yields nil for the probe's empty string, and first panics on a
	// nil list — a panic text/template turns into a render error whose text
	// names a nil pointer dereference rather than anything an author can act
	// on.
	chain, err := CompileTemplate("chain", `{{ first (fromJson .Token) }}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeRender(chain, struct{ Token string }{}); err != nil {
		t.Fatalf("ProbeRender(json chain) = %v, want no error", err)
	}
	if got, err := RenderToString(chain, struct{ Token string }{`["a","b"]`}); err != nil || got != "a" {
		t.Fatalf("RenderToString(json chain) = (%q, %v), want a", got, err)
	}

	// A missing map key yields an untyped nil, which every string-typed helper
	// rejects — so the documented default+index+fromJson idiom needs the
	// string-typed stubs, not just the fromJson one.
	claim, err := CompileTemplate("claim", `{{ default "anon" (index (fromJson .Token) "sub") }}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeRender(claim, struct{ Token string }{}); err != nil {
		t.Fatalf("ProbeRender(default over missing key) = %v, want no error", err)
	}
	if got, err := RenderToString(claim, struct{ Token string }{`{"sub":"u-1"}`}); err != nil || got != "u-1" {
		t.Fatalf("RenderToString(claim) = (%q, %v), want u-1", got, err)
	}

	// What the probe is for: a field the render scope does not have.
	missing, err := CompileTemplate("missing", `{{ .Nope }}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeRender(missing, struct{ Token string }{}); err == nil {
		t.Fatal("ProbeRender(unknown field) = nil, want an error")
	}
}

func TestTemplateFailHelperReturnsRenderError(t *testing.T) {
	tmpl, err := CompileTemplate("t", `{{ fail "stop rendering" }}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = RenderToString(tmpl, nil)
	if err == nil || !strings.Contains(err.Error(), "stop rendering") {
		t.Fatalf("RenderToString() error = %v, want stop rendering", err)
	}
}
