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
package securityprofile

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/filters/headermutation"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

const validInlineAnnotation = `[{"name":"trace","match":[{"domains":["api.example.com"]}],` +
	`"actions":{"headerManipulation":{"set":[{"name":"X-E2E-Trace","value":"abc"}]}}}]`

func sandboxWithRules(name, ns, raw string) *v1alpha1.Sandbox {
	return &v1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       ns,
			ResourceVersion: "7",
			Annotations:     map[string]string{AnnotationSecurityRules: raw},
		},
	}
}

// The inline entry must compile into an identity-keyed profile with no label
// selector: these rules are looked up by verified pod identity only.
func TestNewInlineProfile(t *testing.T) {
	p, err := NewInlineProfile(sandboxWithRules("sbx-1", "sandboxes", validInlineAnnotation))
	if err != nil {
		t.Fatalf("NewInlineProfile: %v", err)
	}
	if p == nil {
		t.Fatal("expected a profile")
	}
	if p.Meta.Name != "sbx-1" || p.Meta.Namespace != "sandboxes" || p.Meta.Version != "7" {
		t.Errorf("meta = %+v, want sbx-1/sandboxes rv 7", p.Meta)
	}
	if p.Selector.Empty() || p.Selector.Matches(labels.Set{"app": "x"}) {
		t.Errorf("selector = %v, want labels.Nothing(): inline rules must never match by labels", p.Selector)
	}
	if len(p.Rules) != 1 || p.Rules[0].Name != "trace" {
		t.Fatalf("rules = %+v, want one rule named trace", p.Rules)
	}
	if p.Rules[0].Actions.HeaderManipulation == nil {
		t.Fatal("rule lost its headerManipulation action")
	}
}

// A Sandbox without the annotation carries no inline rules.
func TestNewInlineProfileNoAnnotation(t *testing.T) {
	p, err := NewInlineProfile(&v1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{Name: "sbx", Namespace: "ns"}})
	if err != nil {
		t.Fatalf("NewInlineProfile: %v", err)
	}
	if p != nil {
		t.Fatalf("profile = %+v, want nil for a Sandbox without the annotation", p)
	}
}

// The annotation is a server artifact: anything the reader does not
// understand must fail closed instead of degrading into dropped rules.
func TestNewInlineProfileRejections(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"invalid json", `{`, "decode"},
		{"empty array", `[]`, "contains no rules"},
		{"unknown field", `[{"name":"r","priority":3,"match":[{"domains":["a.example.com"]}],"actions":{"block":{}}}]`, "decode"},
		{"bypass", `[{"name":"r","match":[{"domains":["a.example.com"]}],"actions":{"bypass":true,"block":{}}}]`, "bypass is not allowed"},
		{"tokenTransformation", `[{"name":"r","match":[{"domains":["a.example.com"]}],"actions":{"tokenTransformation":{}}}]`, "tokenTransformation is not supported"},
		{"mcpToolPolicy", `[{"name":"r","match":[{"domains":["a.example.com"]}],"actions":{"mcpToolPolicy":{"defaultAction":"deny"}}}]`, "mcpToolPolicy is not supported"},
		{"audit", `[{"name":"r","match":[{"domains":["a.example.com"]}],"actions":{"block":{},"audit":[{"name":"log"}]}}]`, "audit is not supported"},
		{"no action", `[{"name":"r","match":[{"domains":["a.example.com"]}],"actions":{}}]`, "at least one of block or headerManipulation"},
		{"bad regex", `[{"name":"r","match":[{"domains":["a.example.com"],"paths":[{"type":"Regex","value":"["}]}],"actions":{"block":{}}}]`, "regex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewInlineProfile(sandboxWithRules("sbx", "ns", tt.raw))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// payloadsFor must project headerManipulation into the headermutation
// filter's phase-based schema: both CRD lists land on the request phase.
func TestPayloadsForHeaderManipulation(t *testing.T) {
	rule := &Rule{Actions: v1alpha1.SecurityRuleActions{
		HeaderManipulation: &v1alpha1.HeaderManipulationAction{
			Set:    []v1alpha1.HeaderValue{{Name: "X-E2E-Trace", Value: "abc"}},
			Remove: []string{"X-Carried"},
		},
	}}
	m, err := payloadsFor(rule)
	if err != nil {
		t.Fatalf("payloadsFor: %v", err)
	}
	raw, ok := m[headermutation.FilterName]
	if !ok {
		t.Fatalf("payloads = %v, want key %q", m, headermutation.FilterName)
	}
	var spec struct {
		Request struct {
			Set    []struct{ Name, Value string } `json:"set"`
			Remove []string                       `json:"remove"`
		} `json:"request"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("payload does not parse: %v", err)
	}
	if len(spec.Request.Set) != 1 || spec.Request.Set[0].Name != "X-E2E-Trace" || spec.Request.Set[0].Value != "abc" {
		t.Errorf("request.set = %+v, want X-E2E-Trace=abc", spec.Request.Set)
	}
	if len(spec.Request.Remove) != 1 || spec.Request.Remove[0] != "X-Carried" {
		t.Errorf("request.remove = %+v, want X-Carried", spec.Request.Remove)
	}
	if len(spec.Response) > 0 && string(spec.Response) != "null" && string(spec.Response) != "{}" {
		t.Errorf("response = %s, want empty", spec.Response)
	}
}

// inlineStore satisfies Matcher the way the profilestore does: selector
// profiles first, then the pod's own inline profile.
type inlineStore struct {
	selector []*Profile
	inline   []*Profile
}

func (s inlineStore) Matches(podName, _ string, _ map[string]string) []*Profile {
	matched := append([]*Profile(nil), s.selector...)
	if podName != "" {
		matched = append(matched, s.inline...)
	}
	return matched
}

// The projected payload must parse in the real headermutation filter: this
// pins the projection to the merged filter's phase-based schema instead of a
// hand-rolled test double, proving inline rules bind through the same Engine
// registration the data plane runs.
func TestInlineHeaderManipulationBindsThroughRealFilter(t *testing.T) {
	regs, err := filter.Build(headermutation.Definition())
	if err != nil {
		t.Fatalf("build headermutation: %v", err)
	}
	inline, err := NewInlineProfile(sandboxWithRules("sbx-1", "ns",
		`[{"name":"trace","match":[{"domains":["*"]}],"actions":{"headerManipulation":`+
			`{"set":[{"name":"X-E2E-Trace","value":"abc"}],"remove":["X-Carried"]}}}]`))
	if err != nil {
		t.Fatalf("NewInlineProfile: %v", err)
	}
	b := newBinder(regs)
	units, err := b.bind([]*Profile{inline}, testRequest("example.com"), inputs.Pod{Name: "sbx-1", Namespace: "ns"})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("units = %d, want 1", len(units))
	}
	cfg, ok := units[0].Cfgs[0].(headermutation.Config)
	if !ok {
		t.Fatalf("cfg = %T, want headermutation.Config", units[0].Cfgs[0])
	}
	if len(cfg.Request.Set) != 1 || cfg.Request.Set[0].Name != "x-e2e-trace" {
		t.Errorf("request.set = %+v, want one op for x-e2e-trace", cfg.Request.Set)
	}
	if len(cfg.Request.Remove) != 1 || cfg.Request.Remove[0] != "x-carried" {
		t.Errorf("request.remove = %+v, want x-carried", cfg.Request.Remove)
	}
}

// Inline header values are plaintext by the E2B contract; a value that looks
// like a Go template must reach the wire verbatim instead of being rendered
// against the filter's scope.
func TestInlineHeaderValuesStayLiteral(t *testing.T) {
	const literal = `{{ .pod.name }}-suffix`
	inline, err := NewInlineProfile(sandboxWithRules("sbx-1", "ns",
		`[{"name":"trace","match":[{"domains":["*"]}],"actions":{"headerManipulation":`+
			`{"set":[{"name":"X-A","value":"`+literal+`"}]}}}]`))
	if err != nil {
		t.Fatalf("NewInlineProfile: %v", err)
	}
	escaped := inline.Rules[0].Actions.HeaderManipulation.Set[0].Value
	tmpl, err := eval.CompileTemplate("test", escaped)
	if err != nil {
		t.Fatalf("compile escaped value: %v", err)
	}
	scope := inputs.NewScope(inputs.Request{}, inputs.Pod{Name: "sbx-1"}, inputs.Profile{}, inputs.Rule{}, nil)
	got, err := eval.RenderToString(tmpl, scope)
	if err != nil {
		t.Fatalf("render escaped value: %v", err)
	}
	if got != literal {
		t.Errorf("rendered = %q, want the untouched literal %q", got, literal)
	}
}

// Selector profiles must evaluate before inline rules: the administrator
// baseline wins the chain, and tenant rules run only after it. The ordering
// itself is the store's contract; this test pins that the resolver binds
// units in the order the matcher returns profiles.
func TestResolverInlineProfilesEvaluateAfterSelectorProfiles(t *testing.T) {
	regs := claimAll(t, nil)

	selectorProfile := compile(t, "baseline", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("admin-rule")})
	inlineProfile, err := NewInlineProfile(sandboxWithRules("sbx-1", "ns",
		`[{"name":"tenant-rule","match":[{"domains":["*"]}],"actions":{"block":{"body":"inline"}}}]`))
	if err != nil {
		t.Fatalf("NewInlineProfile: %v", err)
	}

	store := inlineStore{selector: []*Profile{selectorProfile}, inline: []*Profile{inlineProfile}}
	resolve := NewResolver(store, regs, nil)
	res, err := resolve(context.Background(), inputs.Pod{Name: "sbx-1", Namespace: "ns"}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Units) != 2 {
		t.Fatalf("units = %d, want 2 (one selector rule, one inline rule)", len(res.Units))
	}
	if res.Units[0].ID.Name != "admin-rule" || res.Units[0].ID.Scope != "ns/baseline" {
		t.Errorf("first unit = %+v, want the selector profile's rule first", res.Units[0].ID)
	}
	if res.Units[1].ID.Name != "tenant-rule" || res.Units[1].ID.Scope != "ns/sbx-1" {
		t.Errorf("second unit = %+v, want the inline profile's rule second", res.Units[1].ID)
	}
}

// A matcher that returns no inline profile leaves the resolver behavior
// exactly as before.
func TestResolverWithoutInlineProfilesIsUnchanged(t *testing.T) {
	regs := claimAll(t, nil)
	p := compile(t, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	resolve := NewResolver(benchStore{profiles: []*Profile{p}}, regs, nil)
	res, err := resolve(context.Background(), inputs.Pod{Name: "sbx-1", Namespace: "ns"}, testRequest("example.com"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Units) != 1 {
		t.Fatalf("units = %d, want 1", len(res.Units))
	}
}
