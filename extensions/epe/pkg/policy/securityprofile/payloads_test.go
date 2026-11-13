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
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/mcpacl"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/oauth2"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// registeredNames spells out the registration set wiring.BuildFilters
// produces as a name list: importing wiring here would be an import
// cycle, but every payload key must stay a subset of that set, or
// filter.Project would route a document no filter can parse.
var registeredNames = map[string]bool{
	bypass.FilterName:         true,
	mcpacl.FilterName:         true,
	block.FilterName:          true,
	tokentransform.FilterName: true,
	oauth2.FilterName:         true,
}

func payloadsOrFail(t *testing.T, rule *Rule) map[string]json.RawMessage {
	t.Helper()
	m, err := payloadsFor(rule)
	if err != nil {
		t.Fatalf("payloadsFor: %v", err)
	}
	for name := range m {
		if !registeredNames[name] {
			t.Errorf("payload key %q is not a registered filter name", name)
		}
	}
	return m
}

// The deprecated credentialRef spelling must not survive into the payload:
// the tokentransform filter's schema accepts only the typed union, so a
// document still carrying kind/name/namespace would fail to parse (or
// worse, parse to no credential source at all).
func TestPayloadsForNormalizesDeprecatedCredentialRef(t *testing.T) {
	m := payloadsOrFail(t, &Rule{
		Name: "r",
		Actions: v1alpha1.SecurityRuleActions{
			TokenTransformation: &v1alpha1.TokenTransformationAction{
				CredentialRef: v1alpha1.CredentialRef{
					Kind:      v1alpha1.CredentialRefKindSecret,
					Name:      "legacy",
					Namespace: "tenant-a",
				},
			},
		},
	})
	var doc struct {
		CredentialRef struct {
			Secret *struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"secret"`
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"credentialRef"`
		Disabled *bool `json:"disabled"`
	}
	if err := json.Unmarshal(m[tokentransform.FilterName], &doc); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if doc.CredentialRef.Secret == nil {
		t.Fatalf("payload = %s, want a typed secret ref", m[tokentransform.FilterName])
	}
	if doc.CredentialRef.Secret.Name != "legacy" || doc.CredentialRef.Secret.Namespace != "tenant-a" {
		t.Errorf("secret ref = %+v, want legacy/tenant-a", *doc.CredentialRef.Secret)
	}
	if doc.CredentialRef.Kind != "" || doc.CredentialRef.Name != "" {
		t.Errorf("payload = %s, want the deprecated fields gone", m[tokentransform.FilterName])
	}
	// disabled is absorbed by the key's presence, so it must never appear.
	if doc.Disabled != nil {
		t.Errorf("payload = %s, want no disabled field", m[tokentransform.FilterName])
	}
}

// A credentialRef we cannot normalize is a rule we cannot enforce: the
// error must reach the binder's fail-closed path rather than yielding a
// payload-free (and therefore silently unenforced) rule.
func TestPayloadsForRejectsMalformedCredentialRef(t *testing.T) {
	_, err := payloadsFor(&Rule{
		Name: "r",
		Actions: v1alpha1.SecurityRuleActions{
			TokenTransformation: &v1alpha1.TokenTransformationAction{
				CredentialRef: v1alpha1.CredentialRef{Kind: "Unknown", Name: "ref"},
			},
		},
	})
	if err == nil {
		t.Fatal("payloadsFor accepted an unsupported credentialRef kind")
	}
}

func TestPayloadsForRuleWithoutActions(t *testing.T) {
	m := payloadsOrFail(t, &Rule{Name: "r"})
	if len(m) != 0 {
		t.Errorf("payloads = %v, want an empty map", m)
	}
}

// Each action yields exactly its own key: a rule mounting one filter must
// not produce payloads for its siblings.
func TestPayloadsForEachActionYieldsItsOwnKey(t *testing.T) {
	token := &v1alpha1.TokenTransformationAction{
		CredentialRef: v1alpha1.CredentialRef{Kind: v1alpha1.CredentialRefKindSecret, Name: "s"},
	}
	for _, tc := range []struct {
		name    string
		actions v1alpha1.SecurityRuleActions
		wantKey string
	}{
		{"block", v1alpha1.SecurityRuleActions{Block: &v1alpha1.BlockAction{StatusCode: 403}}, block.FilterName},
		{"bypass", v1alpha1.SecurityRuleActions{Bypass: true}, bypass.FilterName},
		{"mcpToolPolicy", v1alpha1.SecurityRuleActions{MCPToolPolicy: &v1alpha1.MCPToolPolicySpec{DefaultAction: "deny"}}, mcpacl.FilterName},
		{"tokenTransformation", v1alpha1.SecurityRuleActions{TokenTransformation: token}, tokentransform.FilterName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := payloadsOrFail(t, &Rule{Name: "r", Actions: tc.actions})
			if !reflect.DeepEqual([]string(keys(m)), []string{tc.wantKey}) {
				t.Errorf("keys = %v, want exactly [%s]", keys(m), tc.wantKey)
			}
		})
	}
}

func TestPayloadsForBypassEmitsEmptyDocument(t *testing.T) {
	m := payloadsOrFail(t, &Rule{
		Name:    "r",
		Actions: v1alpha1.SecurityRuleActions{Bypass: true},
	})
	if got := string(m[bypass.FilterName]); got != `{}` {
		t.Errorf("bypass payload = %s, want {}", got)
	}
}

// Disabled is expressed by omitting the key, so a disabled action mounts
// nothing.
func TestPayloadsForDisabledTokenTransformationYieldsNoKey(t *testing.T) {
	m := payloadsOrFail(t, &Rule{
		Name: "r",
		Actions: v1alpha1.SecurityRuleActions{
			TokenTransformation: &v1alpha1.TokenTransformationAction{Disabled: true},
		},
	})
	if len(m) != 0 {
		t.Errorf("payloads = %v, want no key for a disabled action", m)
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestProjectRecordsFailuresPerRule pins what lets an inline per-Sandbox
// profile survive one bad action. Project returns the first failure for the
// CRD compiler to reject a version with, but it records failures per rule, so
// a caller that keeps the profile — the inline collection, which has no
// last-known-good to fall back to — keeps every other rule enforceable.
func TestProjectRecordsFailuresPerRule(t *testing.T) {
	boom := errors.New("malformed")
	regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
		Name:   block.FilterName,
		Phases: filter.PhaseRequestHeaders,
		New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
	}, func(raw json.RawMessage) (string, error) {
		var payload struct {
			Body string `json:"body"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return "", err
		}
		if payload.Body == "bad" {
			return "", boom
		}
		return payload.Body, nil
	}))
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	sp := compile(t, nil, "p", "ns", "1", []v1alpha1.SecurityRule{
		matchAllRule("good"), matchAllRule("bad"), matchAllRule("also-good"),
	})
	if err := sp.Project(regs); !errors.Is(err, boom) {
		t.Fatalf("Project() = %v, want the wrapped parse error", err)
	}
	if len(sp.Projections) != len(sp.Rules) {
		t.Fatalf("Projections = %d, want one per rule (%d)", len(sp.Projections), len(sp.Rules))
	}
	for i, want := range []bool{false, true, false} {
		got := sp.Projections[i].Errs[0] != nil
		if got != want {
			t.Errorf("rule %q recorded error = %v, want %v", sp.Rules[i].Name, got, want)
		}
	}
	if cfg, _ := sp.Projections[2].Cfgs[0].(string); cfg != "also-good" {
		t.Errorf("rule after the failing one projected %#v, want its own config", sp.Projections[2].Cfgs[0])
	}
}

// A profile that never went through Project, or went through it against a
// different filter chain, must not be evaluated: the projections are indexed
// by registration position, so binding one would hand a filter another
// filter's configuration.
func TestBindRefusesUnprojectedProfile(t *testing.T) {
	regs := claimAll(t, nil)
	b := newBinder(regs, nil)

	unprojected := compile(t, nil, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	unprojected.Projections = nil
	if _, err := b.bind([]*Profile{unprojected}, testRequest("example.com"), inputs.Workload{}); err == nil ||
		!strings.Contains(err.Error(), "was not projected") {
		t.Fatalf("bind(unprojected) = %v, want a not-projected error", err)
	}

	// Projected, but against a chain of a different size.
	otherChain, err := filter.Build(
		filter.Define(filter.Descriptor[string]{
			Name:   block.FilterName,
			Phases: filter.PhaseRequestHeaders,
			New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
		}, func(json.RawMessage) (string, error) { return "", nil }),
		filter.Define(filter.Descriptor[string]{
			Name:   "extra",
			Phases: filter.PhaseRequestHeaders,
			New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
		}, func(json.RawMessage) (string, error) { return "", nil }),
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	mismatched := compile(t, otherChain, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	if _, err := b.bind([]*Profile{mismatched}, testRequest("example.com"), inputs.Workload{}); err == nil ||
		!strings.Contains(err.Error(), "different filter chain") {
		t.Fatalf("bind(mismatched) = %v, want a chain-mismatch error", err)
	}

	// Same length, different order: the projections are positional, so this
	// must be refused too even though the length check would pass.
	reordered, err := filter.Build(
		filter.Define(filter.Descriptor[string]{
			Name:   "extra",
			Phases: filter.PhaseRequestHeaders,
			New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
		}, func(json.RawMessage) (string, error) { return "", nil }),
		filter.Define(filter.Descriptor[string]{
			Name:   block.FilterName,
			Phases: filter.PhaseRequestHeaders,
			New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
		}, func(json.RawMessage) (string, error) { return "", nil }),
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	swapped := compile(t, reordered, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	twoFilterBinder := newBinder(otherChain, nil)
	if _, err := twoFilterBinder.bind([]*Profile{swapped}, testRequest("example.com"), inputs.Workload{}); err == nil ||
		!strings.Contains(err.Error(), "different filter chain") {
		t.Fatalf("bind(reordered chain) = %v, want a chain-mismatch error", err)
	}
}
