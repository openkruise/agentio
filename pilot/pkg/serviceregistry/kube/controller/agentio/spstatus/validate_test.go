// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spstatus

import (
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/util/assert"
)

func ptrTo[T any](v T) *T { return &v }

func TestValidateSpec(t *testing.T) {
	cases := []struct {
		name       string
		spec       *agentsv1alpha1.SecurityProfileSpec
		wantReason string // "" means valid
	}{
		{
			name: "empty spec is valid",
			spec: &agentsv1alpha1.SecurityProfileSpec{},
		},
		{
			name: "valid path regex",
			spec: specWithRuleMatch(agentsv1alpha1.RuleMatch{
				Domains: []string{"*"},
				Paths: []agentsv1alpha1.PathMatch{
					{Type: agentsv1alpha1.PathMatchTypeRegex, Value: `^/v1/[a-z]+$`},
				},
			}),
		},
		{
			name: "invalid path regex",
			spec: specWithRuleMatch(agentsv1alpha1.RuleMatch{
				Domains: []string{"*"},
				Paths: []agentsv1alpha1.PathMatch{
					{Type: agentsv1alpha1.PathMatchTypeRegex, Value: `^/v1/([a-z]+$`},
				},
			}),
			wantReason: ReasonInvalidRegex,
		},
		{
			name: "prefix path is not compiled as regex",
			spec: specWithRuleMatch(agentsv1alpha1.RuleMatch{
				Domains: []string{"*"},
				Paths: []agentsv1alpha1.PathMatch{
					{Type: agentsv1alpha1.PathMatchTypePrefix, Value: `([unbalanced`},
				},
			}),
		},
		{
			name: "invalid header regex",
			spec: specWithRuleMatch(agentsv1alpha1.RuleMatch{
				Domains: []string{"*"},
				Headers: []agentsv1alpha1.HeaderMatch{
					{Name: "X-A", Type: agentsv1alpha1.StringMatchTypeRegex, Value: `(`},
				},
			}),
			wantReason: ReasonInvalidRegex,
		},
		{
			name: "invalid query param regex",
			spec: specWithRuleMatch(agentsv1alpha1.RuleMatch{
				Domains: []string{"*"},
				QueryParams: []agentsv1alpha1.QueryParamMatch{
					{Name: "q", Type: agentsv1alpha1.StringMatchTypeRegex, Value: `[`},
				},
			}),
			wantReason: ReasonInvalidRegex,
		},
		{
			name:       "invalid ActionCondition pattern",
			spec:       specWithTokenTransformation(`(unclosed`, "{{ .Token }}"),
			wantReason: ReasonInvalidRegex,
		},
		{
			name:       "invalid ValueTemplate",
			spec:       specWithTokenTransformation(`^Bearer `, "{{ .Token"),
			wantReason: ReasonInvalidTemplate,
		},
		{
			name: "valid audit CEL",
			spec: specWithAuditWhen(`result == "blocked"`),
		},
		{
			name: "audit CEL referencing all documented variables",
			spec: specWithAuditWhen(`result == "blocked" && request.host == "a" && pod.name == "b" && profile.name == "c" && rule.name == "d"`),
		},
		{
			name:       "audit CEL that does not parse",
			spec:       specWithAuditWhen(`result ==`),
			wantReason: ReasonInvalidCEL,
		},
		{
			name:       "audit CEL referencing an undeclared variable",
			spec:       specWithAuditWhen(`nosuchvar == "x"`),
			wantReason: ReasonInvalidCEL,
		},
		{
			name:       "audit CEL that is not a bool",
			spec:       specWithAuditWhen(`result`),
			wantReason: ReasonInvalidCEL,
		},
		{
			name: "empty audit CEL is valid (means always fire)",
			spec: specWithAuditWhen(``),
		},
		{
			name:       "invalid audit webhook URL template",
			spec:       specWithAuditURL("http://{{ .Pod.IP "),
			wantReason: ReasonInvalidTemplate,
		},
		{
			name: "duplicate rule name",
			spec: &agentsv1alpha1.SecurityProfileSpec{
				Rules: []agentsv1alpha1.SecurityRule{
					{Name: "r1", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}}},
					{Name: "r1", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}}},
				},
			},
			wantReason: ReasonDuplicateRuleName,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateSpec(tc.spec)
			if tc.wantReason == "" {
				assert.Equal(t, len(got), 0)
				return
			}
			if len(got) == 0 {
				t.Fatalf("expected reason %q, got no errors", tc.wantReason)
			}
			assert.Equal(t, got[0].Reason, tc.wantReason)
			if got[0].Field == "" {
				t.Errorf("SpecError.Field must be populated so the condition message can point at the offender")
			}
		})
	}
}

func specWithRuleMatch(m agentsv1alpha1.RuleMatch) *agentsv1alpha1.SecurityProfileSpec {
	return &agentsv1alpha1.SecurityProfileSpec{
		Rules: []agentsv1alpha1.SecurityRule{{Name: "r1", Match: []agentsv1alpha1.RuleMatch{m}}},
	}
}

func specWithTokenTransformation(pattern, valueTemplate string) *agentsv1alpha1.SecurityProfileSpec {
	return &agentsv1alpha1.SecurityProfileSpec{
		Rules: []agentsv1alpha1.SecurityRule{{
			Name:  "r1",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}},
			Actions: agentsv1alpha1.SecurityRuleActions{
				TokenTransformation: &agentsv1alpha1.TokenTransformationAction{
					Type:          agentsv1alpha1.TokenTransformationTypeApiKey,
					CredentialRef: agentsv1alpha1.CredentialRef{Kind: agentsv1alpha1.CredentialRefKindSecret, Name: "s"},
					ApiKey: &agentsv1alpha1.ApiKeyConfig{
						When:          &agentsv1alpha1.ActionCondition{Header: "Authorization", Pattern: pattern},
						ValueTemplate: valueTemplate,
					},
				},
			},
		}},
	}
}

func specWithAuditWhen(when string) *agentsv1alpha1.SecurityProfileSpec {
	return &agentsv1alpha1.SecurityProfileSpec{
		Audit: []agentsv1alpha1.AuditAction{{
			Name: "a1",
			When: when,
			Webhook: &agentsv1alpha1.AuditWebhook{
				URL:     "http://example.com/audit",
				Timeout: &metav1.Duration{},
			},
		}},
	}
}

func specWithAuditURL(url string) *agentsv1alpha1.SecurityProfileSpec {
	return &agentsv1alpha1.SecurityProfileSpec{
		Audit: []agentsv1alpha1.AuditAction{{
			Name:    "a1",
			Webhook: &agentsv1alpha1.AuditWebhook{URL: url},
		}},
	}
}

// TestValidateSpecRuleLevelAudit covers the rule-level audit override list,
// which the spec-level listMapKey constraint does not protect.
func TestValidateSpecRuleLevelAudit(t *testing.T) {
	spec := &agentsv1alpha1.SecurityProfileSpec{
		Rules: []agentsv1alpha1.SecurityRule{{
			Name:  "r1",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}},
			Actions: agentsv1alpha1.SecurityRuleActions{
				Audit: []agentsv1alpha1.AuditAction{{
					Name:    "a1",
					When:    `result ==`,
					Webhook: &agentsv1alpha1.AuditWebhook{URL: "http://example.com"},
				}},
			},
		}},
	}
	got := ValidateSpec(spec)
	if len(got) != 1 {
		t.Fatalf("want 1 error, got %d: %+v", len(got), got)
	}
	assert.Equal(t, got[0].Reason, ReasonInvalidCEL)
}

// TestValidateSpecAuditHeaderTemplate keeps AuditHeader.Value covered.
func TestValidateSpecAuditHeaderTemplate(t *testing.T) {
	spec := &agentsv1alpha1.SecurityProfileSpec{
		Audit: []agentsv1alpha1.AuditAction{{
			Name: "a1",
			Webhook: &agentsv1alpha1.AuditWebhook{
				URL: "http://example.com",
				Request: &agentsv1alpha1.AuditRequest{
					Headers: []agentsv1alpha1.AuditHeader{{Name: "X-A", Value: "{{ .Bad"}},
				},
			},
		}},
	}
	got := ValidateSpec(spec)
	if len(got) != 1 {
		t.Fatalf("want 1 error, got %d: %+v", len(got), got)
	}
	assert.Equal(t, got[0].Reason, ReasonInvalidTemplate)
}

// TestValidateSpecAuditBodyText keeps AuditBody.Text covered.
func TestValidateSpecAuditBodyText(t *testing.T) {
	spec := &agentsv1alpha1.SecurityProfileSpec{
		Audit: []agentsv1alpha1.AuditAction{{
			Name: "a1",
			Webhook: &agentsv1alpha1.AuditWebhook{
				URL: "http://example.com",
				Request: &agentsv1alpha1.AuditRequest{
					Body: &agentsv1alpha1.AuditBody{Text: ptrTo("{{ .Bad")},
				},
			},
		}},
	}
	got := ValidateSpec(spec)
	if len(got) != 1 {
		t.Fatalf("want 1 error, got %d: %+v", len(got), got)
	}
	assert.Equal(t, got[0].Reason, ReasonInvalidTemplate)
}
