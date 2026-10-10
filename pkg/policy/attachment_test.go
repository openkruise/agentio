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

package policy

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestPolicyAttachmentTargets(t *testing.T) {
	demo := model.Workload{
		UID:       "cluster//Pod/demo/client",
		Namespace: "demo",
		Labels:    map[string]string{"app": "client", "tier": "trusted"},
	}
	other := model.Workload{
		UID:       "cluster//Pod/other/client",
		Namespace: "other",
		Labels:    map[string]string{"app": "client"},
	}

	tests := []struct {
		name      string
		target    AttachmentTarget
		wantDemo  bool
		wantOther bool
	}{
		{name: "global", target: AttachmentTarget{Global: true}, wantDemo: true, wantOther: true},
		{name: "namespace", target: AttachmentTarget{Namespaces: []string{"demo"}}, wantDemo: true},
		{
			name: "global selector",
			target: AttachmentTarget{
				Global:   true,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "trusted"}},
			},
			wantDemo: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attachment, err := NewPolicyAttachment(PolicyAttachment{
				Kind:   PolicyKindSNIPolicy,
				Name:   test.name,
				Target: test.target,
			})
			if err != nil {
				t.Fatalf("new policy attachment: %v", err)
			}
			if got := attachment.Selects(demo); got != test.wantDemo {
				t.Fatalf("Selects(demo) = %v, want %v", got, test.wantDemo)
			}
			if got := attachment.Selects(other); got != test.wantOther {
				t.Fatalf("Selects(other) = %v, want %v", got, test.wantOther)
			}
		})
	}
}

func TestPolicyAttachmentValidation(t *testing.T) {
	invalidSelector := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key:      "app",
		Operator: metav1.LabelSelectorOperator("Invalid"),
		Values:   []string{"client"},
	}}}
	tests := []struct {
		name       string
		attachment PolicyAttachment
	}{
		{
			name: "empty kind",
			attachment: PolicyAttachment{
				Name: "policy",
				Target: AttachmentTarget{
					Global: true,
				},
			},
		},
		{
			name: "empty name",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Target: AttachmentTarget{
					Global: true,
				},
			},
		},
		{
			name: "no target",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
			},
		},
		{
			name: "global and namespace",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
				Target: AttachmentTarget{
					Global:     true,
					Namespaces: []string{"demo"},
				},
			},
		},
		{
			name: "invalid selector",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
				Target: AttachmentTarget{
					Global:   true,
					Selector: invalidSelector,
				},
			},
		},
		{
			name: "empty namespace",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
				Target: AttachmentTarget{
					Namespaces: []string{""},
				},
			},
		},
		{
			name: "duplicate namespace",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
				Target: AttachmentTarget{
					Namespaces: []string{"demo", "demo"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewPolicyAttachment(test.attachment); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestPolicyAttachmentEqualityTracksOnlyReferenceFields(t *testing.T) {
	policy, err := CompileSNIProfile(model.SecurityProfile{
		Name:         "security-profile",
		Namespace:    "demo",
		CreationTime: time.Unix(100, 0),
		Spec:         securitySpec(nil, map[string]string{"app": "sandbox"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	attachment := policy.PolicyAttachment()
	if attachment == nil {
		t.Fatal("expected a policy attachment")
	}
	rulesOnly := *policy
	rulesOnly.Policy = &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{{
		Match: &extensionsv1.SniMatch{Sni: []string{"changed.example.com"}},
	}}}
	if other := rulesOnly.PolicyAttachment(); other == nil || !attachment.Equals(*other) {
		t.Fatal("rules-only policy changes must not change the attachment")
	}
	if policy.Equals(rulesOnly) {
		t.Fatal("rules-only changes must change the compiled policy")
	}
	tests := []struct {
		name   string
		mutate func(*PolicyAttachment)
	}{
		{"resource name", func(p *PolicyAttachment) { p.Name = "demo/other" }},
		{"priority", func(p *PolicyAttachment) { p.Priority++ }},
		{"creation time", func(p *PolicyAttachment) { p.CreationTime = time.Unix(200, 0) }},
		{"namespace", func(p *PolicyAttachment) { p.Target.Namespaces = []string{"other"} }},
		{"pod name", func(p *PolicyAttachment) { p.Target.PodName = "sandbox" }},
		{"global scope", func(p *PolicyAttachment) { p.Target.Global = true }},
		{"selector", func(p *PolicyAttachment) {
			p.Target.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}
			p.selector = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := *policy
			copy := *attachment
			test.mutate(&copy)
			changed.Attachment = &copy
			if attachment.Equals(*changed.PolicyAttachment()) || policy.Equals(changed) {
				t.Fatalf("%s change did not change attachment and compiled policy", test.name)
			}
		})
	}
}

func TestPolicyAttachmentRejectsIncompletePolicy(t *testing.T) {
	for _, policy := range []CompiledSNIPolicy{
		{Policy: &extensionsv1.SniTrafficPolicy{}, Attachment: &PolicyAttachment{}},
		{Name: "demo/policy", Attachment: &PolicyAttachment{}},
	} {
		if got := policy.PolicyAttachment(); got != nil {
			t.Fatalf("incomplete policy produced attachment %+v", got)
		}
	}
}
