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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
)

func secret(ns, name string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
}

func profileWithCredRef(ns string, kind agentsv1alpha1.CredentialRefKind, name string) *agentsv1alpha1.SecurityProfile {
	return &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "sp"},
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Rules: []agentsv1alpha1.SecurityRule{{
				Name:  "r1",
				Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}},
				Actions: agentsv1alpha1.SecurityRuleActions{
					TokenTransformation: &agentsv1alpha1.TokenTransformationAction{
						Type:          agentsv1alpha1.TokenTransformationTypeApiKey,
						CredentialRef: agentsv1alpha1.CredentialRef{Kind: kind, Name: name},
						ApiKey:        &agentsv1alpha1.ApiKeyConfig{ValueTemplate: "{{ .Token }}"},
					},
				},
			}},
		},
	}
}

// refErrsResult wraps the ResolveRefs output so it satisfies krt's
// ResourceNamer requirement for singleton values.
type refErrsResult struct {
	errs []RefError
}

func (refErrsResult) ResourceName() string { return "resolve-refs" }

// runResolveRefs drives ResolveRefs through a real krt collection so the
// krt.HandlerContext dependency tracking is exercised, not stubbed.
func runResolveRefs(
	t *testing.T,
	sp *agentsv1alpha1.SecurityProfile,
	existing []any,
) []RefError {
	t.Helper()
	stop := test.NewStop(t)
	mock := krttest.NewMock(t, existing)
	secrets := krttest.GetMockCollection[*corev1.Secret](mock)
	secrets.WaitUntilSynced(stop)
	out := krt.NewSingleton(func(ctx krt.HandlerContext) *refErrsResult {
		return &refErrsResult{errs: ResolveRefs(ctx, sp, secrets)}
	}, krt.WithStop(stop))
	out.AsCollection().WaitUntilSynced(stop)
	got := out.Get()
	if got == nil {
		return nil
	}
	return got.errs
}

func TestResolveRefs(t *testing.T) {
	cases := []struct {
		name       string
		profile    *agentsv1alpha1.SecurityProfile
		secrets    []any
		wantReason string // "" means resolved
	}{
		{
			name:    "secret present in same namespace",
			profile: profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKindSecret, "cred"),
			secrets: []any{secret("ns-a", "cred")},
		},
		{
			name:       "secret absent",
			profile:    profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKindSecret, "cred"),
			secrets:    []any{},
			wantReason: ReasonSecretNotFound,
		},
		{
			name:       "secret only present in another namespace",
			profile:    profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKindSecret, "cred"),
			secrets:    []any{secret("ns-b", "cred")},
			wantReason: ReasonSecretNotFound,
		},
		{
			name:    "CredentialProvider kind is not checked",
			profile: profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKindCredentialProvider, "provider"),
			secrets: []any{},
		},
		{
			name:       "unknown kind is reported",
			profile:    profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKind("Bogus"), "x"),
			secrets:    []any{},
			wantReason: ReasonUnsupportedRefKind,
		},
		{
			name: "profile without tokenTransformation resolves",
			profile: &agentsv1alpha1.SecurityProfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "sp"},
			},
			secrets: []any{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runResolveRefs(t, tc.profile, tc.secrets)
			if tc.wantReason == "" {
				assert.Equal(t, len(got), 0)
				return
			}
			if len(got) == 0 {
				t.Fatalf("expected reason %q, got no errors", tc.wantReason)
			}
			assert.Equal(t, got[0].Reason, tc.wantReason)
			if got[0].Field == "" {
				t.Errorf("RefError.Field must be populated")
			}
		})
	}
}
