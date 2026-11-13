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

// Wire-level scenarios for the inputs-degradation model: a profile whose
// declared inputs are unavailable (for example its ConfigMap does not exist)
// still installs and enforces. Block rules keep blocking, and only
// inputs-dependent evaluations fail — resolved through the consuming action's
// failStrategy, never through the ext_proc provider's global failureModeAllow.
package securityprofile

import (
	"context"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	policysecurityprofile "github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/pkg/krt"
)

// staticMatcher serves hand-compiled profiles, bypassing the store so tests
// can install a profile in the degraded inputs-unavailable state directly.
type staticMatcher []*policysecurityprofile.Profile

func (m staticMatcher) ResolveProfiles(context.Context, subject.Subject) ([]*policysecurityprofile.Profile, error) {
	return m, nil
}

// compileWithInputsError compiles and projects the CRD object, then marks its
// inputs unavailable — exactly what the profilestore collection produces when
// a declared ConfigMap input is missing: a fully installed, enforcing profile
// version whose inputs slot is poisoned.
func compileWithInputsError(
	t *testing.T,
	obj *v1alpha1.SecurityProfile,
	regs []filter.Registration,
	msg string,
) *policysecurityprofile.Profile {
	t.Helper()
	sp, err := policysecurityprofile.NewProfile(obj, &obj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if err := sp.Project(regs); err != nil {
		t.Fatalf("Project: %v", err)
	}
	sp.InputsError = msg
	return sp
}

// TestScenario_BlockRuleEnforcedWithUnavailableInputs is the key regression
// from the inputs redesign: a profile created while its ConfigMap input is
// missing must still block — previously the whole profile failed to install
// and the pods it selected were unprotected.
func TestScenario_BlockRuleEnforcedWithUnavailableInputs(t *testing.T) {
	profile := securityProfile("guard", "test-ns", nil, map[string]string{"app": "sandbox"}, []v1alpha1.SecurityRule{{
		Name:    "deny-exfil",
		Match:   []v1alpha1.RuleMatch{{Domains: []string{"evil.example.com"}}},
		Actions: v1alpha1.SecurityRuleActions{Block: &v1alpha1.BlockAction{StatusCode: 403}},
	}})
	regs, err := wiring.BuildFilters(wiring.Deps{Providers: &extensionprovider.Registry{}})
	if err != nil {
		t.Fatalf("BuildFilters: %v", err)
	}
	compiled := compileWithInputsError(t, profile, regs,
		`input "routing" from ConfigMap test-ns/missing: not found`)

	h := enginetest.New(t, enginetest.Options{
		Resolve:       policysecurityprofile.NewResolver(staticMatcher{compiled}, regs, nil, nil),
		Registrations: regs,
	})

	h.Run(t, enginetest.NewRequest("GET", "evil.example.com", "/exfil").
		Workload("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"})).
		RequireBlocked(t, 403)

	// A non-matching host still passes through: the degraded profile does not
	// blanket-deny, it enforces exactly its rules.
	h.Run(t, enginetest.NewRequest("GET", "ok.example.com", "/fine").
		Workload("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"})).
		RequirePassthrough(t)
}

// TestScenario_TokenTransformFailStrategyWithUnavailableInputs pins the
// failure routing for inputs-dependent actions on a degraded profile: the
// transformation whose value template reads .Inputs fails through its own
// failStrategy — Block denies with 403, Allow forwards without the mutation —
// and never becomes an ext_proc processing error subject to the provider's
// global failureModeAllow. A template that never reads inputs keeps injecting.
func TestScenario_TokenTransformFailStrategyWithUnavailableInputs(t *testing.T) {
	transformProfile := func(failStrategy v1alpha1.FailStrategy, valueTemplate string) *v1alpha1.SecurityProfile {
		return securityProfile("inject", "test-ns", nil, map[string]string{"app": "sandbox"}, []v1alpha1.SecurityRule{{
			Name:  "inject",
			Match: []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
			Actions: v1alpha1.SecurityRuleActions{TokenTransformation: &v1alpha1.TokenTransformationAction{
				FailStrategy:  failStrategy,
				Type:          v1alpha1.TokenTransformationTypeApiKey,
				CredentialRef: v1alpha1.CredentialRef{Secret: &v1alpha1.SecretCredentialRef{Name: "api-cred"}},
				ApiKey:        &v1alpha1.ApiKeyConfig{ValueTemplate: valueTemplate},
			}},
		}})
	}
	run := func(t *testing.T, failStrategy v1alpha1.FailStrategy, valueTemplate string) *enginetest.Verdict {
		t.Helper()
		regs, err := wiring.BuildFilters(wiring.Deps{
			Providers: &extensionprovider.Registry{},
			Secrets: tokentransform.NewSecretSource(
				krt.NewStaticCollection(
					nil,
					[]*corev1.Secret{newAPIKeySecret("test-ns", "api-cred", "secret-token-123")},
				),
				"test-ns",
			),
		})
		if err != nil {
			t.Fatalf("BuildFilters: %v", err)
		}
		compiled := compileWithInputsError(t, transformProfile(failStrategy, valueTemplate), regs,
			`input "routing" from ConfigMap test-ns/missing: not found`)
		h := enginetest.New(t, enginetest.Options{
			Resolve:       policysecurityprofile.NewResolver(staticMatcher{compiled}, regs, nil, nil),
			Registrations: regs,
		})
		return h.Run(t, enginetest.NewRequest("GET", "api.example.com", "/v1").
			Workload("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}))
	}
	const inputsTemplate = "Bearer {{ .Token }}-{{ .Inputs.routing }}"

	t.Run("default strategy blocks with 403", func(t *testing.T) {
		verdict := run(t, "", inputsTemplate)
		verdict.RequireBlocked(t, 403)
		if verdict.Err != nil {
			t.Fatalf("failure must resolve through failStrategy, not a processing error: %v", verdict.Err)
		}
	})

	t.Run("allow strategy passes through", func(t *testing.T) {
		verdict := run(t, v1alpha1.FailStrategyAllow, inputsTemplate)
		verdict.RequirePassthrough(t)
		if verdict.Err != nil {
			t.Fatalf("failure must resolve through failStrategy, not a processing error: %v", verdict.Err)
		}
	})

	t.Run("template not reading inputs still injects", func(t *testing.T) {
		verdict := run(t, "", "Bearer {{ .Token }}")
		verdict.RequireOutcome(t, "mutated")
		verdict.RequireHeader(t, "Authorization", "Bearer secret-token-123")
	})
}
