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

package validation

import (
	"fmt"
	"regexp"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// ValidateSecurityProfile checks the API contract and expression syntax without
// compiling a data-plane implementation or accessing external references.
func ValidateSecurityProfile(profile model.SecurityProfile) error {
	if _, err := policy.SecurityProfileAttachment(profile); err != nil {
		return err
	}
	if _, err := policy.CompileTCPRules(profile.Spec.TCPRules); err != nil {
		return err
	}
	for _, input := range profile.Spec.Inputs {
		if (input.Inline != nil) == (input.ConfigMap != nil) {
			return fmt.Errorf("input %q must set exactly one source", input.Name)
		}
		if input.ConfigMap != nil && input.ConfigMap.Namespace == "" && profile.Namespace == "" {
			return fmt.Errorf("ConfigMap input %q requires an explicit namespace for a global profile", input.Name)
		}
	}
	if err := validateAudits(profile.Spec.Audit); err != nil {
		return err
	}
	for _, rule := range profile.Spec.Rules {
		if err := validateSecurityRule(rule); err != nil {
			return fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}
	return nil
}

func validateSecurityRule(rule agents.SecurityRule) error {
	if err := policy.ValidateTLSRule(rule); err != nil {
		return err
	}
	for i, match := range rule.Match {
		if err := validateMatch(match); err != nil {
			return fmt.Errorf("match[%d]: %w", i, err)
		}
	}
	if err := validateAudits(rule.Actions.Audit); err != nil {
		return err
	}
	if callout := rule.Actions.HTTPCallout; callout != nil {
		if callout.Request == nil && callout.Response == nil {
			return fmt.Errorf("httpCallout requires at least one request or response phase")
		}
		for _, phase := range []*agents.HTTPCalloutPhase{callout.Request, callout.Response} {
			if phase == nil || phase.Headers == nil || !phase.Headers.Enabled || phase.Headers.Filter == nil {
				continue
			}
			filter := phase.Headers.Filter
			if (len(filter.AllowList) > 0) == (len(filter.DenyList) > 0) {
				return fmt.Errorf("httpCallout header filter requires exactly one non-empty allowList or denyList")
			}
		}
	}
	if action := rule.Actions.TokenTransformation; action != nil && !action.Disabled {
		return validateTokenTransformation(*action)
	}
	return nil
}

func validateMatch(match agents.RuleMatch) error {
	for _, domain := range match.Domains {
		if _, err := policy.NormalizeDomain(domain); err != nil {
			return err
		}
	}
	for _, port := range match.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("destination port %d is outside 1..65535", port)
		}
	}
	for _, path := range match.Paths {
		if path.Type == agents.PathMatchTypeRegex {
			if _, err := regexp.Compile(path.Value); err != nil {
				return fmt.Errorf("path regex: %w", err)
			}
		}
	}
	for _, header := range match.Headers {
		if header.Type == agents.StringMatchTypeRegex {
			if _, err := regexp.Compile(header.Value); err != nil {
				return fmt.Errorf("header %q regex: %w", header.Name, err)
			}
		}
	}
	for _, query := range match.QueryParams {
		if query.Type == agents.StringMatchTypeRegex {
			if _, err := regexp.Compile(query.Value); err != nil {
				return fmt.Errorf("query parameter %q regex: %w", query.Name, err)
			}
		}
	}
	return nil
}

func validateTokenTransformation(action agents.TokenTransformationAction) error {
	ref, err := policy.NormalizeCredentialRef(action.CredentialRef)
	if err != nil {
		return err
	}
	if ref.CredentialProvider != nil {
		for name, value := range ref.CredentialProvider.Parameters {
			if err := validateValueSource(value); err != nil {
				return fmt.Errorf("credentialRef.credentialProvider.parameters[%q]: %w", name, err)
			}
		}
	}
	if action.Type != "" && action.Type != agents.TokenTransformationTypeApiKey || action.ApiKey == nil {
		return nil
	}
	key := action.ApiKey
	if key.TargetHeaders != nil {
		selector := key.TargetHeaders
		if (len(selector.Names) > 0) == (selector.Cel != nil) {
			return fmt.Errorf("apiKey.targetHeaders requires exactly one of names or cel")
		}
		if selector.Cel != nil {
			if err := validateCEL(*selector.Cel); err != nil {
				return fmt.Errorf("apiKey.targetHeaders.cel: %w", err)
			}
		}
		if key.Value == nil {
			return fmt.Errorf("apiKey.value is required with targetHeaders")
		}
		return validateValueSource(*key.Value)
	}
	if key.When != nil {
		if _, err := regexp.Compile(key.When.Pattern); err != nil {
			return fmt.Errorf("apiKey.when.pattern: %w", err)
		}
	}
	return validateTemplate(key.ValueTemplate)
}
