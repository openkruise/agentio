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
	"strings"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// ValidateSecurityProfile checks the API contract and expression syntax without
// compiling a data-plane implementation or accessing external references.
func ValidateSecurityProfile(profile model.SecurityProfile) field.ErrorList {
	spec := field.NewPath("spec")
	var errs field.ErrorList
	if priority := profile.Spec.Priority; priority != nil && *priority < 0 {
		errs = append(errs, field.Invalid(spec.Child("priority"), *priority, "must not be negative"))
	} else if _, err := policy.SecurityProfileAttachment(profile); err != nil {
		errs = appendInvalid(errs, spec.Child("selector"), err)
	}
	_, err := policy.CompileTCPRules(profile.Spec.TCPRules)
	errs = appendInvalid(errs, spec.Child("tcpRules"), err)
	for i, input := range profile.Spec.Inputs {
		path := spec.Child("inputs").Index(i)
		if (input.Inline != nil) == (input.ConfigMap != nil) {
			errs = append(errs, field.Invalid(path, field.OmitValueType{}, "set exactly one input source"))
		}
		if input.ConfigMap != nil && input.ConfigMap.Namespace == "" && profile.Namespace == "" {
			errs = append(
				errs,
				field.Required(path.Child("configMap", "namespace"), "global profiles require an explicit namespace"),
			)
		}
	}
	errs = append(errs, validateAudits(profile.Spec.Audit, spec.Child("audit"))...)
	for i, rule := range profile.Spec.Rules {
		errs = append(errs, validateSecurityRule(rule, spec.Child("rules").Index(i))...)
	}
	return errs
}

func appendInvalid(errs field.ErrorList, path *field.Path, err error) field.ErrorList {
	if err != nil {
		return append(errs, field.Invalid(path, field.OmitValueType{}, err.Error()))
	}
	return errs
}

func validateSecurityRule(rule agents.SecurityRule, path *field.Path) field.ErrorList {
	errs := appendInvalid(nil, path, policy.ValidateTLSRule(rule))
	for i, match := range rule.Match {
		errs = appendInvalid(errs, path.Child("match").Index(i), validateMatch(match))
	}
	actions := path.Child("actions")
	errs = append(errs, validateAudits(rule.Actions.Audit, actions.Child("audit"))...)
	if callout := rule.Actions.HTTPCallout; callout != nil {
		calloutPath := actions.Child("httpCallout")
		namePath := calloutPath.Child("provider", "name")
		if name := callout.Provider.Name; name == "" {
			errs = append(errs, field.Required(namePath, "a named HTTP callout provider is required"))
		} else if problems := kubevalidation.IsDNS1123Subdomain(name); len(problems) != 0 {
			errs = append(errs, field.Invalid(namePath, name, strings.Join(problems, ", ")))
		}
		if callout.Request == nil && callout.Response == nil {
			errs = append(
				errs,
				field.Invalid(calloutPath, field.OmitValueType{}, "requires at least one request or response phase"),
			)
		}
		for _, entry := range []struct {
			name  string
			phase *agents.HTTPCalloutPhase
		}{{"request", callout.Request}, {"response", callout.Response}} {
			phase := entry.phase
			if phase == nil || phase.Headers == nil || !phase.Headers.Enabled || phase.Headers.Filter == nil {
				continue
			}
			filter := phase.Headers.Filter
			if (len(filter.AllowList) > 0) == (len(filter.DenyList) > 0) {
				errs = append(errs, field.Invalid(calloutPath.Child(entry.name, "headers", "filter"),
					field.OmitValueType{}, "requires exactly one non-empty allowList or denyList"))
			}
		}
	}
	if action := rule.Actions.TokenTransformation; action != nil && !action.Disabled {
		errs = appendInvalid(errs, actions.Child("tokenTransformation"), validateTokenTransformation(*action))
	}
	return errs
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
