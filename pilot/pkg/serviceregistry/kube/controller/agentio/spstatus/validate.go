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
	"fmt"
	"regexp"
	texttemplate "text/template"

	"github.com/google/cel-go/cel"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// Condition reasons produced by ValidateSpec.
const (
	ReasonInvalidRegex      = "InvalidRegex"
	ReasonInvalidCEL        = "InvalidCEL"
	ReasonInvalidTemplate   = "InvalidTemplate"
	ReasonDuplicateRuleName = "DuplicateRuleName"
)

// SpecError is one validation failure. Field is a JSONPath-ish locator so the
// condition message can point at the offender.
type SpecError struct {
	Field   string
	Reason  string
	Message string
}

// auditCELEnv declares the variables documented on AuditAction.When
// (securityprofile_types.go:456-461). Compiling against this env catches both
// parse errors and references to variables the data plane does not provide.
var auditCELEnv = func() *cel.Env {
	env, err := cel.NewEnv(
		cel.Variable("result", cel.StringType),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("pod", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("profile", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("rule", cel.MapType(cel.StringType, cel.StringType)),
	)
	if err != nil {
		// A malformed env is a programming error, not user input.
		panic(fmt.Sprintf("failed to build audit CEL env: %v", err))
	}
	return env
}()

// ValidateSpec reports syntax problems the CRD schema cannot express: whether
// regexes, CEL expressions and Go templates actually compile, and whether rule
// names are unique. It never performs I/O.
//
// Returns nil when the spec is valid.
func ValidateSpec(spec *agentsv1alpha1.SecurityProfileSpec) []SpecError {
	if spec == nil {
		return nil
	}
	var errs []SpecError

	errs = append(errs, validateAuditList("spec.audit", spec.Audit)...)

	seen := make(map[string]struct{}, len(spec.Rules))
	for i, rule := range spec.Rules {
		base := fmt.Sprintf("spec.rules[%d]", i)
		if _, dup := seen[rule.Name]; dup {
			errs = append(errs, SpecError{
				Field:   base + ".name",
				Reason:  ReasonDuplicateRuleName,
				Message: fmt.Sprintf("rule name %q is used more than once", rule.Name),
			})
		}
		seen[rule.Name] = struct{}{}

		for j, m := range rule.Match {
			errs = append(errs, validateRuleMatch(fmt.Sprintf("%s.match[%d]", base, j), m)...)
		}
		errs = append(errs, validateActions(base+".actions", rule.Actions)...)
	}
	return errs
}

func validateRuleMatch(field string, m agentsv1alpha1.RuleMatch) []SpecError {
	var errs []SpecError
	for i, p := range m.Paths {
		if p.Type != agentsv1alpha1.PathMatchTypeRegex {
			continue
		}
		if err := compileRegex(p.Value); err != nil {
			errs = append(errs, SpecError{
				Field:   fmt.Sprintf("%s.paths[%d].value", field, i),
				Reason:  ReasonInvalidRegex,
				Message: err.Error(),
			})
		}
	}
	for i, h := range m.Headers {
		if h.Type != agentsv1alpha1.StringMatchTypeRegex {
			continue
		}
		if err := compileRegex(h.Value); err != nil {
			errs = append(errs, SpecError{
				Field:   fmt.Sprintf("%s.headers[%d].value", field, i),
				Reason:  ReasonInvalidRegex,
				Message: err.Error(),
			})
		}
	}
	for i, q := range m.QueryParams {
		if q.Type != agentsv1alpha1.StringMatchTypeRegex {
			continue
		}
		if err := compileRegex(q.Value); err != nil {
			errs = append(errs, SpecError{
				Field:   fmt.Sprintf("%s.queryParams[%d].value", field, i),
				Reason:  ReasonInvalidRegex,
				Message: err.Error(),
			})
		}
	}
	return errs
}

func validateActions(field string, a agentsv1alpha1.SecurityRuleActions) []SpecError {
	var errs []SpecError
	if tt := a.TokenTransformation; tt != nil && tt.ApiKey != nil {
		if w := tt.ApiKey.When; w != nil {
			if err := compileRegex(w.Pattern); err != nil {
				errs = append(errs, SpecError{
					Field:   field + ".tokenTransformation.apiKey.when.pattern",
					Reason:  ReasonInvalidRegex,
					Message: err.Error(),
				})
			}
		}
		if err := compileTemplate(tt.ApiKey.ValueTemplate); err != nil {
			errs = append(errs, SpecError{
				Field:   field + ".tokenTransformation.apiKey.valueTemplate",
				Reason:  ReasonInvalidTemplate,
				Message: err.Error(),
			})
		}
	}
	errs = append(errs, validateAuditList(field+".audit", a.Audit)...)
	return errs
}

func validateAuditList(field string, audits []agentsv1alpha1.AuditAction) []SpecError {
	var errs []SpecError
	for i, a := range audits {
		base := fmt.Sprintf("%s[%d]", field, i)
		if a.When != "" {
			if err := compileAuditCEL(a.When); err != nil {
				errs = append(errs, SpecError{
					Field:   base + ".when",
					Reason:  ReasonInvalidCEL,
					Message: err.Error(),
				})
			}
		}
		w := a.Webhook
		if w == nil {
			continue
		}
		if err := compileTemplate(w.URL); err != nil {
			errs = append(errs, SpecError{
				Field:   base + ".webhook.url",
				Reason:  ReasonInvalidTemplate,
				Message: err.Error(),
			})
		}
		if w.Request == nil {
			continue
		}
		for j, h := range w.Request.Headers {
			if err := compileTemplate(h.Value); err != nil {
				errs = append(errs, SpecError{
					Field:   fmt.Sprintf("%s.webhook.request.headers[%d].value", base, j),
					Reason:  ReasonInvalidTemplate,
					Message: err.Error(),
				})
			}
		}
		if b := w.Request.Body; b != nil && b.Text != nil {
			if err := compileTemplate(*b.Text); err != nil {
				errs = append(errs, SpecError{
					Field:   base + ".webhook.request.body.text",
					Reason:  ReasonInvalidTemplate,
					Message: err.Error(),
				})
			}
		}
	}
	return errs
}

func compileRegex(v string) error {
	if _, err := regexp.Compile(v); err != nil {
		return fmt.Errorf("must be a valid RE2 expression: %w", err)
	}
	return nil
}

func compileTemplate(v string) error {
	if _, err := texttemplate.New("t").Parse(v); err != nil {
		return fmt.Errorf("must be a valid Go text/template: %w", err)
	}
	return nil
}

func compileAuditCEL(expr string) error {
	ast, issues := auditCELEnv.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("must be a valid CEL expression: %w", issues.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return fmt.Errorf("must evaluate to bool, got %s", ast.OutputType())
	}
	return nil
}
