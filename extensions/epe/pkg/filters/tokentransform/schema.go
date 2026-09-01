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

// schema.go is tokentransform's payload contract: the JSON document a
// policy source must produce, and the only place the filter's config is
// built. The vocabulary is the filter's own — Type is a signer-registry
// key, and credentialRef is the typed union only. Released ApiKey spellings
// are accepted at the JSON boundary below and immediately normalized, which
// is why this file names no API package.
package tokentransform

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/cel-go/cel"
	"k8s.io/utils/ptr"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
)

// The failStrategy values that let a failed transformation through. Everything
// else blocks, including an empty or unrecognized value: the CRD defaults the
// field to Block, so an empty one means the payload skipped API-server
// defaulting, and failing closed matches the filter's fail-closed convention.
const (
	failStrategyAllow  = "Allow"
	failStrategyIgnore = "Ignore"
	maxHeaderRules     = 16
	maxHeaderTargets   = 64
)

// spec is the wire form of a tokentransform payload. Tags mirror the
// SecurityProfile CRD's TokenTransformationAction so a CRD-shaped document
// parses unchanged, minus `disabled`: an open payload map
// says "off" by omitting the key, so the policy side absorbs that field
// rather than passing it through. Tags are explicit
// because renaming a Go field must never silently change the wire.
type spec struct {
	FailStrategy  string            `json:"failStrategy,omitempty"`
	Type          string            `json:"type,omitempty"`
	CredentialRef credentialRefSpec `json:"credentialRef"`
	ApiKey        *apiKeySpec       `json:"apiKey,omitempty"`
	// Headers detects and rejects the superseded root headers spelling.
	// Ignoring it could silently apply a coexisting legacy apiKey transform.
	Headers []headerSpec `json:"headers,omitempty"`
}

// credentialRefSpec is the typed union; exactly one branch must be set.
type credentialRefSpec struct {
	Secret             *secretRefSpec   `json:"secret,omitempty"`
	CredentialProvider *providerRefSpec `json:"credentialProvider,omitempty"`
}

type secretRefSpec struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type providerRefSpec struct {
	Name       string                     `json:"name,omitempty"`
	Parameters map[string]valueSourceSpec `json:"parameters,omitempty"`
}

// valueSourceSpec is one provider parameter; exactly one field must be set.
type valueSourceSpec struct {
	Value    *string `json:"value,omitempty"`
	Cel      *string `json:"cel,omitempty"`
	Template *string `json:"template,omitempty"`
}

// apiKeySpec is the one normalized ApiKey form used after JSON decoding.
type apiKeySpec struct {
	TargetHeaders *headerSelectorSpec `json:"targetHeaders,omitempty"`
	Value         *valueSourceSpec    `json:"value,omitempty"`
	Body          *bodyTargetSpec     `json:"-"`
}

// apiKeyWireSpec exists only while decoding the released and current JSON
// spellings. UnmarshalJSON immediately folds the legacy fields into the
// selector/value form so they cannot leak into the compiled filter config.
type apiKeyWireSpec struct {
	When          *whenSpec           `json:"when,omitempty"`
	TargetHeader  string              `json:"targetHeader,omitempty"`
	ValueTemplate string              `json:"valueTemplate,omitempty"`
	TargetHeaders *headerSelectorSpec `json:"targetHeaders,omitempty"`
	Value         *valueSourceSpec    `json:"value,omitempty"`
	Target        *apiKeyTargetSpec   `json:"target,omitempty"`
	// NestedHeaders detects and rejects the unreleased apiKey.headers spelling
	// from the branch baseline. It is never compiled as configuration.
	NestedHeaders json.RawMessage `json:"headers,omitempty"`
}

type apiKeyTargetSpec struct {
	Header *headerTargetSpec `json:"header,omitempty"`
	Body   *bodyTargetSpec   `json:"body,omitempty"`
}

type headerTargetSpec struct {
	Name string `json:"name,omitempty"`
}

type bodyTargetSpec struct {
	CEL       string `json:"cel,omitempty"`
	condition *whenSpec
}

type headerSelectorSpec struct {
	Names []string `json:"names,omitempty"`
	CEL   *string  `json:"cel,omitempty"`

	// condition is the released when field normalized into selection. A
	// non-match selects no headers, preserving the pre-credential short-circuit.
	condition *whenSpec
}

type headerSpec struct {
	Names     []string        `json:"names,omitempty"`
	CEL       *string         `json:"cel,omitempty"`
	Value     valueSourceSpec `json:"value"`
	Condition *whenSpec       `json:"-"`
}

type whenSpec struct {
	Header  string `json:"header,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

func (s *apiKeySpec) UnmarshalJSON(raw []byte) error {
	var wire apiKeyWireSpec
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	if len(wire.NestedHeaders) != 0 {
		return fmt.Errorf("apiKey.headers is not supported; use apiKey.targetHeaders and apiKey.value")
	}
	*s = apiKeySpec{}
	if wire.Target != nil {
		if wire.TargetHeaders != nil || wire.TargetHeader != "" {
			return fmt.Errorf("apiKey target must not be combined with targetHeaders or targetHeader")
		}
		hasHeader := wire.Target.Header != nil
		hasBody := wire.Target.Body != nil
		if hasHeader == hasBody {
			return fmt.Errorf("apiKey target must set exactly one of header or body")
		}
		if hasHeader {
			s.TargetHeaders = &headerSelectorSpec{
				Names:     []string{wire.Target.Header.Name},
				condition: wire.When,
			}
		} else {
			s.Body = wire.Target.Body
			s.Body.condition = wire.When
		}
		s.Value = wire.Value
		if s.Value == nil {
			s.Value = &valueSourceSpec{Template: ptr.To(wire.ValueTemplate)}
		}
		return nil
	}
	if wire.TargetHeaders != nil {
		s.TargetHeaders = wire.TargetHeaders
		s.Value = wire.Value
		return nil
	}

	name := wire.TargetHeader
	if name == "" {
		name = DefaultTargetHeader
	}
	s.TargetHeaders = &headerSelectorSpec{
		Names:     []string{name},
		condition: wire.When,
	}
	s.Value = &valueSourceSpec{Template: ptr.To(wire.ValueTemplate)}
	return nil
}

// parse compiles one payload document into the filter config. Templates,
// CEL programs and regexps are compiled here — once per profile version,
// never per request. A type with no registered signer fails closed here
// rather than at request time, so silent fail-open is structurally
// impossible.
func parse(raw json.RawMessage) (Config, error) {
	var s spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return Config{}, err
	}
	if len(s.Headers) != 0 {
		return Config{}, fmt.Errorf("root headers is not supported; use apiKey.targetHeaders and apiKey.value")
	}
	key := s.Type
	if key == "" {
		key = TypeAPIKey
	}
	if !HasSigner(key) {
		return Config{}, fmt.Errorf("token transformation type %q has no signer in this build", s.Type)
	}

	cfg := Config{
		Type:      key,
		FailBlock: s.FailStrategy != failStrategyAllow && s.FailStrategy != failStrategyIgnore,
	}

	source, err := parseSource(s.CredentialRef)
	if err != nil {
		return Config{}, err
	}
	cfg.Source = source

	switch {
	case key != TypeAPIKey:
		// Signer-specific transports such as AliyunSTS carry no ApiKey config.
	case s.ApiKey == nil:
		return Config{}, fmt.Errorf("token transformation defines no apiKey config")
	default:
		value := valueSourceSpec{}
		if s.ApiKey.Value != nil {
			value = *s.ApiKey.Value
		}
		if s.ApiKey.Body != nil {
			cfg.SignerCfg, err = compileBodyTarget(*s.ApiKey.Body, value)
		} else {
			cfg.SignerCfg, err = compileHeaderRules([]headerSpec{{
				Names:     s.ApiKey.TargetHeaders.Names,
				CEL:       s.ApiKey.TargetHeaders.CEL,
				Value:     value,
				Condition: s.ApiKey.TargetHeaders.condition,
			}}, "apiKey")
		}
	}
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func compileBodyTarget(body bodyTargetSpec, value valueSourceSpec) (ApiKeyConfig, error) {
	program, err := eval.CompileBodyMutation(body.CEL)
	if err != nil {
		return ApiKeyConfig{}, fmt.Errorf("compile apiKey.target.body.cel: %w", err)
	}
	compiledValue, err := compileAPIKeyValue(value, "apiKey.value")
	if err != nil {
		return ApiKeyConfig{}, err
	}
	var condition *When
	if body.condition != nil {
		re, err := regexp.Compile(body.condition.Pattern)
		if err != nil {
			return ApiKeyConfig{}, fmt.Errorf("compile when pattern %q: %w", body.condition.Pattern, err)
		}
		condition = &When{Header: body.condition.Header, Re: re}
	}
	return ApiKeyConfig{Body: &ApiKeyBodyConfig{
		Program: program, Value: compiledValue, Condition: condition,
	}}, nil
}

func compileHeaderRules(rules []headerSpec, apiKeyPath ...string) (ApiKeyConfig, error) {
	if len(rules) > maxHeaderRules {
		return ApiKeyConfig{}, fmt.Errorf("token transformation headers has %d rules, want at most %d", len(rules), maxHeaderRules)
	}
	compiled := make([]ApiKeyHeaderConfig, 0, len(rules))
	staticTargets := 0
	staticNames := make(map[string]struct{})
	for i, rule := range rules {
		selectorPath := fmt.Sprintf("headers[%d]", i)
		valuePath := selectorPath + ".value"
		if len(apiKeyPath) > 0 && len(rules) == 1 {
			selectorPath = apiKeyPath[0] + ".targetHeaders"
			valuePath = apiKeyPath[0] + ".value"
		}
		hasNames := len(rule.Names) > 0
		hasCEL := rule.CEL != nil
		if hasNames == hasCEL {
			return ApiKeyConfig{}, fmt.Errorf("%s: exactly one of names or cel must be set", selectorPath)
		}

		out := ApiKeyHeaderConfig{}
		if rule.Condition != nil {
			re, err := regexp.Compile(rule.Condition.Pattern)
			if err != nil {
				return ApiKeyConfig{}, fmt.Errorf("compile when pattern %q: %w", rule.Condition.Pattern, err)
			}
			out.Condition = &When{Header: rule.Condition.Header, Re: re}
		}
		if hasNames {
			staticTargets += len(rule.Names)
			if staticTargets > maxHeaderTargets {
				return ApiKeyConfig{}, fmt.Errorf("token transformation headers has more than %d static targets", maxHeaderTargets)
			}
			out.Names = make([]string, len(rule.Names))
			for j, rawName := range rule.Names {
				name, err := filter.ValidateHeaderName(filter.HeaderSet, rawName)
				if err != nil {
					return ApiKeyConfig{}, fmt.Errorf("%s.names[%d]: %w", selectorPath, j, err)
				}
				if _, duplicate := staticNames[name]; duplicate {
					return ApiKeyConfig{}, fmt.Errorf("%s.names[%d]: duplicates static header %q", selectorPath, j, name)
				}
				staticNames[name] = struct{}{}
				out.Names[j] = name
			}
		} else {
			env, err := eval.RequestMutationEnv()
			if err != nil {
				return ApiKeyConfig{}, fmt.Errorf("init %s selector CEL: %w", selectorPath, err)
			}
			out.Selector, err = compileCEL(env, selectorPath+".cel", *rule.CEL, cel.ListType(cel.StringType))
			if err != nil {
				return ApiKeyConfig{}, err
			}
		}

		compiledValue, err := compileAPIKeyValue(rule.Value, valuePath)
		if err != nil {
			return ApiKeyConfig{}, err
		}
		out.Value = compiledValue
		compiled = append(compiled, out)
	}
	return ApiKeyConfig{Headers: compiled}, nil
}

func compileAPIKeyValue(source valueSourceSpec, valuePath string) (HeaderValueSource, error) {
	branches := 0
	if source.Value != nil {
		branches++
	}
	if source.Template != nil {
		branches++
	}
	if source.Cel != nil {
		branches++
	}
	if branches != 1 {
		return HeaderValueSource{}, fmt.Errorf("%s: exactly one of value, template or cel must be set", valuePath)
	}
	var out HeaderValueSource
	switch {
	case source.Value != nil:
		out.Literal = ptr.To(*source.Value)
	case source.Template != nil:
		if *source.Template == "" {
			return HeaderValueSource{}, fmt.Errorf("%s.template is empty", valuePath)
		}
		tmpl, err := eval.CompileTemplate(valuePath+".template", *source.Template)
		if err != nil {
			return HeaderValueSource{}, fmt.Errorf("compile %s.template: %w", valuePath, err)
		}
		if _, err := eval.ProbeRender(tmpl, ApiKeyTemplateData{}); err != nil {
			return HeaderValueSource{}, fmt.Errorf("probe %s.template: %w", valuePath, err)
		}
		out.Template = tmpl
	case source.Cel != nil:
		env, err := eval.RequestMutationEnv()
		if err != nil {
			return HeaderValueSource{}, fmt.Errorf("init %s CEL: %w", valuePath, err)
		}
		out.CEL, err = compileCEL(env, valuePath+".cel", *source.Cel, cel.StringType)
		if err != nil {
			return HeaderValueSource{}, err
		}
	}
	return out, nil
}

func compileCEL(env *cel.Env, label, expression string, want *cel.Type) (cel.Program, error) {
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile %s: %w", label, issues.Err())
	}
	got := ast.OutputType()
	if !want.IsAssignableType(got) && !dynamicCELFallback(want, got) {
		return nil, fmt.Errorf("compile %s: expression must return %s, got %s", label, want, got)
	}
	prog, err := env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(eval.RestrictedRequestCELCostLimit),
	)
	if err != nil {
		return nil, fmt.Errorf("program %s: %w", label, err)
	}
	return prog, nil
}

func dynamicCELFallback(want, got *cel.Type) bool {
	if got.IsExactType(cel.DynType) {
		return true
	}
	return want.IsExactType(cel.ListType(cel.StringType)) && got.IsExactType(cel.ListType(cel.DynType))
}

// parseSource resolves the credentialRef union into the filter's own
// SourceSpec. Neither branch set is as malformed as both: a payload that
// names no credential cannot be served, and guessing a default would be a
// silent fail-open.
func parseSource(ref credentialRefSpec) (SourceSpec, error) {
	hasSecret := ref.Secret != nil
	hasProvider := ref.CredentialProvider != nil
	switch {
	case hasSecret && hasProvider:
		return SourceSpec{}, fmt.Errorf("credentialRef must not set both secret and credentialProvider")
	case hasSecret:
		if ref.Secret.Name == "" {
			return SourceSpec{}, fmt.Errorf("credentialRef.secret.name is empty")
		}
		return SourceSpec{
			Kind: SourceKindSecret, Name: ref.Secret.Name, Namespace: ref.Secret.Namespace,
		}, nil
	case hasProvider:
		if ref.CredentialProvider.Name == "" {
			return SourceSpec{}, fmt.Errorf("credentialRef.credentialProvider.name is empty")
		}
		params, err := compileParams(ref.CredentialProvider.Parameters)
		if err != nil {
			return SourceSpec{}, err
		}
		return SourceSpec{
			Kind: SourceKindProvider, Name: ref.CredentialProvider.Name, Parameters: params,
		}, nil
	default:
		return SourceSpec{}, fmt.Errorf("credentialRef sets neither secret nor credentialProvider")
	}
}

// compileParams pre-compiles credentialProvider parameter sources; a
// compile failure is a malformed payload and fails closed at parse time.
func compileParams(parameters map[string]valueSourceSpec) (map[string]ParamSource, error) {
	if len(parameters) == 0 {
		return nil, nil
	}
	out := make(map[string]ParamSource, len(parameters))
	for name, source := range parameters {
		count := 0
		if source.Value != nil {
			count++
		}
		if source.Cel != nil {
			count++
		}
		if source.Template != nil {
			count++
		}
		if count != 1 {
			return nil, fmt.Errorf("credential parameter %q: exactly one of value, cel or template must be set", name)
		}
		var ps ParamSource
		switch {
		case source.Value != nil:
			v := *source.Value
			ps.Value = &v
		case source.Template != nil:
			tmpl, err := eval.CompileTemplate("credentialParameter", *source.Template)
			if err != nil {
				return nil, fmt.Errorf("credential parameter %q: %w", name, err)
			}
			ps.Template = tmpl
		default:
			prog, err := eval.CompileValue(*source.Cel)
			if err != nil {
				return nil, fmt.Errorf("credential parameter %q: %w", name, err)
			}
			ps.Cel = prog
		}
		out[name] = ps
	}
	return out, nil
}

// NewDefinition returns a token-transform definition with its dependencies frozen.
func NewDefinition(deps Deps) filter.Definition {
	return filter.Define(NewDescriptor(deps), parse)
}
