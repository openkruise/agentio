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
	"encoding/json"
	"fmt"
	"text/template/parse"

	"github.com/google/cel-go/cel"
	agents "github.com/openkruise/agents-api/agents/v1alpha1"
)

func validateCEL(expression string) error {
	environment, err := cel.NewEnv()
	if err != nil {
		return fmt.Errorf("create CEL parser: %w", err)
	}
	_, issues := environment.Parse(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("CEL syntax: %w", issues.Err())
	}
	return nil
}

func validateTemplate(raw string) error {
	tree := parse.New("template")
	// Function availability and execution contexts belong to the API consumer.
	tree.Mode = parse.SkipFuncCheck
	_, err := tree.Parse(raw, "", "", map[string]*parse.Tree{})
	return err
}

func validateValueSource(value agents.ValueSource) error {
	sources := 0
	for _, source := range []*string{value.Value, value.Cel, value.Template} {
		if source != nil {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("value source requires exactly one of value, cel or template")
	}
	if value.Cel != nil {
		return validateCEL(*value.Cel)
	}
	if value.Template != nil {
		return validateTemplate(*value.Template)
	}
	return nil
}

func validateAudits(actions []agents.AuditAction) error {
	for _, action := range actions {
		if err := validateAudit(action); err != nil {
			return fmt.Errorf("audit %q: %w", action.Name, err)
		}
	}
	return nil
}

func validateAudit(action agents.AuditAction) error {
	if action.When != "" {
		if err := validateCEL(action.When); err != nil {
			return err
		}
	}
	if action.Webhook == nil {
		return fmt.Errorf("webhook is required")
	}
	webhook := action.Webhook
	if err := validateTemplate(webhook.URL); err != nil {
		return fmt.Errorf("webhook.url: %w", err)
	}
	if webhook.Request == nil {
		return nil
	}
	for _, header := range webhook.Request.Headers {
		if err := validateTemplate(header.Value); err != nil {
			return fmt.Errorf("webhook.request.headers[%q]: %w", header.Name, err)
		}
	}
	body := webhook.Request.Body
	if body == nil {
		return nil
	}
	if body.JSON != nil && body.Text != nil {
		return fmt.Errorf("audit body must not set both json and text")
	}
	if body.Text != nil {
		return validateTemplate(*body.Text)
	}
	if body.JSON != nil {
		var value any
		if err := json.Unmarshal(body.JSON.Raw, &value); err != nil {
			return fmt.Errorf("audit body JSON: %w", err)
		}
		return validateJSONTemplates(value)
	}
	return nil
}

func validateJSONTemplates(value any) error {
	switch value := value.(type) {
	case string:
		return validateTemplate(value)
	case map[string]any:
		for key, child := range value {
			if err := validateJSONTemplates(child); err != nil {
				return fmt.Errorf("[%q]: %w", key, err)
			}
		}
	case []any:
		for i, child := range value {
			if err := validateJSONTemplates(child); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
	}
	return nil
}
