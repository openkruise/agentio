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

package model

import (
	"encoding/json"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// HTTPPolicy is the configuration carried in SecurityProfile.policy_json.
type HTTPPolicy struct {
	Rules  []agentsv1alpha1.SecurityRule         `json:"rules,omitempty"`
	Audit  []agentsv1alpha1.AuditAction          `json:"audit,omitempty"`
	Inputs []agentsv1alpha1.SecurityProfileInput `json:"inputs,omitempty"`
}

// MarshalJSON preserves an empty inline input as a declared source.
func (p HTTPPolicy) MarshalJSON() ([]byte, error) {
	type input struct {
		agentsv1alpha1.SecurityProfileInput
		Inline map[string]string `json:"inline,omitzero"`
	}
	inputs := make([]input, len(p.Inputs))
	for i, declared := range p.Inputs {
		inputs[i] = input{SecurityProfileInput: declared, Inline: declared.Inline}
	}
	type plain HTTPPolicy
	return json.Marshal(struct {
		plain
		Inputs []input `json:"inputs,omitempty"`
	}{plain: plain(p), Inputs: inputs})
}
