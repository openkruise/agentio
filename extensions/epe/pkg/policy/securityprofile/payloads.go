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

// payloads.go is the SecurityProfile adapter's entire knowledge of which
// CRD field feeds which filter. A second policy API writes its own
// equivalent and reuses every filter and filter.Project unchanged.
package securityprofile

import (
	"encoding/json"
	"fmt"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	// The filter packages are imported for their FilterName
	// constants only: the payload keys must be the registered names, and
	// hardcoded strings would drift. This is the one place the policy
	// layer names filter packages.
	"istio.io/istio/extensions/epe/pkg/filters/block"
	"istio.io/istio/extensions/epe/pkg/filters/bypass"
	"istio.io/istio/extensions/epe/pkg/filters/headermutation"
	"istio.io/istio/extensions/epe/pkg/filters/mcpacl"
	"istio.io/istio/extensions/epe/pkg/filters/tokentransform"
)

// payloadsFor turns one rule's actions into the per-filter payload
// documents filter.Project consumes, keyed by registered filter name. A
// key is absent exactly when the rule does not mount that filter.
//
// Marshal errors are returned, never swallowed: an action we cannot encode
// is a rule we cannot enforce, and the binder fails such a rule closed.
func payloadsFor(rule *Rule) (map[string]json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if a := rule.Actions.Block; a != nil {
		raw, err := json.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("marshal block action: %w", err)
		}
		m[block.FilterName] = raw
	}
	if rule.Actions.Bypass {
		// bypass is enabled by presence; it has nothing to configure.
		m[bypass.FilterName] = json.RawMessage(`{}`)
	}
	if a := rule.Actions.MCPToolPolicy; a != nil {
		raw, err := json.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("marshal mcpToolPolicy action: %w", err)
		}
		m[mcpacl.FilterName] = raw
	}
	if a := rule.Actions.HeaderManipulation; a != nil {
		raw, err := headerManipulationPayload(a)
		if err != nil {
			return nil, fmt.Errorf("build headerManipulation payload: %w", err)
		}
		m[headermutation.FilterName] = raw
	}
	// Disabled is absorbed here: an open payload map expresses "off" by
	// omitting the key, so a disabled action simply produces no payload.
	if a := rule.Actions.TokenTransformation; a != nil && !a.Disabled {
		raw, err := tokenTransformPayload(a)
		if err != nil {
			return nil, fmt.Errorf("build tokenTransformation payload: %w", err)
		}
		m[tokentransform.FilterName] = raw
	}
	return m, nil
}

// tokenTransformPayload emits the action as tokentransform's document. Two
// adjustments make the CRD's shape the filter's schema: the deprecated
// credentialRef spelling is normalized to the typed union, and disabled is
// cleared because presence of the key is what enables the filter. Both are
// CRD compatibility concerns that must not travel into the filter.
func tokenTransformPayload(a *v1alpha1.TokenTransformationAction) (json.RawMessage, error) {
	ref, err := normalizeCredentialRef(a.CredentialRef)
	if err != nil {
		return nil, err
	}
	normalized := *a
	normalized.CredentialRef = ref
	normalized.Disabled = false
	return json.Marshal(&normalized)
}

// headerManipulationPayload wraps the CRD's flat set/remove lists in the
// headermutation filter's phase-based schema. SecurityRule header
// manipulation is defined for egress requests only, so both lists land on
// the request phase and the response phase stays empty.
func headerManipulationPayload(a *v1alpha1.HeaderManipulationAction) (json.RawMessage, error) {
	type opSpec struct {
		Set    []v1alpha1.HeaderValue `json:"set,omitempty"`
		Remove []string               `json:"remove,omitempty"`
	}
	return json.Marshal(struct {
		Request opSpec `json:"request"`
	}{Request: opSpec{Set: a.Set, Remove: a.Remove}})
}
