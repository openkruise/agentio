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
	"strings"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"

	// The filter packages are imported for their FilterName
	// constants only: the payload keys must be the registered names, and
	// hardcoded strings would drift. This is the one place the policy
	// layer names filter packages.
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/mcpacl"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/oauth2"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
)

// RuleProjection is one rule's projected per-filter configuration. Cfgs and
// Errs are parallel to the registration slice the projection ran against; Err
// is a failure to build the rule's payloads at all, which fails the rule
// closed regardless of which filters it mounts.
//
// Failures are recorded as well as returned, because a nil entry in Cfgs is
// ambiguous: it also means "this rule does not mount that filter", which the
// engine rightly skips. Both compilers reject a version whose Project fails,
// so recorded failures should never reach the store — but if a future caller
// forgets to reject, the recorded error is what makes the binder fail that
// rule closed instead of silently skipping the broken action as unmounted.
type RuleProjection struct {
	Cfgs []any
	Errs []error
	Err  error
}

// Project builds and parses every rule's per-filter payloads against regs,
// stores the result on the profile, and returns the first failure.
//
// It runs once per profile version, at the collection boundary: the compiled
// templates, CEL programs and regexps a rule needs therefore exist before any
// request can match it, and an authoring error such as an uncompilable
// credential parameter CEL expression surfaces there rather than on the first
// matching request, where the ext_proc provider's global failureModeAllow —
// not the action's own failStrategy — would decide the outcome.
//
// Both compilers treat the returned error the same way: the CRD and the
// per-Sandbox profile version alike are rejected, retaining any
// last-known-good version under the same identity. Compile-time errors are
// uniformly admission failures; only runtime errors (credential fetch,
// rendering against request data) resolve through per-action failure
// policies.
func (sp *Profile) Project(regs []filter.Registration) error {
	// Always assigned, so len(Projections) == len(Rules) marks a profile as
	// projected — the binder refuses to evaluate one that is not.
	sp.Projections = make([]RuleProjection, len(sp.Rules))
	sp.projectedAgainst = chainFingerprint(regs)
	var firstErr error
	for i := range sp.Rules {
		rule := &sp.Rules[i]
		payloads, err := payloadsFor(rule)
		if err != nil {
			sp.Projections[i] = RuleProjection{Err: err}
			if firstErr == nil {
				firstErr = fmt.Errorf("rule %q: %w", rule.Name, err)
			}
			continue
		}
		cfgs, errs := filter.Project(regs, payloads)
		sp.Projections[i] = RuleProjection{Cfgs: cfgs, Errs: errs}
		for j, err := range errs {
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("rule %q: filter %q: %w", rule.Name, regs[j].Name, err)
			}
		}
	}
	return firstErr
}

// chainFingerprint identifies a registration set by its ordered names. A
// projection's Cfgs are indexed by registration position, so equal lengths are
// not enough: two chains of the same size in a different order would each
// receive the other's configuration. NUL separates, because a registered
// filter name cannot contain one.
//
// Names are sufficient only because a filter's Parse is a pure function of its
// payload — the dependencies a Definition captures are read by New at request
// time, not by Parse. A Parse that closed over its Deps would make two chains
// with equal names produce different configs, and this fingerprint would not
// tell them apart.
func chainFingerprint(regs []filter.Registration) string {
	names := make([]string, len(regs))
	for i, reg := range regs {
		names[i] = reg.Name
	}
	return strings.Join(names, "\x00")
}

// projection returns rule i's projection for a binder evaluating against
// chain. A profile reaches the request path only through a compiler that
// projects it, so a missing projection, or one built against a different
// chain, means the collection and the resolver were wired differently: that
// fails the request closed rather than handing one filter another's
// configuration.
func (sp *Profile) projection(i int, chain string) (RuleProjection, error) {
	if len(sp.Projections) != len(sp.Rules) {
		return RuleProjection{}, fmt.Errorf("profile %q was not projected against the filter chain",
			sp.ResourceName())
	}
	if sp.projectedAgainst != chain {
		return RuleProjection{}, fmt.Errorf(
			"profile %q was projected against a different filter chain than the resolver evaluates",
			sp.ResourceName())
	}
	return sp.Projections[i], nil
}

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
	if a := rule.Actions.HTTPCallout; a != nil {
		raw, err := httpCalloutPayload(a)
		if err != nil {
			return nil, fmt.Errorf("build httpCallout payload: %w", err)
		}
		m[httpcallout.FilterName] = raw
	}
	// Disabled is absorbed here: an open payload map expresses "off" by
	// omitting the key, so a disabled action simply produces no payload.
	if a := rule.Actions.TokenTransformation; a != nil && !a.Disabled {
		if a.Type == v1alpha1.TokenTransformationTypeOAuth2 {
			raw, err := oauth2Payload(a)
			if err != nil {
				return nil, fmt.Errorf("build OAuth2 payload: %w", err)
			}
			m[oauth2.FilterName] = raw
			return m, nil
		}
		if a.OAuth2 != nil {
			return nil, fmt.Errorf("oauth2 configuration requires the OAuth2 transformation type")
		}
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
	ref, err := NormalizeCredentialRef(a.CredentialRef)
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
