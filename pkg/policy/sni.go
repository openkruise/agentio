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

package policy

import (
	"fmt"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
)

// CompileSNIRules projects TLS and HTTPS-capable HTTP rules in source order.
// Sandbox-owned rules and shared SecurityProfiles use the same projection.
func CompileSNIRules(rules []agentsv1alpha1.SecurityRule) (*extensionsv1.SniTrafficPolicy, error) {
	var result *extensionsv1.SniTrafficPolicy
	for ruleIndex, rule := range rules {
		if err := ValidateTLSRule(rule); err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", ruleIndex, err)
		}
		action := extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION
		if rule.Actions.TLS != nil {
			switch rule.Actions.TLS.Action {
			case agentsv1alpha1.TLSActionDeny:
				action = extensionsv1.SniAction_SNI_ACTION_DENY
			case agentsv1alpha1.TLSActionPassthrough:
				action = extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH
			}
		}
		for matchIndex, match := range rule.Match {
			if rule.Actions.TLS == nil && !mayMatchHTTPS(match.Schemes) {
				continue
			}
			seen := sets.New[string]()
			matched := &extensionsv1.SniMatch{}
			for domainIndex, domain := range match.Domains {
				normalized, err := normalizeSNI(domain)
				if err != nil {
					return nil, fmt.Errorf("rules[%d].match[%d].domains[%d]: %w",
						ruleIndex, matchIndex, domainIndex, err)
				}
				if seen.Contains(normalized) {
					continue
				}
				seen.Insert(normalized)
				matched.Sni = append(matched.Sni, normalized)
			}
			for _, port := range match.Ports {
				if port < 1 || port > 65535 {
					return nil, fmt.Errorf("rules[%d].match[%d]: invalid destination port %d", ruleIndex, matchIndex, port)
				}
				matched.Ports = append(matched.Ports, uint32(port))
			}
			if len(matched.Sni) == 0 {
				continue
			}
			if result == nil {
				result = &extensionsv1.SniTrafficPolicy{}
			}
			result.Rules = append(result.Rules, &extensionsv1.SniRule{Match: matched, Action: action})
		}
	}
	return result, nil
}

// ValidateTLSRule enforces the connection-only contract for CRDs and inline rules.
func ValidateTLSRule(rule agentsv1alpha1.SecurityRule) error {
	actions := rule.Actions
	if actions.TLS == nil {
		return nil
	}
	if actions.TLS.Action != agentsv1alpha1.TLSActionDeny && actions.TLS.Action != agentsv1alpha1.TLSActionPassthrough {
		return fmt.Errorf("invalid TLS action %q", actions.TLS.Action)
	}
	if actions.Bypass || actions.Block != nil || actions.MCPToolPolicy != nil ||
		actions.HeaderManipulation != nil || actions.HTTPCallout != nil ||
		actions.TokenTransformation != nil || len(actions.Audit) > 0 {
		return fmt.Errorf("TLS action cannot be combined with HTTP actions or rule audit")
	}
	if len(rule.Match) == 0 {
		return fmt.Errorf("TLS rule requires a match")
	}
	for i, match := range rule.Match {
		if len(match.Domains) == 0 {
			return fmt.Errorf("match[%d]: TLS rule requires domains", i)
		}
		if len(match.Paths) > 0 || len(match.Methods) > 0 || len(match.Schemes) > 0 ||
			len(match.Headers) > 0 || len(match.QueryParams) > 0 {
			return fmt.Errorf("match[%d]: TLS rule only supports domains and ports", i)
		}
		for _, port := range match.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("match[%d]: invalid destination port %d", i, port)
			}
		}
	}
	return nil
}

func mayMatchHTTPS(schemes []string) bool {
	if len(schemes) == 0 {
		return true
	}
	for _, scheme := range schemes {
		if strings.EqualFold(scheme, "https") {
			return true
		}
	}
	return false
}

func normalizeSNI(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSuffix(value, "."))
	if normalized == "" || strings.HasSuffix(normalized, ".") {
		return "", fmt.Errorf("invalid SNI value %q", value)
	}
	if normalized == "*" {
		return normalized, nil
	}
	if strings.Contains(normalized, "*") {
		rest, ok := strings.CutPrefix(normalized, "*.")
		if !ok || strings.Contains(rest, "*") || len(validation.IsDNS1123Subdomain(rest)) > 0 {
			return "", fmt.Errorf("wildcard must be the complete leftmost label in %q", value)
		}
		return normalized, nil
	}
	if problems := validation.IsDNS1123Subdomain(normalized); len(problems) > 0 {
		return "", fmt.Errorf("invalid DNS name %q: %s", value, strings.Join(problems, "; "))
	}
	return normalized, nil
}
