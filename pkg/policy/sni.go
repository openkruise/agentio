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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// CompiledSNIPolicy is the SNI specialization of the shared compiled policy.
type CompiledSNIPolicy = CompiledPolicy[*extensionsv1.SniTrafficPolicy]

// CompileSNIProfile compiles one profile; profiles with no HTTPS-capable hosts return nil, nil.
func CompileSNIProfile(profile model.SecurityProfile) (*CompiledSNIPolicy, error) {
	payload, err := CompileSNIRules(profile.Spec.Rules)
	if err != nil {
		return nil, fmt.Errorf("security profile %s: %w", profile.ResourceName(), err)
	}
	if payload == nil {
		return nil, nil
	}
	if profile.Dedicated {
		if strings.TrimSpace(profile.SandboxUID) == "" {
			return nil, fmt.Errorf("dedicated security profile requires a Sandbox UID")
		}
		compiled := &CompiledSNIPolicy{Name: profile.ResourceName(), Policy: payload}
		if profile.Name != "" && profile.Namespace != "" {
			attachment, err := NewPolicyAttachment(PolicyAttachment{
				Kind:   PolicyKindSNIPolicy,
				Name:   profile.ResourceName(),
				Target: AttachmentTarget{Namespaces: []string{profile.Namespace}, PodName: profile.Name},
			})
			if err != nil {
				return nil, err
			}
			compiled.Attachment = &attachment
		}
		return compiled, nil
	}
	priority := agentsv1alpha1.DefaultSecurityProfilePriority
	if profile.Spec.Priority != nil {
		priority = *profile.Spec.Priority
	}
	if priority < 0 {
		return nil, fmt.Errorf("security profile %s priority %d is negative", profile.ResourceName(), priority)
	}
	selector, err := metav1.LabelSelectorAsSelector(&profile.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("security profile %s selector: %w", profile.ResourceName(), err)
	}
	resourceName := profile.Name
	if !profile.Global {
		resourceName = profile.Namespace + "/" + profile.Name
	}
	target := AttachmentTarget{Selector: profile.Spec.Selector}
	if profile.Global {
		target.Global = true
	} else {
		target.Namespaces = []string{profile.Namespace}
	}
	attachment, err := NewPolicyAttachment(PolicyAttachment{
		Kind:            PolicyKindSNIPolicy,
		Name:            resourceName,
		Target:          target,
		Priority:        priority,
		CreationTime:    profile.CreationTime,
		SourceName:      profile.Name,
		SourceNamespace: profile.Namespace,
		selector:        selector,
	})
	if err != nil {
		return nil, err
	}
	return &CompiledSNIPolicy{
		Name:       resourceName,
		Attachment: &attachment,
		Policy:     payload,
	}, nil
}

// CompileSNIRules projects HTTPS-capable security matches into SNI termination rules.
// Sandbox-owned rules and shared SecurityProfiles use the same projection.
func CompileSNIRules(rules []agentsv1alpha1.SecurityRule) (*extensionsv1.SniTrafficPolicy, error) {
	hosts, err := sniHosts(rules)
	if err != nil || len(hosts) == 0 {
		return nil, err
	}
	return &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{{
		Match:  &extensionsv1.SniMatch{Sni: hosts},
		Action: extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION,
	}}}, nil
}

func sniHosts(rules []agentsv1alpha1.SecurityRule) ([]string, error) {
	seen := sets.New[string]()
	result := make([]string, 0)
	for ruleIndex, rule := range rules {
		for matchIndex, match := range rule.Match {
			if !mayMatchHTTPS(match.Schemes) {
				continue
			}
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
				result = append(result, normalized)
			}
		}
	}
	return result, nil
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
