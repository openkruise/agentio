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

package kruise

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/policy"
)

// Sandbox policy annotations contain complete native and E2B configuration snapshots.
const (
	AnnotationSecurityProfile = "agents.kruise.io/security-profile"
	AnnotationE2BNetwork      = "agents.kruise.io/e2b-network"
)

// SandboxSecurityProfile combines the Sandbox policy annotations into one profile.
func SandboxSecurityProfile(sandbox metav1.Object) (*agents.SecurityProfileSpec, error) {
	a := sandbox.GetAnnotations()
	var result *agents.SecurityProfileSpec
	legacyRules, legacy := a[agents.AnnotationSecurityRules]
	if raw, found := a[AnnotationSecurityProfile]; found {
		if legacy {
			return nil, fmt.Errorf(
				"%s and %s are mutually exclusive",
				agents.AnnotationSecurityRules,
				AnnotationSecurityProfile,
			)
		}
		// Decode only the inline fields: selection and identity belong to the Sandbox.
		var spec *struct {
			Rules    []agents.SecurityRule         `json:"rules,omitempty"`
			TCPRules []agents.TCPRule              `json:"tcpRules,omitempty"`
			Inputs   []agents.SecurityProfileInput `json:"inputs,omitempty"`
			Audit    []agents.AuditAction          `json:"audit,omitempty"`
		}
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&spec); err != nil {
			return nil, fmt.Errorf("decode %s: %w", AnnotationSecurityProfile, err)
		}
		if spec == nil || !json.Valid([]byte(raw)) {
			return nil, fmt.Errorf("%s must contain a single JSON object", AnnotationSecurityProfile)
		}
		result = &agents.SecurityProfileSpec{
			Rules:    spec.Rules,
			TCPRules: spec.TCPRules,
			Inputs:   spec.Inputs,
			Audit:    spec.Audit,
		}
		if err := validateSandboxProfile(sandbox.GetNamespace(), result); err != nil {
			return nil, err
		}
	} else if legacyRules != "" {
		rules, err := sandboxSecurityRules(sandbox)
		if err != nil {
			return nil, err
		}
		result = &agents.SecurityProfileSpec{Rules: rules}
	}
	if raw, found := a[AnnotationE2BNetwork]; found {
		profile, err := e2bProfile(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", AnnotationE2BNetwork, err)
		}
		if result == nil {
			return profile, nil
		}
		result.Rules = append(result.Rules, profile.Rules...)
		result.TCPRules = append(result.TCPRules, profile.TCPRules...)
	}
	return result, nil
}

func validateSandboxProfile(namespace string, spec *agents.SecurityProfileSpec) error {
	for _, input := range spec.Inputs {
		if input.ConfigMap != nil && input.ConfigMap.Namespace != "" && input.ConfigMap.Namespace != namespace {
			return fmt.Errorf("inline ConfigMap input %q must use the Sandbox namespace", input.Name)
		}
	}
	for _, rule := range spec.Rules {
		if len(rule.Match) == 0 {
			return fmt.Errorf("inline rule %q requires a match", rule.Name)
		}
		for i, match := range rule.Match {
			if len(match.Domains) == 0 {
				return fmt.Errorf("inline rule %q match[%d] requires domains", rule.Name, i)
			}
		}
		if action := rule.Actions.TokenTransformation; action != nil {
			ref := action.CredentialRef
			if ref.Secret != nil || ref.Kind == agents.CredentialRefKindSecret {
				return fmt.Errorf("inline token credentials require an authorized CredentialProvider, not a Secret")
			}
		}
	}
	return nil
}

type e2bNetwork struct {
	AllowInternetAccess *bool `json:"allowInternetAccess"`
	Network             struct {
		EgressProxy json.RawMessage `json:"egressProxy"`
		AllowOut    []string        `json:"allowOut"`
		DenyOut     []string        `json:"denyOut"`
		DNSServers  *[]string       `json:"dnsServers"`
		Rules       map[string][]struct {
			Transform struct {
				Headers map[string]string `json:"headers"`
			} `json:"transform"`
		} `json:"rules"`
	} `json:"network"`
}

func e2bProfile(raw string) (*agents.SecurityProfileSpec, error) {
	var config *e2bNetwork
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("network configuration must be a JSON object")
	}
	if len(config.Network.EgressProxy) > 0 && string(config.Network.EgressProxy) != "null" {
		return nil, fmt.Errorf("egressProxy is not supported by the Agentio E2B conversion")
	}
	rules, err := e2bHeaderRules(config)
	if err != nil {
		return nil, err
	}
	spec := &agents.SecurityProfileSpec{Rules: rules}
	var allowDomains []string
	var allowIPs []string
	for _, value := range config.Network.AllowOut {
		if _, err := netip.ParseAddr(value); err == nil {
			allowIPs = append(allowIPs, value)
			continue
		}
		if _, err := netip.ParsePrefix(value); err == nil {
			allowIPs = append(allowIPs, value)
			continue
		}
		domain, err := policy.NormalizeDomain(value)
		if err != nil {
			return nil, err
		}
		allowDomains = append(allowDomains, domain)
	}
	if len(allowDomains) > 0 {
		dns := []string{"8.8.8.8"}
		if config.Network.DNSServers != nil {
			dns = *config.Network.DNSServers
		}
		for _, value := range dns {
			ip, err := netip.ParseAddr(value)
			if err != nil || !ip.Is4() {
				return nil, fmt.Errorf("invalid IPv4 DNS server %q", value)
			}
			allowIPs = append(allowIPs, value)
		}
		spec.Rules = append(
			spec.Rules,
			agents.SecurityRule{
				Name:    "agentio-e2b-allow-tls",
				Match:   []agents.RuleMatch{{Domains: allowDomains}},
				Actions: agents.SecurityRuleActions{TLS: &agents.TLSAction{Action: agents.TLSActionPassthrough}},
			},
			agents.SecurityRule{
				Name:    "agentio-e2b-allow-web",
				Match:   []agents.RuleMatch{{Domains: allowDomains, Schemes: []string{"http", "https"}}},
				Actions: agents.SecurityRuleActions{Bypass: true},
			},
		)
	}
	if len(allowIPs) > 0 {
		spec.TCPRules = append(
			spec.TCPRules,
			agents.TCPRule{
				Name:   "agentio-e2b-allow-addresses",
				Match:  []agents.TCPMatch{{CIDRs: allowIPs}},
				Action: agents.TCPActionAllow,
			},
		)
	}
	if len(config.Network.DenyOut) > 0 {
		rule := agents.TCPRule{
			Name:   "agentio-e2b-deny-addresses",
			Match:  []agents.TCPMatch{{CIDRs: config.Network.DenyOut}},
			Action: agents.TCPActionDeny,
		}
		if _, err := policy.CompileTCPRules([]agents.TCPRule{rule}); err != nil {
			return nil, err
		}
		spec.TCPRules = append(spec.TCPRules, rule)
	}
	if config.AllowInternetAccess != nil && !*config.AllowInternetAccess {
		spec.TCPRules = append(
			spec.TCPRules,
			agents.TCPRule{Name: "agentio-e2b-deny-rest", Match: []agents.TCPMatch{{}}, Action: agents.TCPActionDeny},
		)
	}
	return spec, nil
}

func e2bHeaderRules(config *e2bNetwork) ([]agents.SecurityRule, error) {
	// Run broader transforms first so more specific rules can override the same header.
	domains := make([]string, 0, len(config.Network.Rules))
	for domain := range config.Network.Rules {
		domains = append(domains, domain)
	}
	slices.SortFunc(domains, func(a, b string) int {
		aw, bw := strings.HasPrefix(a, "*."), strings.HasPrefix(b, "*.")
		if aw != bw {
			if bw {
				return 1
			}
			return -1
		}
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return strings.Compare(a, b)
	})
	seen := map[string]bool{}
	var rules []agents.SecurityRule
	for _, domain := range domains {
		normalized, err := policy.NormalizeDomain(domain)
		if err != nil {
			return nil, err
		}
		if normalized == "*" || seen[normalized] {
			return nil, fmt.Errorf("invalid or duplicate transform domain %q", domain)
		}
		seen[normalized] = true
		headers := map[string]string{}
		for _, operation := range config.Network.Rules[domain] {
			names := make([]string, 0, len(operation.Transform.Headers))
			for name := range operation.Transform.Headers {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				headers[strings.ToLower(name)] = operation.Transform.Headers[name]
			}
		}
		names := make([]string, 0, len(headers))
		for name := range headers {
			names = append(names, name)
		}
		slices.Sort(names)
		mutation := &agents.HeaderManipulationAction{}
		for _, name := range names {
			mutation.Set = append(mutation.Set, agents.HeaderValue{Name: name, Value: headers[name]})
		}
		if len(mutation.Set) == 0 {
			// shortcut: reject empty transform sets until SNI selection can express wildcard exclusions.
			return nil, fmt.Errorf("transform domain %q requires at least one header assignment", domain)
		}
		rules = append(rules, agents.SecurityRule{
			Name:    fmt.Sprintf("agentio-e2b-transform-%d", len(rules)),
			Match:   []agents.RuleMatch{{Domains: []string{normalized}, Schemes: []string{"https"}}},
			Actions: agents.SecurityRuleActions{HeaderManipulation: mutation},
		})
	}
	return rules, nil
}
