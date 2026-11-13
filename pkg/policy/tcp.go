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
	"net/netip"
	"slices"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
)

// CompileTCPRules validates and normalizes the inline gateway destination chain.
func CompileTCPRules(rules []agents.TCPRule) (*securityv1.TCPPolicy, error) {
	result := &securityv1.TCPPolicy{}
	for _, rule := range rules {
		out := &securityv1.TCPRule{Name: rule.Name}
		switch rule.Action {
		case agents.TCPActionAllow:
			out.Action = securityv1.TCPAction_TCP_ACTION_ALLOW
		case agents.TCPActionDeny:
			out.Action = securityv1.TCPAction_TCP_ACTION_DENY
		}
		for _, match := range rule.Match {
			clause := &securityv1.TCPMatch{Cidrs: slices.Clone(match.CIDRs)}
			for _, port := range match.Ports {
				clause.Ports = append(clause.Ports, uint32(port))
			}
			out.Match = append(out.Match, clause)
		}
		result.Rules = append(result.Rules, out)
	}
	if err := NormalizeTCPPolicy(result); err != nil {
		return nil, err
	}
	return result, nil
}

// NormalizeTCPPolicy validates an unpublished policy and canonicalizes its CIDRs.
func NormalizeTCPPolicy(value *securityv1.TCPPolicy) error {
	names := make(map[string]bool, len(value.GetRules()))
	for _, rule := range value.GetRules() {
		if rule.GetName() == "" || names[rule.GetName()] {
			return fmt.Errorf("tcpRules: empty or duplicate name %q", rule.GetName())
		}
		names[rule.Name] = true
		if rule.Action != securityv1.TCPAction_TCP_ACTION_ALLOW && rule.Action != securityv1.TCPAction_TCP_ACTION_DENY {
			return fmt.Errorf("tcpRules %q: invalid action %v", rule.Name, rule.Action)
		}
		if len(rule.Match) == 0 {
			return fmt.Errorf("tcpRules %q: match is required", rule.Name)
		}
		for _, match := range rule.Match {
			if match == nil {
				return fmt.Errorf("tcpRules %q: match is required", rule.Name)
			}
			for i, raw := range match.Cidrs {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil {
					address, err := netip.ParseAddr(raw)
					if err != nil || address.Zone() != "" {
						return fmt.Errorf("tcpRules %q: invalid IP address or CIDR %q", rule.Name, raw)
					}
					prefix = netip.PrefixFrom(address, address.BitLen())
				}
				if prefix.Addr().Is4In6() {
					return fmt.Errorf("tcpRules %q: IPv4-mapped address or CIDR is unsupported %q", rule.Name, raw)
				}
				match.Cidrs[i] = prefix.Masked().String()
			}
			for _, port := range match.Ports {
				if port < 1 || port > 65535 {
					return fmt.Errorf("tcpRules %q: invalid port %d", rule.Name, port)
				}
			}
		}
	}
	return nil
}

// MatchTCPRules evaluates already validated rules; callers concatenate profiles
// before applying the default allow so an unmatched profile cannot end the chain.
func MatchTCPRules(rules []*securityv1.TCPRule, target netip.AddrPort) (allowed bool, index int) {
	for i, rule := range rules {
		for _, match := range rule.Match {
			if len(match.Ports) > 0 && !slices.Contains(match.Ports, uint32(target.Port())) {
				continue
			}
			addressMatches := len(match.Cidrs) == 0
			for _, cidr := range match.Cidrs {
				if netip.MustParsePrefix(cidr).Contains(target.Addr().Unmap()) {
					addressMatches = true
					break
				}
			}
			if addressMatches {
				return rule.Action == securityv1.TCPAction_TCP_ACTION_ALLOW, i
			}
		}
	}
	return true, -1
}
