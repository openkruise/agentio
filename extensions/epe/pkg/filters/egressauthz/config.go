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

package egressauthz

import (
	"fmt"
	"net/netip"
)

// Config is an immutable, caller-owned snapshot for one authorization scope.
// The caller validates and orders Policies before publishing a new Config.
// Each authorizer filters its candidate set against one immutable configuration.
// Slices and nested rules must not be mutated after publication.
type Config struct {
	// DeniedCIDRs are global restrictions checked before workload policies.
	DeniedCIDRs []netip.Prefix
	Policies    []Policy
}

// Validate checks the complete snapshot without modifying or sorting it.
// The zero Config is valid and imposes no policy restriction.
func (c Config) Validate() error {
	for _, prefix := range c.DeniedCIDRs {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return fmt.Errorf("invalid or IPv4-mapped denied CIDR: %s", prefix)
		}
	}
	names := make(map[string]struct{}, len(c.Policies))
	for _, policy := range c.Policies {
		if _, exists := names[policy.Name]; exists {
			return fmt.Errorf("duplicate policy name: %q", policy.Name)
		}
		if err := policy.Validate(); err != nil {
			return err
		}
		names[policy.Name] = struct{}{}
	}
	return nil
}

// Evaluate traverses a validated snapshot in policy order and then rule order.
// Global denies take precedence. Otherwise the first policy match decides.
// No policies means allow; otherwise no match means deny.
func (c Config) Evaluate(address netip.AddrPort, dnsCandidates ...string) Decision {
	unmatched := Decision{Action: Deny, RuleIndex: -1}
	if !address.IsValid() || address.Port() == 0 || address.Addr().Zone() != "" {
		return unmatched
	}
	ip, port := address.Addr().Unmap(), address.Port()
	for i, prefix := range c.DeniedCIDRs {
		if prefix.Contains(ip) {
			return Decision{Action: Deny, PolicyName: "EPEConfig/egressAuthorization", RuleIndex: i}
		}
	}
	if len(c.Policies) == 0 {
		return Decision{Action: Allow, RuleIndex: -1}
	}
	for _, policy := range c.Policies {
		for i, rule := range policy.Rules {
			if rule.matches(ip, port, dnsCandidates) {
				if rule.SourceIndex != nil {
					i = *rule.SourceIndex
				}
				return Decision{Action: rule.Action, PolicyName: policy.Name, RuleIndex: i}
			}
		}
	}
	return unmatched
}
