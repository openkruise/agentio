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
	"k8s.io/apimachinery/pkg/util/validation"
	"net/netip"
	"slices"
	"strings"
)

// Policy preserves one source policy's identity and ordered rules. Name is a
// unique key within a Config; adapters should qualify it with namespace and
// resource kind when combining namespaced and global policies.
type Policy struct {
	Name  string
	Rules []Rule
}

// Action is the decision made by a matching destination rule.
type Action string

// Allow and Deny are the possible destination rule decisions.
const (
	Allow Action = "Allow"
	Deny  Action = "Deny"
)

// Rule matches any CIDR or observed FQDN, AND any port range.
// Use 0.0.0.0/0 and/or ::/0 to match all addresses.
// Empty Ports matches every non-zero port.
type Rule struct {
	// SourceIndex preserves the xDS rule ordinal when non-TCP rules are omitted.
	SourceIndex *int
	Action      Action
	CIDRs       []netip.Prefix
	FQDNs       []string
	Ports       []PortRange
}

// PortRange is inclusive. End == 0 means the single port Start.
type PortRange struct {
	Start uint16
	End   uint16
}

// Decision identifies the first matching policy and its zero-based rule index.
// A default decision has PolicyName empty and RuleIndex -1.
type Decision struct {
	Action     Action
	PolicyName string
	RuleIndex  int
}

// Validate checks the policy identity and all destination rules.
func (p Policy) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("policy name is required")
	}
	for i, rule := range p.Rules {
		if err := rule.validate(); err != nil {
			return fmt.Errorf("policy %q rule %d: %w", p.Name, i, err)
		}
	}
	return nil
}

func (r Rule) validate() error {
	if r.Action != Allow && r.Action != Deny {
		return fmt.Errorf("invalid action: %q", r.Action)
	}
	if len(r.CIDRs) == 0 && len(r.FQDNs) == 0 {
		return fmt.Errorf("CIDRs or FQDNs are required")
	}
	for _, name := range r.FQDNs {
		if errors := validation.IsDNS1123Subdomain(name); len(errors) > 0 {
			return fmt.Errorf("invalid destination FQDN %q: %s", name, strings.Join(errors, "; "))
		}
	}
	for _, prefix := range r.CIDRs {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return fmt.Errorf("invalid or IPv4-mapped CIDR: %s", prefix)
		}
	}
	for _, ports := range r.Ports {
		if ports.Start == 0 || ports.last() < ports.Start {
			return fmt.Errorf("invalid port range: %d-%d", ports.Start, ports.End)
		}
	}
	return nil
}

func (p PortRange) last() uint16 {
	if p.End == 0 {
		return p.Start
	}
	return p.End
}

func (r Rule) matches(ip netip.Addr, port uint16, dnsCandidates []string) bool {
	matched := slices.ContainsFunc(dnsCandidates, func(name string) bool {
		return slices.Contains(r.FQDNs, strings.ToLower(strings.TrimSuffix(name, ".")))
	})
	for _, prefix := range r.CIDRs {
		matched = matched || prefix.Contains(ip)
	}
	if !matched {
		return false
	}
	if len(r.Ports) == 0 {
		return true
	}
	for _, ports := range r.Ports {
		if port >= ports.Start && port <= ports.last() {
			return true
		}
	}
	return false
}
