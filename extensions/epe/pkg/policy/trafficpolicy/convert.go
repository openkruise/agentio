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

// Package trafficpolicy projects compiled TrafficPolicy resources into EPE snapshots.
package trafficpolicy

import (
	"fmt"
	"net/netip"
	"strings"

	sec "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
)

var allIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// Compile preserves Workload reference order and declaration order. EPE handles
// HTTP/CONNECT TCP traffic; rules for other protocols cannot authorize it.
// Workload bindings select applicable policies; egress matches only destinations.
func Compile(policies []NamedPolicy) (egressauthz.Config, error) {
	cfg := egressauthz.Config{}
	for _, p := range policies {
		if p.Policy == nil {
			return cfg, fmt.Errorf("TrafficPolicy %q is missing", p.Name)
		}
		out := egressauthz.Policy{Name: p.Name}
		for i, r := range p.Policy.GetEgress().GetRules() {
			if r == nil || r.Match == nil {
				return cfg, fmt.Errorf("TrafficPolicy %q egress rule %d: missing match", p.Name, i)
			}
			rule := egressauthz.Rule{Action: egressauthz.Allow, SourceIndex: &i}
			switch r.Action {
			case sec.TrafficPolicy_ALLOW:
			case sec.TrafficPolicy_DENY:
				rule.Action = egressauthz.Deny
			default:
				return cfg, fmt.Errorf("TrafficPolicy %q egress rule %d: invalid action %d", p.Name, i, r.Action)
			}
			destinations, err := prefixes(r.Match.DestinationIps)
			if err != nil {
				return cfg, fmt.Errorf("TrafficPolicy %q egress rule %d destinations: %w", p.Name, i, err)
			}
			ports, err := tcpPorts(r.Match.Ports)
			if err != nil {
				return cfg, fmt.Errorf("TrafficPolicy %q egress rule %d ports: %w", p.Name, i, err)
			}
			if len(r.Match.Ports) > 0 && len(ports) == 0 {
				continue
			}
			for _, name := range r.Match.DestinationFqdns {
				rule.FQDNs = append(rule.FQDNs, strings.ToLower(strings.TrimSuffix(name, ".")))
			}
			rule.CIDRs = destinations
			if len(destinations) == 0 && len(rule.FQDNs) == 0 {
				rule.CIDRs = append([]netip.Prefix(nil), allIPs...)
			}
			rule.Ports = ports
			out.Rules = append(out.Rules, rule)
		}
		cfg.Policies = append(cfg.Policies, out)
	}
	return cfg, cfg.Validate()
}

func prefixes(values []*sec.TrafficPolicy_Address) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		if v == nil {
			return nil, fmt.Errorf("nil address")
		}
		ip, ok := netip.AddrFromSlice(v.Address)
		if !ok || ip.Is4In6() || v.Length > uint32(ip.BitLen()) {
			return nil, fmt.Errorf("invalid address prefix")
		}
		out = append(out, netip.PrefixFrom(ip, int(v.Length)).Masked())
	}
	return out, nil
}

func tcpPorts(values []*sec.TrafficPolicy_PortMatch) ([]egressauthz.PortRange, error) {
	out := []egressauthz.PortRange{}
	for _, p := range values {
		if p == nil {
			return nil, fmt.Errorf("nil port match")
		}
		if _, ok := sec.TrafficPolicy_Protocol_name[int32(p.Protocol)]; !ok {
			return nil, fmt.Errorf("unknown protocol %d", p.Protocol)
		}
		start, end := uint32(1), uint32(65535)
		if p.Port != nil {
			start = *p.Port
			end = start
		}
		if p.EndPort != nil {
			end = *p.EndPort
		}
		if start == 0 || end == 0 || start > 65535 || end > 65535 || start > end {
			return nil, fmt.Errorf("invalid port range %d-%d", start, end)
		}
		if p.Protocol == sec.TrafficPolicy_ICMP && (p.Port != nil || p.EndPort != nil) {
			return nil, fmt.Errorf("ICMP cannot constrain ports")
		}
		if p.Protocol == sec.TrafficPolicy_ALL || p.Protocol == sec.TrafficPolicy_TCP {
			out = append(out, egressauthz.PortRange{Start: uint16(start), End: uint16(end)})
		}
	}
	return out, nil
}
