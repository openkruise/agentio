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
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// CompiledAuthorization is the authorization specialization of the shared compiled policy.
type CompiledAuthorization = CompiledPolicy[*securityv1.Authorization]

// TrafficPolicyAsAuthorizations projects a shared policy into the Workload wire
// format. Sandbox inline rules are compiled separately and never enter this path.
func TrafficPolicyAsAuthorizations(
	compiled CompiledTrafficPolicy,
	source model.TrafficPolicy,
	rootNamespace string,
) ([]CompiledAuthorization, error) {
	name, namespace, priority := source.Name, source.Namespace, source.Spec.Priority
	scope := securityv1.Scope_NAMESPACE
	if source.Global {
		namespace = rootNamespace
	}
	if namespace == rootNamespace {
		scope = securityv1.Scope_GLOBAL
	}
	if !selectorEmpty(source.Spec.Selector) {
		scope = securityv1.Scope_WORKLOAD_SELECTOR
	}
	result := make([]CompiledAuthorization, 0, 2)
	for _, direction := range []struct {
		suffix string
		mode   extensionsv1.TrafficPolicyMode
		rules  *securityv1.TrafficPolicy_RuleSet
	}{
		{"egress", extensionsv1.TrafficPolicyMode_CLIENT, compiled.Policy.GetEgress()},
		{"ingress", extensionsv1.TrafficPolicyMode_SERVER, compiled.Policy.GetIngress()},
	} {
		if direction.rules == nil {
			continue
		}
		extension, err := newTrafficPolicyExtension(priority, direction.mode)
		if err != nil {
			return nil, err
		}
		authorization := &securityv1.Authorization{
			Name:           name + "-" + direction.suffix,
			Namespace:      namespace,
			Scope:          scope,
			Action:         securityv1.Action_ALLOW,
			AuthExtensions: []*securityv1.Extension{extension},
		}
		for _, rule := range direction.rules.Rules {
			// Legacy consumers cannot enforce FQDN-only destinations.
			if len(rule.Match.DestinationFqdns) > 0 && len(rule.Match.DestinationIps) == 0 {
				continue
			}
			authorization.Groups = append(authorization.Groups, asAuthorizationGroup(rule))
		}
		result = append(result, CompiledAuthorization{
			Name:   namespace + "/" + authorization.Name,
			Policy: authorization,
		})
	}
	return result, nil
}

// Preserve the legacy negative-match encoding of reject rules.
func asAuthorizationGroup(rule *securityv1.TrafficPolicy_Rule) *securityv1.Group {
	negative := rule.Action == securityv1.TrafficPolicy_DENY
	group := &securityv1.Group{}
	appendAddressRule := func(addresses []*securityv1.Address, source bool) {
		if len(addresses) == 0 {
			return
		}
		match := &securityv1.Match{}
		switch {
		case source && negative:
			match.NotSourceIps = addresses
		case source:
			match.SourceIps = addresses
		case negative:
			match.NotDestinationIps = addresses
		default:
			match.DestinationIps = addresses
		}
		group.Rules = append(group.Rules, &securityv1.Rules{Matches: []*securityv1.Match{match}})
	}
	appendAddressRule(authorizationAddresses(rule.Match.SourceIps), true)
	appendAddressRule(authorizationAddresses(rule.Match.DestinationIps), false)
	if ranges := authorizationPortRanges(rule.Match.Ports); len(ranges) > 0 {
		match := &securityv1.Match{}
		if negative {
			match.NotDestinationPortRanges = ranges
		} else {
			match.DestinationPortRanges = ranges
		}
		group.Rules = append(group.Rules, &securityv1.Rules{Matches: []*securityv1.Match{match}})
	}
	return group
}

func authorizationAddresses(addresses []*securityv1.TrafficPolicy_Address) []*securityv1.Address {
	result := make([]*securityv1.Address, 0, len(addresses))
	for _, address := range addresses {
		// Both projections are immutable, so the address bytes can be shared.
		result = append(result, &securityv1.Address{Address: address.Address, Length: address.Length})
	}
	return result
}

func authorizationPortRanges(ports []*securityv1.TrafficPolicy_PortMatch) []*securityv1.PortRange {
	result := make([]*securityv1.PortRange, 0, len(ports))
	for _, port := range ports {
		// Keep the legacy encoding: omit empty entries and use 0 as an
		// unspecified lower bound, including for protocol-only matches.
		if port.Port == nil && port.EndPort == nil && port.Protocol == securityv1.TrafficPolicy_ALL {
			continue
		}
		start, end := uint32(0), uint32(65535)
		if port.Port != nil {
			start = *port.Port
			end = start
		}
		if port.EndPort != nil {
			end = *port.EndPort
		}
		result = append(
			result,
			&securityv1.PortRange{Start: start, End: end, Protocol: securityv1.Protocol(port.Protocol)},
		)
	}
	return result
}

func newTrafficPolicyExtension(priority int32, mode extensionsv1.TrafficPolicyMode) (*securityv1.Extension, error) {
	config, err := anyFor(&extensionsv1.TrafficPolicyExtension{Priority: priority, Mode: mode})
	if err != nil {
		return nil, err
	}
	return &securityv1.Extension{Name: "traffic-policy", Config: config}, nil
}
