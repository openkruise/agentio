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
	"slices"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// CompiledTrafficPolicy contains native rules and their shared-policy attachment.
type CompiledTrafficPolicy struct {
	CompiledPolicy[*securityv1.TrafficPolicy]

	// Legacy compatibility projection, compiled once per shared source.
	AsAuthorization []CompiledAuthorization
}

// Equals compares native policy output and its legacy authorization projection.
func (p CompiledTrafficPolicy) Equals(other CompiledTrafficPolicy) bool {
	return p.CompiledPolicy.Equals(other.CompiledPolicy) &&
		slices.EqualFunc(p.AsAuthorization, other.AsAuthorization, CompiledAuthorization.Equals)
}

// CompileTrafficPolicy preserves rule actions and both directions in one
// payload with shared-policy attachment metadata.
func CompileTrafficPolicy(
	ctx krt.HandlerContext,
	source model.TrafficPolicy,
	inputs TrafficPolicyInputs,
) (*CompiledTrafficPolicy, error) {
	selector, err := metav1.LabelSelectorAsSelector(&source.Spec.Selector)
	if err != nil {
		return nil, err
	}
	if source.Spec.Priority < 0 {
		return nil, fmt.Errorf("traffic policy %s requires a nonnegative priority", source.ResourceName())
	}
	name := "namespaces/" + source.Namespace + "/trafficPolicies/" + source.Name
	peerNamespace := source.Namespace
	target := AttachmentTarget{Selector: source.Spec.Selector}
	if source.Global {
		name = "trafficPolicies/" + source.Name
		peerNamespace = inputs.RootNamespace
	}
	switch {
	case source.Global || (peerNamespace == inputs.RootNamespace && selector.Empty()):
		// Keep selector-less root-namespace baselines mesh-wide in both APIs.
		target.Global = true
	default:
		target.Namespaces = []string{source.Namespace}
	}
	result, err := CompileTrafficPolicyRules(ctx, model.TrafficPolicyRules{
		Ingress: source.Spec.Ingress,
		Egress:  source.Spec.Egress,
	}, peerNamespace, inputs)
	if err != nil {
		return nil, err
	}
	attachment, err := NewPolicyAttachment(PolicyAttachment{
		Kind:            PolicyKindTrafficPolicy,
		Name:            name,
		UID:             source.UID,
		Target:          target,
		Priority:        source.Spec.Priority,
		CreationTime:    source.CreationTime,
		SourceName:      source.Name,
		SourceNamespace: source.Namespace,
		selector:        selector,
	})
	if err != nil {
		return nil, err
	}
	compiled := &CompiledTrafficPolicy{
		CompiledPolicy: CompiledPolicy[*securityv1.TrafficPolicy]{Name: name, Policy: result, Attachment: &attachment},
	}
	return compiled, nil
}

// CompileTrafficPolicyRules compiles rule bodies without resource identity or
// binding metadata.
func CompileTrafficPolicyRules(
	ctx krt.HandlerContext,
	rules model.TrafficPolicyRules,
	namespace string,
	inputs TrafficPolicyInputs,
) (*securityv1.TrafficPolicy, error) {
	if err := inputs.validate(); err != nil {
		return nil, err
	}
	result := &securityv1.TrafficPolicy{}
	var err error
	if result.Ingress, err = compileNativeDirection(ctx, rules.Ingress, namespace, inputs, true); err != nil {
		return nil, err
	}
	if result.Egress, err = compileNativeDirection(ctx, rules.Egress, namespace, inputs, false); err != nil {
		return nil, err
	}
	return result, nil
}

func compileNativeDirection(
	ctx krt.HandlerContext,
	direction *agentsv1alpha1.TrafficPolicyDirection,
	namespace string,
	inputs TrafficPolicyInputs,
	ingress bool,
) (*securityv1.TrafficPolicy_RuleSet, error) {
	if direction == nil {
		return nil, nil
	}
	var result *securityv1.TrafficPolicy_RuleSet
	for _, rule := range direction.Rules {
		// Egress requires To peers and ingress requires From peers, even for port-only rules.
		// A direction containing only skipped rules does not configure default deny.
		peers := rule.To
		if ingress {
			peers = rule.From
		}
		if len(peers) == 0 {
			continue
		}
		action := securityv1.TrafficPolicy_ALLOW
		switch rule.Action {
		case agentsv1alpha1.RuleActionAllow:
		case agentsv1alpha1.RuleActionReject:
			action = securityv1.TrafficPolicy_DENY
		default:
			return nil, fmt.Errorf("unsupported traffic rule action %q", rule.Action)
		}
		ports, err := compileNativePorts(rule.Ports)
		if err != nil {
			return nil, err
		}
		// Preserve a configured direction even when its declared peers resolve to
		// no addresses: those rules do not match, but default deny still applies.
		if result == nil {
			result = &securityv1.TrafficPolicy_RuleSet{}
		}
		addresses := resolvePeers(ctx, peers, namespace, inputs)
		if len(addresses) == 0 {
			continue
		}
		match := &securityv1.TrafficPolicy_Match{Ports: ports}
		if ingress {
			match.SourceIps = nativeAddresses(addresses)
		} else {
			match.DestinationIps = nativeAddresses(addresses)
		}
		result.Rules = append(result.Rules, &securityv1.TrafficPolicy_Rule{
			Action: action,
			Match:  match,
		})
	}
	return result, nil
}

func compileNativePorts(ports []agentsv1alpha1.TrafficPolicyPort) ([]*securityv1.TrafficPolicy_PortMatch, error) {
	result := make([]*securityv1.TrafficPolicy_PortMatch, 0, len(ports))
	for _, port := range ports {
		// Preserve the existing compiler's default ALL for an omitted protocol.
		protocol := securityv1.TrafficPolicy_ALL
		switch strings.ToUpper(port.Protocol) {
		case "":
		case "TCP":
			protocol = securityv1.TrafficPolicy_TCP
		case "UDP":
			protocol = securityv1.TrafficPolicy_UDP
		case "ICMP":
			protocol = securityv1.TrafficPolicy_ICMP
		case "SCTP":
			protocol = securityv1.TrafficPolicy_SCTP
		default:
			return nil, fmt.Errorf("unsupported traffic protocol %q", port.Protocol)
		}
		match := &securityv1.TrafficPolicy_PortMatch{Protocol: protocol}
		for _, value := range []*int32{port.Port, port.EndPort} {
			if value != nil && (*value < 1 || *value > 65535) {
				return nil, fmt.Errorf("traffic port %d is outside 1..65535", *value)
			}
		}
		if port.Port != nil {
			value := uint32(*port.Port)
			match.Port = &value
		}
		if port.EndPort != nil {
			value := uint32(*port.EndPort)
			match.EndPort = &value
		}
		if port.Port != nil && port.EndPort != nil && *port.Port > *port.EndPort {
			return nil, fmt.Errorf("traffic port range has reversed bounds")
		}
		if match.Protocol == securityv1.TrafficPolicy_ICMP && (match.Port != nil || match.EndPort != nil) {
			return nil, fmt.Errorf("ICMP cannot have port constraints")
		}
		result = append(result, match)
	}
	return result, nil
}

// nativeAddresses adapts the shared peer resolver's result to the native API.
func nativeAddresses(addresses []*securityv1.Address) []*securityv1.TrafficPolicy_Address {
	result := make([]*securityv1.TrafficPolicy_Address, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, &securityv1.TrafficPolicy_Address{
			Address: append([]byte(nil), address.Address...),
			Length:  address.Length,
		})
	}
	return result
}
