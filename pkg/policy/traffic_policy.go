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
	"sort"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// HostnameResolver resolves one hostname while registering any krt dependency
// carried by ctx. Production resolvers use a hostname-keyed DNS collection;
// tests may provide an in-memory implementation.
type HostnameResolver func(krt.HandlerContext, string) []netip.Addr

// CompiledAuthorization is the authorization specialization of the shared compiled policy.
type CompiledAuthorization = CompiledPolicy[*securityv1.Authorization]

// TrafficPolicyInputs carries the collections and indexes a TrafficPolicy uses to resolve peers.
type TrafficPolicyInputs struct {
	RootNamespace string

	Services       krt.Collection[*corev1.Service]
	EndpointSlices krt.Collection[*discoveryv1.EndpointSlice]
	Pods           krt.Collection[*corev1.Pod]

	ServicesByNamespace     krt.Index[string, *corev1.Service]
	EndpointSlicesByService krt.Index[string, *discoveryv1.EndpointSlice]
	PodsByNamespace         krt.Index[string, *corev1.Pod]

	Resolve HostnameResolver
}

// validate reports missing collections up front.
func (i TrafficPolicyInputs) validate() error {
	switch {
	case i.Services == nil || i.ServicesByNamespace == nil:
		return fmt.Errorf("Kubernetes Service collection and namespace index are required")
	case i.EndpointSlices == nil || i.EndpointSlicesByService == nil:
		return fmt.Errorf("EndpointSlice collection and service index are required")
	case i.Pods == nil || i.PodsByNamespace == nil:
		return fmt.Errorf("Pod collection and namespace index are required")
	}
	return nil
}

// CompileTrafficPolicy compiles one policy into up to two Authorizations, one
// per direction.
func CompileTrafficPolicy(ctx krt.HandlerContext, source model.TrafficPolicy, inputs TrafficPolicyInputs) ([]CompiledAuthorization, error) {
	if err := inputs.validate(); err != nil {
		return nil, err
	}
	sandboxUID, err := policySandboxUID(source.SandboxUID, source.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("traffic policy %s: %w", source.ResourceName(), err)
	}
	source.SandboxUID = sandboxUID
	selector, err := metav1.LabelSelectorAsSelector(&source.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("traffic policy %s selector: %w", source.ResourceName(), err)
	}
	namespace := source.Namespace
	if source.Global {
		namespace = inputs.RootNamespace
	}
	result := make([]CompiledAuthorization, 0, 2)
	if source.Spec.Egress != nil {
		compiled, err := compileTrafficPolicyDirection(ctx, source, namespace, "egress", extensionsv1.TrafficPolicyMode_CLIENT, source.Spec.Egress, selector, inputs)
		if err != nil {
			return nil, err
		}
		result = append(result, compiled)
	}
	if source.Spec.Ingress != nil {
		compiled, err := compileTrafficPolicyDirection(ctx, source, namespace, "ingress", extensionsv1.TrafficPolicyMode_SERVER, source.Spec.Ingress, selector, inputs)
		if err != nil {
			return nil, err
		}
		result = append(result, compiled)
	}
	return result, nil
}

// CompileTrafficPolicies compiles a whole set, ordered deterministically.
func CompileTrafficPolicies(ctx krt.HandlerContext, policies []model.TrafficPolicy, inputs TrafficPolicyInputs) ([]CompiledAuthorization, error) {
	result := make([]CompiledAuthorization, 0, len(policies)*2)
	for _, source := range policies {
		compiled, err := CompileTrafficPolicy(ctx, source, inputs)
		if err != nil {
			return nil, err
		}
		result = append(result, compiled...)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceName() < result[j].ResourceName() })
	return result, nil
}

func compileTrafficPolicyDirection(ctx krt.HandlerContext, source model.TrafficPolicy, namespace, suffix string,
	mode extensionsv1.TrafficPolicyMode, direction *agentsv1alpha1.TrafficPolicyDirection,
	selector labels.Selector, inputs TrafficPolicyInputs,
) (CompiledAuthorization, error) {
	scope := securityv1.Scope_NAMESPACE
	// A selector-less policy in the root namespace applies mesh-wide, like a
	// GlobalTrafficPolicy.
	if source.Global || namespace == inputs.RootNamespace {
		scope = securityv1.Scope_GLOBAL
	}
	if source.SandboxUID != "" || !selector.Empty() {
		scope = securityv1.Scope_WORKLOAD_SELECTOR
	}
	authorization := &securityv1.Authorization{
		Name:      source.Name + "-" + suffix,
		Namespace: namespace,
		Scope:     scope,
		Action:    securityv1.Action_ALLOW,
	}
	for _, rule := range direction.Rules {
		if group := compileTrafficPolicyRule(ctx, rule, namespace, inputs); group != nil {
			authorization.Groups = append(authorization.Groups, group)
		}
	}
	extension, err := newTrafficPolicyExtension(source.Spec.Priority, mode)
	if err != nil {
		return CompiledAuthorization{}, err
	}
	authorization.AuthExtensions = []*securityv1.Extension{extension}
	compiled := CompiledAuthorization{
		Name: authorization.GetNamespace() + "/" + authorization.GetName(), Policy: authorization,
	}
	if scope == securityv1.Scope_WORKLOAD_SELECTOR {
		target := AttachmentTarget{Selector: source.Spec.Selector}
		if source.SandboxUID != "" {
			target.SandboxUID = source.SandboxUID
		} else if source.Global {
			target.Global = true
		} else {
			target.Namespaces = []string{source.Namespace}
		}
		attachment, err := NewPolicyAttachment(PolicyAttachment{
			Kind: PolicyKindAuthorization, Name: compiled.Name, Target: target,
			Priority:     source.Spec.Priority,
			CreationTime: source.CreationTime, SourceName: source.Name,
			SourceNamespace: source.Namespace, selector: selector,
		})
		if err != nil {
			return CompiledAuthorization{}, err
		}
		compiled.Attachment = &attachment
	}
	return compiled, nil
}

func compileTrafficPolicyRule(ctx krt.HandlerContext, rule agentsv1alpha1.TrafficPolicyRule, policyNamespace string, inputs TrafficPolicyInputs) *securityv1.Group {
	negative := rule.Action == agentsv1alpha1.RuleActionReject
	sourceAddresses := resolvePeers(ctx, rule.From, policyNamespace, inputs)
	destinationAddresses := resolvePeers(ctx, rule.To, policyNamespace, inputs)
	sourceUnresolved := len(rule.From) > 0 && len(sourceAddresses) == 0
	destinationUnresolved := len(rule.To) > 0 && len(destinationAddresses) == 0
	if sourceUnresolved || destinationUnresolved {
		// Omit the complete group because an empty non-TCP match can match all.
		// Keep the Authorization and its dependencies, but omit this group so
		// every data-plane path treats the unresolved rule as no-match.
		return nil
	}
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
	appendAddressRule(sourceAddresses, true)
	appendAddressRule(destinationAddresses, false)
	if ranges := compilePortRanges(rule.Ports); len(ranges) > 0 {
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

// Peer resolution keeps Pod readiness and deletion state from removing a
// selected IP from policy control; namespace and labels define the peer set.
func resolvePeers(ctx krt.HandlerContext, peers []agentsv1alpha1.TrafficPolicyPeer, policyNamespace string, inputs TrafficPolicyInputs) []*securityv1.Address {
	result := make([]*securityv1.Address, 0)
	add := func(value string) {
		prefix, err := parsePrefix(value)
		if err != nil {
			return
		}
		result = append(result, &securityv1.Address{Address: prefix.Addr().AsSlice(), Length: uint32(prefix.Bits())})
	}
	for _, peer := range peers {
		switch {
		case peer.CIDR != "":
			add(peer.CIDR)
		case peer.Service != nil:
			namespace := peer.Service.Namespace
			if namespace == "" {
				namespace = policyNamespace
			}
			services := []*corev1.Service(nil)
			if peer.Service.Name == "" || peer.Service.Name == "*" {
				services = krt.Fetch(ctx, inputs.Services,
					krt.FilterIndex(inputs.ServicesByNamespace, namespace))
			} else if service := krt.FetchOne(ctx, inputs.Services,
				krt.FilterKey(namespace+"/"+peer.Service.Name)); service != nil {
				services = append(services, *service)
			}
			for _, service := range services {
				if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != corev1.ClusterIPNone {
					add(service.Spec.ClusterIP)
				}
				for _, slice := range krt.Fetch(ctx, inputs.EndpointSlices,
					krt.FilterIndex(inputs.EndpointSlicesByService, service.Namespace+"/"+service.Name)) {
					if slice.AddressType == discoveryv1.AddressTypeFQDN {
						continue
					}
					for _, endpoint := range slice.Endpoints {
						for _, address := range endpoint.Addresses {
							add(address)
						}
					}
				}
			}
		case peer.FQDN != "":
			resolved := []netip.Addr(nil)
			if inputs.Resolve != nil {
				resolved = inputs.Resolve(ctx, peer.FQDN)
			}
			for _, address := range resolved {
				if address.IsValid() {
					add(address.String())
				}
			}
		case peer.Workload != nil:
			pods := krt.Fetch(ctx, inputs.Pods,
				krt.FilterLabel(peer.Workload.Selector),
				krt.FilterIndex(inputs.PodsByNamespace, peer.Workload.Namespace),
			)
			for _, pod := range pods {
				if len(pod.Status.PodIPs) > 0 {
					for _, address := range pod.Status.PodIPs {
						add(address.IP)
					}
				} else if pod.Status.PodIP != "" {
					add(pod.Status.PodIP)
				}
			}
		}
	}
	return result
}

func parsePrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(address, address.BitLen()), nil
}

func compilePortRanges(ports []agentsv1alpha1.TrafficPolicyPort) []*securityv1.PortRange {
	result := make([]*securityv1.PortRange, 0, len(ports))
	for _, port := range ports {
		if port.Port == nil && port.EndPort == nil && port.Protocol == "" {
			continue
		}
		start, end := uint32(0), uint32(65535)
		if port.Port != nil {
			start = uint32(*port.Port)
			end = start
		}
		if port.EndPort != nil {
			end = uint32(*port.EndPort)
		}
		result = append(result, &securityv1.PortRange{Start: start, End: end, Protocol: parseProtocol(port.Protocol)})
	}
	return result
}

func parseProtocol(value string) securityv1.Protocol {
	switch strings.ToUpper(value) {
	case "TCP":
		return securityv1.Protocol_TCP
	case "UDP":
		return securityv1.Protocol_UDP
	case "ICMP":
		return securityv1.Protocol_ICMP
	case "SCTP":
		return securityv1.Protocol_SCTP
	default:
		return securityv1.Protocol_ALL
	}
}

func newTrafficPolicyExtension(priority int32, mode extensionsv1.TrafficPolicyMode) (*securityv1.Extension, error) {
	config, err := anyFor(&extensionsv1.TrafficPolicyExtension{Priority: priority, Mode: mode})
	if err != nil {
		return nil, err
	}
	return &securityv1.Extension{Name: "traffic-policy", Config: config}, nil
}
