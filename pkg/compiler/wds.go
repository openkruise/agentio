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

// This file encodes Workload and Service models into WDS Address wire resources.

package compiler

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

// wdsProjection contains the resolved inputs for one WDS Workload projection.
// Callers resolve every KRT dependency into this flat value before encoding.
type wdsProjection struct {
	ClusterID             string
	Workload              model.Workload
	Endpoints             []model.Endpoint
	Services              []model.Service
	SNIPolicy             *extensionsv1.SniTrafficPolicy
	EgressPolicies        *extensionsv1.EgressPolicies
	AuthorizationNames    []string
	TrafficPolicyNames    []string
	SecurityProfileNames  []string
	MetadataConfiguration *workloadMetadataConfiguration
	EgressGatewayKeys     []string
}

// buildWDSAddress compiles one Workload into the canonical Address form
// consumed by ztunnel.
func buildWDSAddress(input wdsProjection) (*model.Resource, error) {
	if err := validateDiscoveredWorkload(input.Workload); err != nil {
		return nil, fmt.Errorf("workload %q: %w", input.Workload.UID, err)
	}
	addresses, aliases, err := parseAddresses(input.Workload.Addresses)
	if err != nil {
		return nil, fmt.Errorf("workload %s addresses: %w", input.Workload.UID, err)
	}
	if len(addresses) == 0 {
		return nil, nil
	}
	trustDomain, serviceAccount, err := projectWorkloadIdentity(input)
	if err != nil {
		return nil, err
	}

	services, serviceKeys := workloadServices(input)

	status := workloadv1.WorkloadStatus_HEALTHY
	if !input.Workload.Ready {
		status = workloadv1.WorkloadStatus_UNHEALTHY
	}
	tunnel := workloadv1.TunnelProtocol_NONE
	if input.Workload.TunnelProtocol == model.TunnelProtocolHBONE {
		tunnel = workloadv1.TunnelProtocol_HBONE
	}
	wireWorkload := &workloadv1.Workload{
		Uid:                   input.Workload.UID,
		AuthorizationPolicies: append([]string(nil), input.AuthorizationNames...),
		Name:                  input.Workload.Name,
		Namespace:             input.Workload.Namespace,
		Addresses:             addresses,
		TunnelProtocol:        tunnel,
		TrustDomain:           trustDomain,
		ServiceAccount:        serviceAccount,
		Node:                  input.Workload.NodeName,
		Services:              services,
		Status:                status,
		ClusterId:             input.ClusterID,
		WorkloadType:          workloadv1.WorkloadType_POD,
		WorkloadName:          input.Workload.Name,
		CanonicalName:         input.Workload.CanonicalName,
		CanonicalRevision:     input.Workload.CanonicalRevision,
		NativeTunnel:          input.Workload.NativeTunnel,
	}
	if input.Workload.HostNetwork {
		wireWorkload.NetworkMode = workloadv1.NetworkMode_HOST_NETWORK
	}
	// Discovery-only workloads without a complete instance identity have no instance alias.
	if source := input.Workload.Source; source.Validate() == nil {
		aliases = append(aliases, source.WorkloadAlias())
	}
	address := &workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: wireWorkload}}
	if input.MetadataConfiguration != nil {
		metadata, err := newWorkloadMetadataExtension(filteredWorkloadLabels(
			input.Workload.Labels, input.MetadataConfiguration.IgnoredLabels))
		if err != nil {
			return nil, fmt.Errorf("marshal metadata for workload %s: %w", input.Workload.UID, err)
		}
		wireWorkload.Extensions = append(wireWorkload.Extensions, metadata)
	}

	// Always publish the native binding, even when empty. Native clients must
	// distinguish no applicable policies from a referenced body not yet received.
	trafficPolicyRefs, err := marshalDeterministicAny(&extensionsv1.PolicyReference{
		TypeUrl:       model.TrafficPolicyType,
		ResourceNames: append([]string(nil), input.TrafficPolicyNames...),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal traffic policy references for workload %s: %w", input.Workload.UID, err)
	}
	wireWorkload.Extensions = append(wireWorkload.Extensions, &workloadv1.Extension{
		Name:   "traffic-policy-reference",
		Config: trafficPolicyRefs,
	})

	config, err := marshalDeterministicAny(&extensionsv1.PolicyReference{
		TypeUrl:       model.SecurityProfileType,
		ResourceNames: append([]string(nil), input.SecurityProfileNames...),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal security profile references for workload %s: %w", input.Workload.UID, err)
	}
	wireWorkload.Extensions = append(wireWorkload.Extensions, &workloadv1.Extension{
		Name:   "security-profile-reference",
		Config: config,
	})

	if input.EgressPolicies != nil {
		config, err := marshalDeterministicAny(input.EgressPolicies)
		if err != nil {
			return nil, fmt.Errorf("marshal egress policies for workload %s: %w", input.Workload.UID, err)
		}
		wireWorkload.Extensions = append(
			wireWorkload.Extensions,
			&workloadv1.Extension{Name: "egress-policies", Config: config},
		)
	}
	if input.SNIPolicy != nil {
		config, err := marshalDeterministicAny(input.SNIPolicy)
		if err != nil {
			return nil, fmt.Errorf("marshal SNI policy for workload %s: %w", input.Workload.UID, err)
		}
		wireWorkload.Extensions = append(wireWorkload.Extensions, &workloadv1.Extension{
			Name:   "sni-traffic-policy",
			Config: config,
		})
	}

	addressValue, err := marshalDeterministicAny(address)
	if err != nil {
		return nil, fmt.Errorf("marshal workload %s: %w", input.Workload.UID, err)
	}
	facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
		TrafficPolicyRefs: append([]string(nil), input.TrafficPolicyNames...),
		AuthorizationRefs: append([]string(nil), input.AuthorizationNames...),
		Namespace:         input.Workload.Namespace,
		WorkloadUID:       input.Workload.UID,
		Source:            input.Workload.Source,
		NodeName:          input.Workload.NodeName,
		Principal:         input.Workload.Principal,
		ServiceKeys:       serviceKeys,
		GatewayReferences: input.EgressGatewayKeys,
	}}
	facts.GatewayOwner = input.Workload.GatewayKey
	addressResource, err := model.NewResource(
		model.ResourceKey{
			TypeURL: model.AddressType,
			Name:    input.Workload.UID,
		}, "", addressValue, aliases, facts)
	if err != nil {
		return nil, err
	}
	return &addressResource, nil
}

func workloadServices(input wdsProjection) (map[string]*workloadv1.PortList, []string) {
	serviceByKey := make(map[string]model.Service, len(input.Services))
	for _, service := range input.Services {
		serviceByKey[service.ResourceName()] = service
	}
	ready := readyWDSEndpoints(input.Endpoints, serviceByKey)

	services := make(map[string]*workloadv1.PortList)
	serviceKeys := make([]string, 0, len(serviceByKey))
	for key := range serviceByKey {
		serviceKeys = append(serviceKeys, key)
	}
	sort.Strings(serviceKeys)
	for _, serviceKey := range serviceKeys {
		service := serviceByKey[serviceKey]
		servicePorts := append([]model.ServicePort(nil), service.Ports...)
		sort.Slice(servicePorts, func(i, j int) bool {
			if servicePorts[i].Port != servicePorts[j].Port {
				return servicePorts[i].Port < servicePorts[j].Port
			}
			if servicePorts[i].Name != servicePorts[j].Name {
				return servicePorts[i].Name < servicePorts[j].Name
			}
			if servicePorts[i].Protocol != servicePorts[j].Protocol {
				return servicePorts[i].Protocol < servicePorts[j].Protocol
			}
			if servicePorts[i].TargetPortName != servicePorts[j].TargetPortName {
				return servicePorts[i].TargetPortName < servicePorts[j].TargetPortName
			}
			return servicePorts[i].TargetPort < servicePorts[j].TargetPort
		})
		ports := &workloadv1.PortList{}
		services[serviceKey] = ports
		for _, servicePort := range servicePorts {
			resolved, ambiguous := resolveWDSServicePort(serviceKey, servicePort, ready)
			if resolved == 0 || ambiguous {
				continue
			}
			ports.Ports = append(ports.Ports, &workloadv1.Port{
				ServicePort: servicePort.Port,
				TargetPort:  resolved,
			})
		}
	}

	return services, serviceKeys
}

func readyWDSEndpoints(endpoints []model.Endpoint, serviceByKey map[string]model.Service) []model.Endpoint {
	ready := make([]model.Endpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		service, found := serviceByKey[endpoint.ServiceKey]
		if endpoint.Ready || (found && service.PublishNotReadyAddresses) {
			ready = append(ready, endpoint)
		}
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].ServiceKey != ready[j].ServiceKey {
			return ready[i].ServiceKey < ready[j].ServiceKey
		}
		if ready[i].PortName != ready[j].PortName {
			return ready[i].PortName < ready[j].PortName
		}
		if ready[i].Protocol != ready[j].Protocol {
			return ready[i].Protocol < ready[j].Protocol
		}
		if ready[i].Port != ready[j].Port {
			return ready[i].Port < ready[j].Port
		}
		return ready[i].ResourceName() < ready[j].ResourceName()
	})

	return ready
}

func resolveWDSServicePort(serviceKey string, servicePort model.ServicePort, ready []model.Endpoint) (uint32, bool) {
	resolved := uint32(0)
	ambiguous := false
	for _, endpoint := range ready {
		if endpoint.ServiceKey != serviceKey || endpoint.PortName != servicePort.Name ||
			normalizedProtocol(endpoint.Protocol) != normalizedProtocol(servicePort.Protocol) || endpoint.Port == 0 {
			continue
		}
		if servicePort.TargetPort > 0 && endpoint.Port != servicePort.TargetPort {
			ambiguous = true
			break
		}
		if resolved != 0 && resolved != endpoint.Port {
			ambiguous = true
			break
		}
		resolved = endpoint.Port
	}
	return resolved, ambiguous
}

// buildWDSService compiles the networking-only Service model into the Service
// variant of a WDS Address resource.
func buildWDSService(service model.Service, gatewayKey string) (model.Resource, error) {
	addresses := make([]*workloadv1.NetworkAddress, 0, len(service.Addresses))
	aliases := make([]string, 0, len(service.Addresses))
	for _, value := range service.Addresses {
		address, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		addresses = append(addresses, &workloadv1.NetworkAddress{
			Network: service.Network,
			Address: address.AsSlice(),
		})
		aliases = append(aliases, addressAlias(service.Network, address.String()))
	}
	ports := make([]*workloadv1.Port, 0, len(service.Ports))
	for _, port := range service.Ports {
		ports = append(ports, &workloadv1.Port{
			ServicePort: port.Port,
			TargetPort:  port.TargetPort,
			AppProtocol: wireAppProtocol(port.AppProtocol),
		})
	}
	wireService := &workloadv1.Service{
		Name:          service.Name,
		Namespace:     service.Namespace,
		Hostname:      service.Hostname,
		Addresses:     addresses,
		Ports:         ports,
		LoadBalancing: wireLoadBalancing(service),
		IpFamilies:    wireIPFamilies(service.IPFamilies),
		Canonical:     service.Canonical,
	}
	address := &workloadv1.Address{
		Type: &workloadv1.Address_Service{
			Service: wireService,
		},
	}
	value, err := marshalDeterministicAny(address)
	if err != nil {
		return model.Resource{}, fmt.Errorf("marshal service %s: %w", service.ResourceName(), err)
	}
	facts := model.ResourceFacts{Service: &model.ServiceResourceFacts{ServiceKey: service.ResourceName()}}
	if gatewayKey != "" {
		facts.GatewayOwner = gatewayKey
	}
	return model.NewResource(
		model.ResourceKey{
			TypeURL: model.AddressType,
			Name:    service.ResourceName(),
		}, "", value, aliases, facts)
}

// wireLoadBalancing prioritizes an internal traffic policy of Local, then the
// traffic-distribution preference. PublishNotReadyAddresses adds the ALLOW_ALL
// health policy.
func wireLoadBalancing(service model.Service) *workloadv1.LoadBalancing {
	var lb *workloadv1.LoadBalancing
	if service.InternalTrafficPolicyLocal {
		lb = &workloadv1.LoadBalancing{
			RoutingPreference: []workloadv1.LoadBalancing_Scope{
				workloadv1.LoadBalancing_NODE,
			},
			Mode: workloadv1.LoadBalancing_STRICT,
		}
	} else {
		switch service.TrafficDistribution {
		case model.TrafficDistributionPreferSameZone:
			lb = &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{
					workloadv1.LoadBalancing_NETWORK,
					workloadv1.LoadBalancing_REGION,
					workloadv1.LoadBalancing_ZONE,
				},
				Mode: workloadv1.LoadBalancing_FAILOVER,
			}
		case model.TrafficDistributionPreferSameNode:
			lb = &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{
					workloadv1.LoadBalancing_NETWORK,
					workloadv1.LoadBalancing_REGION,
					workloadv1.LoadBalancing_ZONE,
					workloadv1.LoadBalancing_SUBZONE,
					workloadv1.LoadBalancing_NODE,
				},
				Mode: workloadv1.LoadBalancing_FAILOVER,
			}
		}
	}
	if service.PublishNotReadyAddresses {
		if lb == nil {
			lb = &workloadv1.LoadBalancing{}
		}
		lb.HealthPolicy = workloadv1.LoadBalancing_ALLOW_ALL
	}
	return lb
}

func wireIPFamilies(families model.IPFamilies) workloadv1.IPFamilies {
	switch families {
	case model.IPFamiliesIPv4Only:
		return workloadv1.IPFamilies_IPV4_ONLY
	case model.IPFamiliesIPv6Only:
		return workloadv1.IPFamilies_IPV6_ONLY
	case model.IPFamiliesDual:
		return workloadv1.IPFamilies_DUAL
	default:
		return workloadv1.IPFamilies_AUTOMATIC
	}
}

func wireAppProtocol(protocol model.AppProtocol) workloadv1.AppProtocol {
	switch protocol {
	case model.AppProtocolHTTP11:
		return workloadv1.AppProtocol_HTTP11
	case model.AppProtocolHTTP2:
		return workloadv1.AppProtocol_HTTP2
	case model.AppProtocolGRPC:
		return workloadv1.AppProtocol_GRPC
	default:
		return workloadv1.AppProtocol_UNKNOWN
	}
}

func filteredWorkloadLabels(labels map[string]string, ignored []string) map[string]string {
	filtered := make(map[string]string, len(labels))
	for key, value := range labels {
		if !matchesIgnoredLabel(key, ignored) {
			filtered[key] = value
		}
	}
	return filtered
}

func matchesIgnoredLabel(key string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == key {
			return true
		}
		if matched, _ := path.Match(pattern, key); matched {
			return true
		}
	}
	return false
}

func newWorkloadMetadataExtension(labels map[string]string) (*workloadv1.Extension, error) {
	config, err := marshalDeterministicAny(&extensionsv1.WorkloadMetadata{
		Labels:                    labels,
		MeshInternalTrafficPolicy: features.MeshInternalTrafficPolicy,
	})
	if err != nil {
		return nil, err
	}
	return &workloadv1.Extension{
		Name:   "workload-metadata",
		Config: config,
	}, nil
}

func normalizedProtocol(protocol string) string {
	if protocol == "" {
		return "TCP"
	}
	return strings.ToUpper(protocol)
}

func parseAddresses(values []string) ([][]byte, []string, error) {
	addresses := make([][]byte, 0, len(values))
	aliases := make([]string, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, nil, fmt.Errorf("parse address %q: %w", value, err)
		}
		addresses = append(addresses, address.AsSlice())
		aliases = append(aliases, addressAlias("", address.String()))
	}
	sort.Strings(aliases)
	return addresses, aliases, nil
}

func addressAlias(network, address string) string {
	return network + "/" + address
}

// projectWorkloadIdentity returns the WDS trust domain and service account from the principal.
// A nonempty principal must use the namespace/service-account format and match the Workload namespace.
func projectWorkloadIdentity(input wdsProjection) (string, string, error) {
	principal := input.Workload.Principal
	if principal == (model.Principal{}) {
		return "", "", nil
	}
	if namespace, account, kubernetes := podsource.ServiceAccountFromPrincipal(principal); kubernetes {
		if namespace != input.Workload.Namespace {
			return "", "", fmt.Errorf(
				"workload %s namespace does not match service account principal",
				input.Workload.UID,
			)
		}
		return principal.TrustDomain(), account, nil
	}
	return "", "", fmt.Errorf("WDS identity fields cannot represent workload principal %s", principal.String())
}

// marshalDeterministicAny encodes the payload before wrapping it: deterministic
// marshaling of an outer Any cannot reorder bytes already stored in its Value.
func marshalDeterministicAny(message proto.Message) (*anypb.Any, error) {
	value := new(anypb.Any)
	if err := anypb.MarshalFrom(value, message, proto.MarshalOptions{Deterministic: true}); err != nil {
		return nil, err
	}
	return value, nil
}
