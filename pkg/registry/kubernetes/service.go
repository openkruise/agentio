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

package kubernetes

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// This file adapts Kubernetes Services and EndpointSlices into the long-term
// networking-only Service and Endpoint models. Identity, attestation, and
// policy attachment must not be inferred from these values.

func newServiceCollections(
	services krt.Collection[*corev1.Service],
	slices krt.Collection[*discoveryv1.EndpointSlice],
	clusterDomain string,
	derivedOptions func(name string) []krt.CollectionOption,
) (krt.Collection[model.Service], krt.Collection[model.Endpoint]) {
	serviceCollection := krt.NewCollection(services, func(_ krt.HandlerContext, service *corev1.Service) *model.Service {
		return serviceFromKubernetes(clusterDomain, service)
	}, derivedOptions("services")...)
	endpointCollection := krt.NewManyCollection(slices, func(_ krt.HandlerContext, slice *discoveryv1.EndpointSlice) []model.Endpoint {
		return endpointsFromSlice(clusterDomain, slice)
	}, derivedOptions("endpoints")...)
	return serviceCollection, endpointCollection
}

func serviceFromKubernetes(clusterDomain string, service *corev1.Service) *model.Service {
	hostname := service.Name + "." + service.Namespace + ".svc." + clusterDomain
	addresses := make([]string, 0, len(service.Spec.ClusterIPs))
	for _, address := range service.Spec.ClusterIPs {
		if address != "" && address != corev1.ClusterIPNone {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 && service.Spec.ClusterIP != "" && service.Spec.ClusterIP != corev1.ClusterIPNone {
		addresses = []string{service.Spec.ClusterIP}
	}
	ports := make([]model.ServicePort, 0, len(service.Spec.Ports))
	for _, port := range service.Spec.Ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = corev1.ProtocolTCP
		}
		targetPort := uint32(0)
		targetPortName := ""
		if port.TargetPort.Type == intstr.String {
			targetPortName = port.TargetPort.StrVal
		} else if port.TargetPort.IntVal > 0 {
			targetPort = uint32(port.TargetPort.IntVal)
		} else {
			// Kubernetes defaults an omitted targetPort to the Service port. Fake
			// clients do not run API defaulting, so normalize it here as well.
			targetPort = uint32(port.Port)
		}
		ports = append(ports, model.ServicePort{
			Name:           port.Name,
			Port:           uint32(port.Port),
			TargetPortName: targetPortName,
			TargetPort:     targetPort,
			Protocol:       string(protocol),
			AppProtocol:    serviceAppProtocol(port),
		})
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		if ports[i].Name != ports[j].Name {
			return ports[i].Name < ports[j].Name
		}
		if ports[i].Protocol != ports[j].Protocol {
			return ports[i].Protocol < ports[j].Protocol
		}
		if ports[i].AppProtocol != ports[j].AppProtocol {
			return ports[i].AppProtocol < ports[j].AppProtocol
		}
		if ports[i].TargetPortName != ports[j].TargetPortName {
			return ports[i].TargetPortName < ports[j].TargetPortName
		}
		return ports[i].TargetPort < ports[j].TargetPort
	})
	return &model.Service{
		Namespace:                  service.Namespace,
		Name:                       service.Name,
		Hostname:                   hostname,
		Addresses:                  addresses,
		Ports:                      ports,
		InternalTrafficPolicyLocal: internalTrafficPolicyLocal(service),
		TrafficDistribution:        trafficDistribution(service),
		IPFamilies:                 serviceIPFamilies(service),
		PublishNotReadyAddresses:   service.Spec.PublishNotReadyAddresses,
		Canonical:                  true,
	}
}

func internalTrafficPolicyLocal(service *corev1.Service) bool {
	policy := service.Spec.InternalTrafficPolicy
	return policy != nil && *policy == corev1.ServiceInternalTrafficPolicyLocal
}

// trafficDistribution resolves the Service's native topology preference.
func trafficDistribution(service *corev1.Service) model.TrafficDistribution {
	if value := service.Spec.TrafficDistribution; value != nil {
		switch *value {
		case corev1.ServiceTrafficDistributionPreferSameZone, corev1.ServiceTrafficDistributionPreferClose:
			return model.TrafficDistributionPreferSameZone
		case corev1.ServiceTrafficDistributionPreferSameNode:
			return model.TrafficDistributionPreferSameNode
		}
	}
	return model.TrafficDistributionAny
}

func serviceIPFamilies(service *corev1.Service) model.IPFamilies {
	switch {
	case len(service.Spec.IPFamilies) == 2:
		return model.IPFamiliesDual
	case len(service.Spec.IPFamilies) == 1 && service.Spec.IPFamilies[0] == corev1.IPv4Protocol:
		return model.IPFamiliesIPv4Only
	case len(service.Spec.IPFamilies) == 1:
		return model.IPFamiliesIPv6Only
	default:
		return model.IPFamiliesAutomatic
	}
}

// serviceAppProtocol maps Kubernetes service port hints to the internal protocol model.
func serviceAppProtocol(port corev1.ServicePort) model.AppProtocol {
	if port.Protocol == corev1.ProtocolUDP {
		return model.AppProtocolUnknown
	}
	name := port.Name
	if port.AppProtocol != nil {
		name = *port.AppProtocol
		switch name {
		case "kubernetes.io/h2c":
			return model.AppProtocolHTTP2
		case "kubernetes.io/ws":
			return model.AppProtocolHTTP11
		case "kubernetes.io/wss":
			return model.AppProtocolUnknown
		}
	}
	if len(name) >= len("grpc-web") && strings.EqualFold(name[:len("grpc-web")], "grpc-web") {
		return model.AppProtocolUnknown
	}
	if index := strings.IndexByte(name, '-'); index >= 0 {
		name = name[:index]
	}
	switch strings.ToLower(name) {
	case "http":
		return model.AppProtocolHTTP11
	case "http2":
		return model.AppProtocolHTTP2
	case "grpc":
		return model.AppProtocolGRPC
	default:
		return model.AppProtocolUnknown
	}
}

func endpointsFromSlice(clusterDomain string, slice *discoveryv1.EndpointSlice) []model.Endpoint {
	if slice.AddressType == discoveryv1.AddressTypeFQDN {
		// FQDN EndpointSlices are unsupported; skip them entirely, including targetRefs.
		return nil
	}
	serviceName := slice.Labels[discoveryv1.LabelServiceName]
	if serviceName == "" {
		return nil
	}
	hostname := serviceName + "." + slice.Namespace + ".svc." + clusterDomain
	serviceKey := slice.Namespace + "/" + hostname
	sourceKey := slice.Namespace + "/" + slice.Name
	result := make([]model.Endpoint, 0, len(slice.Endpoints)*len(slice.Ports))
	for _, endpoint := range slice.Endpoints {
		ready := endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready
		terminating := endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating
		zone := ""
		if endpoint.Zone != nil {
			zone = *endpoint.Zone
		}
		for _, address := range endpoint.Addresses {
			for _, port := range slice.Ports {
				if port.Port == nil {
					continue
				}
				portName := ""
				if port.Name != nil {
					portName = *port.Name
				}
				protocol := corev1.ProtocolTCP
				if port.Protocol != nil && *port.Protocol != "" {
					protocol = *port.Protocol
				}
				// Accept only TCP ports: the workload port mapping has no transport-protocol field.
				if protocol != corev1.ProtocolTCP {
					continue
				}
				targetKind, targetUID, targetName, targetNamespace := "", "", "", ""
				hasTargetRef := endpoint.TargetRef != nil
				if endpoint.TargetRef != nil {
					targetKind = endpoint.TargetRef.Kind
					targetUID = string(endpoint.TargetRef.UID)
					targetName = endpoint.TargetRef.Name
					targetNamespace = endpoint.TargetRef.Namespace
					if targetNamespace == "" {
						targetNamespace = slice.Namespace
					}
				}
				result = append(result, model.Endpoint{
					ServiceKey:      serviceKey,
					SourceKey:       sourceKey,
					Address:         address,
					PortName:        portName,
					Port:            uint32(*port.Port),
					Protocol:        string(protocol),
					Ready:           ready,
					Terminating:     terminating,
					Zone:            zone,
					HasTargetRef:    hasTargetRef,
					TargetKind:      targetKind,
					TargetUID:       targetUID,
					TargetName:      targetName,
					TargetNamespace: targetNamespace,
				})
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceName() < result[j].ResourceName() })
	return result
}
