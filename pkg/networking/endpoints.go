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

package networking

import (
	"cmp"
	"slices"

	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// BuildExtProcLoadAssignment resolves an accepted target against current Service endpoints.
func BuildExtProcLoadAssignment(
	name string,
	provider *configv1.ExtProcProvider,
	services []model.Service,
	endpoints []model.Endpoint,
) *endpointv3.ClusterLoadAssignment {
	assignment := &endpointv3.ClusterLoadAssignment{ClusterName: name}
	selected := selectExtProcEndpoints(provider, services, endpoints)
	if len(selected) > 0 {
		locality := &endpointv3.LocalityLbEndpoints{}
		for _, endpoint := range selected {
			locality.LbEndpoints = append(locality.LbEndpoints, &endpointv3.LbEndpoint{
				HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
					Address: socketAddress(endpoint.Address, endpoint.Port),
				}},
			})
		}
		assignment.Endpoints = []*endpointv3.LocalityLbEndpoints{locality}
	}
	return assignment
}

func selectExtProcEndpoints(
	provider *configv1.ExtProcProvider,
	services []model.Service,
	endpoints []model.Endpoint,
) []model.Endpoint {
	port := provider.GetPort()
	if port == 0 {
		port = 9002
	}
	var selected []model.Endpoint
	for _, service := range services {
		if service.Namespace != provider.GetServiceRef().GetNamespace() ||
			service.Name != provider.GetServiceRef().GetName() {
			continue
		}
		for _, servicePort := range service.Ports {
			if servicePort.Port != port || (servicePort.Protocol != "" && servicePort.Protocol != "TCP") {
				continue
			}
			for _, endpoint := range endpoints {
				if endpoint.ServiceKey != service.ResourceName() || !endpoint.Ready || endpoint.Terminating ||
					endpoint.PortName != servicePort.Name || endpoint.Port == 0 ||
					(endpoint.Protocol != "" && endpoint.Protocol != "TCP") ||
					(servicePort.TargetPort != 0 && endpoint.Port != servicePort.TargetPort) {
					continue
				}
				selected = append(selected, endpoint)
			}
		}
	}
	slices.SortFunc(selected, func(a, b model.Endpoint) int {
		return cmp.Or(cmp.Compare(a.Address, b.Address), cmp.Compare(a.Port, b.Port))
	})
	return slices.CompactFunc(selected, func(a, b model.Endpoint) bool {
		return a.Address == b.Address && a.Port == b.Port
	})
}
