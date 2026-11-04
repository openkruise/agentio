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

	"github.com/openkruise/agentio/pkg/model"
)

// ServiceTarget identifies a TCP Service port to resolve for EDS.
type ServiceTarget struct {
	Namespace string
	Name      string
	Port      uint32
}

// BuildServiceLoadAssignment resolves a Service port to ready, serving, non-terminating endpoints.
// EndpointSlice ports are authoritative; Service targetPort does not constrain them.
func BuildServiceLoadAssignment(
	name string,
	target ServiceTarget,
	services []model.Service,
	endpoints []model.Endpoint,
) *endpointv3.ClusterLoadAssignment {
	assignment := &endpointv3.ClusterLoadAssignment{ClusterName: name}
	selected := selectServiceEndpoints(target, services, endpoints)
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

func selectServiceEndpoints(
	target ServiceTarget,
	services []model.Service,
	endpoints []model.Endpoint,
) []model.Endpoint {
	var selected []model.Endpoint
	for _, service := range services {
		if service.Namespace != target.Namespace || service.Name != target.Name {
			continue
		}
		for _, servicePort := range service.Ports {
			if servicePort.Port != target.Port || (servicePort.Protocol != "" && servicePort.Protocol != "TCP") {
				continue
			}
			for _, endpoint := range endpoints {
				if endpoint.ServiceKey != service.ResourceName() ||
					!endpoint.Ready || !endpoint.Serving || endpoint.Terminating ||
					endpoint.PortName != servicePort.Name ||
					endpoint.Port == 0 ||
					(endpoint.Protocol != "" && endpoint.Protocol != "TCP") {
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
