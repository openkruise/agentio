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

package model

import (
	"fmt"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

var xdsResourceTypes = map[string]string{
	"Address":                AddressType,
	"Workload":               WorkloadType,
	"Authorization":          WorkloadAuthorizationType,
	"TrafficPolicy":          TrafficPolicyType,
	"Sandbox":                SandboxType,
	"Cluster":                ClusterType,
	"Endpoint":               EndpointType,
	"Listener":               ListenerType,
	"Route":                  RouteType,
	"Secret":                 SecretType,
	"ExtensionConfiguration": ExtensionConfigurationType,
	"ProxyConfig":            ProxyConfigType,
}

// XDSResourceType maps configuration names to the wire types served by Agentiod.
func XDSResourceType(name string) (string, bool) {
	typ, found := xdsResourceTypes[name]
	return typ, found
}

// ValidateXDSClients validates the control-plane authorization boundary.
func ValidateXDSClients(clients []*configv1.XDSClient) error {
	seen := make(map[string]bool, len(clients))
	for i, client := range clients {
		uri, err := ParseSPIFFEID(client.GetPrincipal())
		if err != nil {
			return fmt.Errorf("xdsClients[%d].principal: %w", i, err)
		}
		principal, err := ParsePrincipalURL(uri, uri.Host)
		if err != nil {
			return fmt.Errorf("xdsClients[%d].principal: %w", i, err)
		}
		if principal.String() != client.GetPrincipal() {
			return fmt.Errorf("xdsClients[%d].principal must be a canonical SPIFFE identity", i)
		}
		if seen[client.GetPrincipal()] {
			return fmt.Errorf("duplicate xdsClients principal %q", client.GetPrincipal())
		}
		seen[client.GetPrincipal()] = true
		for _, resource := range client.GetResources() {
			if _, found := XDSResourceType(resource); resource != "*" && !found {
				return fmt.Errorf("xdsClients[%d]: unknown resource %q", i, resource)
			}
		}
	}
	return nil
}
