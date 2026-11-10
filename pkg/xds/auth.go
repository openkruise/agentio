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

package xds

import (
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/model"
)

func clientVersion(node *corev3.Node) string {
	version := metadataString(node.GetMetadata(), "ISTIO_VERSION")
	if version == "" {
		version = node.GetUserAgentVersion()
	}
	return version
}

func metadataString(metadata *structpb.Struct, key string) string {
	if metadata == nil {
		return ""
	}
	return metadata.GetFields()[key].GetStringValue()
}

func typeAccess(class model.ClientClass, typeURL string) (known, allowed bool) {
	if class == model.ClientEPE {
		known, _ := typeAccess(model.ClientEgressGateway, typeURL)
		return known, typeURL == model.WorkloadType || typeURL == model.TrafficPolicyType ||
			typeURL == model.SecurityProfileType ||
			typeURL == model.SandboxType
	}
	if class == model.ClientAgentioEgress {
		switch typeURL {
		case model.WorkloadType,
			model.TrafficPolicyType,
			model.SandboxType,
			model.ClusterType,
			model.EndpointType,
			model.ListenerType,
			model.RouteType,
			model.SecretType,
			model.ExtensionConfigurationType:
			return true, true
		default:
			known, _ := typeAccess(model.ClientEgressGateway, typeURL)
			return known, false
		}
	}
	switch typeURL {
	case model.SecurityProfileType:
		return true, false
	case model.AddressType, model.WorkloadAuthorizationType, model.TrafficPolicyType, model.SandboxType:
		return true, true
	case model.WorkloadType,
		model.ClusterType,
		model.EndpointType,
		model.ListenerType,
		model.RouteType,
		model.SecretType,
		model.ExtensionConfigurationType,
		model.ProxyConfigType:
		return true, class == model.ClientEgressGateway
	default:
		return false, false
	}
}

// scopeAllows checks ownership of generic gateway resources. Workload,
// Authorization, Sandbox, and TrafficPolicy visibility is handled by their generators.
func scopeAllows(scope model.ClientScope, resource model.Resource) bool {
	if resource.Facts.GatewayOwner == "" || resource.Facts.GatewayOwner != scope.GatewayKey {
		return false
	}
	if scope.Class != model.ClientEgressGateway && scope.Class != model.ClientAgentioEgress {
		return false
	}
	// Domain certificates have the same wire contract and ownership on both gateways.
	return resource.Key.TypeURL == model.SecretType ||
		resource.Facts.AgentioEgress == (scope.Class == model.ClientAgentioEgress)
}
