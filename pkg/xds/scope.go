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
	"fmt"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"github.com/openkruise/agentio/pkg/model"
)

// ScopeFunc builds a client scope from node metadata and an attested identity.
type ScopeFunc func(node *corev3.Node, peer model.PeerIdentity) (model.ClientScope, error)

// ScopeFuncs dispatches scope construction by the authenticated client attestation;
// an unregistered attestation fails closed.
type ScopeFuncs map[model.Attestation]ScopeFunc

func (s ScopeFuncs) ResolveScope(node *corev3.Node, peer model.PeerIdentity) (model.ClientScope, error) {
	scopeFunc, found := s[peer.AttestedBy]
	if !found || scopeFunc == nil {
		return model.ClientScope{}, fmt.Errorf("no scope function is registered for attestation %q", peer.AttestedBy)
	}
	return scopeFunc(node, peer)
}

// KubernetesScopeFunc verifies self-reported metadata against the token-bound
// identity, then delegates ownership resolution; only the verified node name
// is passed on.
func KubernetesScopeFunc(resolver interface {
	ResolveScope(peer model.PeerIdentity, nodeName string) (model.ClientScope, error)
}) ScopeFunc {
	return func(node *corev3.Node, peer model.PeerIdentity) (model.ClientScope, error) {
		metadata := node.GetMetadata()
		if _, err := boundClaim(
			"namespace",
			metadataString(metadata, "POD_NAMESPACE"),
			peer.Kubernetes.Namespace,
		); err != nil {
			return model.ClientScope{}, err
		}
		if _, err := boundClaim(
			"workload name",
			metadataString(metadata, "POD_NAME"),
			peer.Kubernetes.WorkloadName,
		); err != nil {
			return model.ClientScope{}, err
		}
		if _, err := boundClaim(
			"workload UID",
			metadataString(metadata, "POD_UID"),
			peer.Kubernetes.WorkloadUID,
		); err != nil {
			return model.ClientScope{}, err
		}
		nodeName := metadataString(metadata, "NODE_NAME")
		if nodeName == "" {
			nodeName = metadataString(metadata, "ISTIO_META_NODE_NAME")
		}
		nodeName, err := boundClaim("node name", nodeName, peer.Kubernetes.NodeName)
		if err != nil {
			return model.ClientScope{}, err
		}
		scope, err := resolver.ResolveScope(peer, nodeName)
		if err != nil {
			return model.ClientScope{}, err
		}
		proxyType := nodeProxyType(node)
		if proxyType == model.ProxyTypeResourceConsumer {
			// The Pod is attested; the ADS server requires an explicit principal grant.
			scope.Class = model.ClientResourceConsumer
			return scope, nil
		}
		var expectedType string
		switch scope.Class {
		case model.ClientDedicatedZTunnel, model.ClientSharedZTunnel:
			expectedType = model.ProxyTypeZTunnel
		case model.ClientEgressGateway:
			expectedType = model.ProxyTypeWaypoint
			// Envoy and Porter share the authenticated gateway scope. Each
			// client subscribes to the resource types it consumes.
			if proxyType == model.ProxyTypeAgentioEgress || proxyType == model.ProxyTypeAgentioPorter {
				scope.Class = model.ClientAgentioEgress
				expectedType = proxyType
			}
		default:
			return model.ClientScope{}, fmt.Errorf("unknown client class %q", scope.Class)
		}
		if proxyType != expectedType {
			return model.ClientScope{}, fmt.Errorf(
				"%s scope requires %s proxy type, got %q",
				scope.Class,
				expectedType,
				proxyType,
			)
		}
		return scope, nil
	}
}

func nodeProxyType(node *corev3.Node) string {
	proxyType, _, _ := strings.Cut(node.GetId(), "~")
	return proxyType
}

func boundClaim(field, claimed, authenticated string) (string, error) {
	if authenticated == "" {
		return claimed, nil
	}
	if claimed != "" && claimed != authenticated {
		return "", fmt.Errorf("claimed %s %q does not match bound identity %q", field, claimed, authenticated)
	}
	return authenticated, nil
}
