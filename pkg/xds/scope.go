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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openkruise/agentio/pkg/model"
)

// ScopeFunc builds a client scope from node metadata and an attested identity.
type ScopeFunc func(node *corev3.Node, peer model.PeerIdentity) (model.ClientScope, error)

// ScopeFuncs dispatches scope construction by the authenticated client attestation;
// an unregistered attestation fails closed.
type ScopeFuncs map[model.Attestation]ScopeFunc

// ResolveScope waits for local cache readiness after resolving authenticated identity.
func (s ScopeFuncs) ResolveScope(
	ctx context.Context,
	node *corev3.Node,
	peer model.PeerIdentity,
) (model.ClientScope, error) {
	scopeFunc, found := s[peer.AttestedBy]
	if !found || scopeFunc == nil {
		return model.ClientScope{}, fmt.Errorf("no scope function is registered for attestation %q", peer.AttestedBy)
	}
	scope, err := scopeFunc(node, peer)
	if !errors.Is(err, model.ErrScopeNotReady) {
		return scope, err
	}
	// TokenReview can observe a newly created Pod before our informer and derived
	// Workload do. Retry local lookups only; invalid ownership is never retried.
	pending := err
	err = wait.PollUntilContextTimeout(
		ctx,
		25*time.Millisecond,
		5*time.Second,
		false,
		func(context.Context) (bool, error) {
			var resolveErr error
			scope, resolveErr = scopeFunc(node, peer)
			if errors.Is(resolveErr, model.ErrScopeNotReady) {
				pending = resolveErr
				return false, nil
			}
			return resolveErr == nil, resolveErr
		},
	)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return model.ClientScope{}, fmt.Errorf("waiting for client scope (%s): %w", pending.Error(), err)
	}
	return scope, err
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
		var expectedType string
		switch scope.Class {
		case model.ClientEPE:
			expectedType = model.ProxyTypeEPE
		case model.ClientSharedZTunnel, model.ClientDedicatedZTunnel:
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
