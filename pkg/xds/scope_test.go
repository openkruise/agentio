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
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/model"
)

func nodeWithMetadata(fields map[string]string) *corev3.Node {
	values := make(map[string]*structpb.Value, len(fields))
	for key, value := range fields {
		values[key] = structpb.NewStringValue(value)
	}
	return &corev3.Node{
		Id:       "ztunnel~10.0.0.1~client.demo~demo.svc.cluster.local",
		Metadata: &structpb.Struct{Fields: values},
	}
}

type fakeNodeResolver struct {
	scope    model.ClientScope
	err      error
	calls    int
	nodeName string
}

func (f *fakeNodeResolver) ResolveScope(_ model.PeerIdentity, nodeName string) (model.ClientScope, error) {
	f.calls++
	f.nodeName = nodeName
	return f.scope, f.err
}

func TestScopeFuncsDispatchesByAuthenticatedAttestation(t *testing.T) {
	want := model.ClientScope{
		Class:     model.ClientSharedZTunnel,
		Principal: serviceAccountPrincipal("agentio-system", "ztunnel"),
		NodeName:  "node-a",
	}
	calls := 0
	scopeFuncs := ScopeFuncs{
		model.AttestationKubernetes: func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) {
			calls++
			return want, nil
		},
	}
	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{Namespace: "agentio-system", ServiceAccount: "ztunnel"},
	}

	scope, err := scopeFuncs.ResolveScope(&corev3.Node{}, peer)
	if err != nil {
		t.Fatalf("kubernetes scope rejected: %v", err)
	}
	if scope != want || calls != 1 {
		t.Fatalf("scope = %#v calls = %d", scope, calls)
	}
}

func TestScopeFuncsFailsClosedForUnregisteredAttestation(t *testing.T) {
	calls := 0
	scopeFuncs := ScopeFuncs{model.AttestationKubernetes: func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) {
		calls++
		return model.ClientScope{}, nil
	}}
	peer := model.PeerIdentity{AttestedBy: model.Attestation("firecracker")}

	if _, err := scopeFuncs.ResolveScope(&corev3.Node{}, peer); err == nil {
		t.Fatal("unregistered attestation resolved a scope")
	}
	if calls != 0 {
		t.Fatal("unregistered client leaked to the Kubernetes scope function")
	}
}

func TestScopeFuncsFailsClosedOnNilEntry(t *testing.T) {
	scopeFuncs := ScopeFuncs{model.AttestationKubernetes: nil}
	peer := model.PeerIdentity{AttestedBy: model.AttestationKubernetes}
	if _, err := scopeFuncs.ResolveScope(&corev3.Node{}, peer); err == nil {
		t.Fatal("nil scope function entry resolved a scope")
	}
}

func TestKubernetesScopeFuncVerifiesBoundIdentity(t *testing.T) {
	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName:   "bound-pod",
			WorkloadUID:    "bound-uid",
			NodeName:       "node-a",
			Namespace:      "demo",
			ServiceAccount: "client",
		},
	}
	tests := []struct {
		name         string
		metadata     map[string]string
		wantError    string
		wantNodeName string
	}{
		{
			name: "matching metadata resolves",
			metadata: map[string]string{
				"POD_NAMESPACE": "demo", "POD_NAME": "bound-pod", "POD_UID": "bound-uid", "NODE_NAME": "node-a",
			},
			wantNodeName: "node-a",
		},
		{
			name:         "absent metadata with bound token still resolves",
			metadata:     map[string]string{},
			wantNodeName: "node-a",
		},
		{
			name:         "istio meta node name fallback",
			metadata:     map[string]string{"ISTIO_META_NODE_NAME": "node-a"},
			wantNodeName: "node-a",
		},
		{
			name:      "namespace mismatch rejected",
			metadata:  map[string]string{"POD_NAMESPACE": "other"},
			wantError: "namespace",
		},
		{
			name:      "workload name mismatch rejected",
			metadata:  map[string]string{"POD_NAME": "other-pod"},
			wantError: "workload name",
		},
		{
			name:      "workload UID mismatch rejected",
			metadata:  map[string]string{"POD_UID": "other-uid"},
			wantError: "workload UID",
		},
		{
			name:      "node name mismatch rejected",
			metadata:  map[string]string{"NODE_NAME": "node-b"},
			wantError: "node name",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeNodeResolver{scope: model.ClientScope{Class: model.ClientDedicatedZTunnel}}
			scopeFunc := KubernetesScopeFunc(resolver)
			scope, err := scopeFunc(nodeWithMetadata(test.metadata), peer)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("err = %v, want mismatch on %s", err, test.wantError)
				}
				if resolver.calls != 0 {
					t.Fatal("mismatched metadata reached the resolver")
				}
				return
			}
			if err != nil {
				t.Fatalf("scope rejected: %v", err)
			}
			if scope != resolver.scope || resolver.calls != 1 {
				t.Fatalf("scope = %#v calls = %d", scope, resolver.calls)
			}
			if resolver.nodeName != test.wantNodeName {
				t.Fatalf("nodeName = %q, want %q", resolver.nodeName, test.wantNodeName)
			}
		})
	}
}

// An unbound token has no authenticated node; the client's asserted node name
// passes through as the shared ztunnel role assertion.
func TestKubernetesScopeFuncPassesAssertedNodeForUnboundToken(t *testing.T) {
	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{Namespace: "agentio-system", ServiceAccount: "ztunnel"},
	}
	resolver := &fakeNodeResolver{scope: model.ClientScope{Class: model.ClientSharedZTunnel}}
	if _, err := KubernetesScopeFunc(
		resolver,
	)(
		nodeWithMetadata(map[string]string{"NODE_NAME": "node-b"}),
		peer,
	); err != nil {
		t.Fatalf("unbound node assertion rejected: %v", err)
	}
	if resolver.nodeName != "node-b" {
		t.Fatalf("nodeName = %q, want asserted node-b", resolver.nodeName)
	}
}

func TestKubernetesScopeFuncMatchesProxyTypeToResolvedScope(t *testing.T) {
	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{Namespace: "demo", ServiceAccount: "egress"},
	}
	for _, test := range []struct {
		name      string
		nodeID    string
		scope     model.ClientScope
		wantError bool
	}{
		{
			name:   "waypoint declares gateway role",
			nodeID: "waypoint~10.0.0.1~egress.demo~demo.svc.cluster.local",
			scope:  model.ClientScope{Class: model.ClientEgressGateway},
		},
		{
			name:      "missing node type cannot obtain gateway scope",
			scope:     model.ClientScope{Class: model.ClientEgressGateway},
			wantError: true,
		},
		{
			name:      "sidecar cannot obtain gateway scope",
			nodeID:    "sidecar~10.0.0.1~egress.demo~demo.svc.cluster.local",
			scope:     model.ClientScope{Class: model.ClientEgressGateway},
			wantError: true,
		},
		{
			name:      "waypoint cannot obtain sandbox scope",
			nodeID:    "waypoint~10.0.0.1~client.demo~demo.svc.cluster.local",
			scope:     model.ClientScope{Class: model.ClientDedicatedZTunnel},
			wantError: true,
		},
		{
			name:   "ztunnel declares dedicated sandbox role",
			nodeID: "ztunnel~10.0.0.1~client.demo~demo.svc.cluster.local",
			scope:  model.ClientScope{Class: model.ClientDedicatedZTunnel},
		},
		{
			name:   "ztunnel declares shared node role",
			nodeID: "ztunnel~10.0.0.1~ztunnel.agentio-system~agentio-system.svc.cluster.local",
			scope:  model.ClientScope{Class: model.ClientSharedZTunnel},
		},
		{
			name:      "missing node type cannot obtain sandbox scope",
			scope:     model.ClientScope{Class: model.ClientDedicatedZTunnel},
			wantError: true,
		},
		{
			name:      "sidecar cannot obtain sandbox scope",
			nodeID:    "sidecar~10.0.0.1~client.demo~demo.svc.cluster.local",
			scope:     model.ClientScope{Class: model.ClientDedicatedZTunnel},
			wantError: true,
		},
		{
			name:      "unknown scope cannot be asserted as ztunnel",
			nodeID:    "ztunnel~10.0.0.1~client.demo~demo.svc.cluster.local",
			scope:     model.ClientScope{Class: "unknown"},
			wantError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeNodeResolver{scope: test.scope}
			node := nodeWithMetadata(nil)
			node.Id = test.nodeID
			_, err := KubernetesScopeFunc(resolver)(node, peer)
			if test.wantError && err == nil {
				t.Fatal("scope resolved despite proxy type mismatch")
			}
			if !test.wantError && err != nil {
				t.Fatalf("matching proxy type rejected: %v", err)
			}
		})
	}
}

func TestKubernetesResourceConsumerUsesBoundPodScope(t *testing.T) {
	resolver := &fakeNodeResolver{scope: ztunnelScope()}
	node := nodeWithMetadata(map[string]string{})
	node.Id = model.ProxyTypeResourceConsumer + "~10.0.0.1~epe.demo~demo.svc.cluster.local"
	scope, err := KubernetesScopeFunc(resolver)(node, model.PeerIdentity{AttestedBy: model.AttestationKubernetes})
	if err != nil {
		t.Fatal(err)
	}
	if scope.Class != model.ClientResourceConsumer || scope.Principal != resolver.scope.Principal ||
		scope.GatewayKey != "" {
		t.Fatalf("scope = %+v", scope)
	}
}
