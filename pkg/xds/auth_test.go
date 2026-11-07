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
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/model"
)

func requestWithMetadata(podName, namespace, nodeName string) *discoveryv3.DeltaDiscoveryRequest {
	return &discoveryv3.DeltaDiscoveryRequest{Node: &corev3.Node{
		Id: "sidecar~10.0.0.1~client-pod.demo~demo.svc.cluster.local",
		Metadata: &structpb.Struct{Fields: map[string]*structpb.Value{
			"POD_NAME":      structpb.NewStringValue(podName),
			"POD_NAMESPACE": structpb.NewStringValue(namespace),
			"NODE_NAME":     structpb.NewStringValue(nodeName),
		}},
	}}
}

func TestClientVersionFromNode(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*discoveryv3.DeltaDiscoveryRequest)
		version string
	}{
		{
			name: "istio version metadata",
			mutate: func(request *discoveryv3.DeltaDiscoveryRequest) {
				request.Node.Metadata.Fields["ISTIO_VERSION"] = structpb.NewStringValue("1.24.2")
			},
			version: "1.24.2",
		},
		{
			name: "user agent fallback",
			mutate: func(request *discoveryv3.DeltaDiscoveryRequest) {
				request.Node.UserAgentVersionType = &corev3.Node_UserAgentVersion{UserAgentVersion: "1.30.0"}
			},
			version: "1.30.0",
		},
		{
			name: "metadata wins over user agent",
			mutate: func(request *discoveryv3.DeltaDiscoveryRequest) {
				request.Node.Metadata.Fields["ISTIO_VERSION"] = structpb.NewStringValue("1.24.2")
				request.Node.UserAgentVersionType = &corev3.Node_UserAgentVersion{UserAgentVersion: "1.30.0"}
			},
			version: "1.24.2",
		},
		{name: "absent", mutate: func(*discoveryv3.DeltaDiscoveryRequest) {}, version: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := requestWithMetadata("client-pod", "demo", "node-a")
			tc.mutate(request)
			if version := clientVersion(request.GetNode()); version != tc.version {
				t.Fatalf("clientVersion() = %q, want %q", version, tc.version)
			}
		})
	}
}

func TestScopeAllowsGatewayOwnedResources(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   model.ClientScope
		owner   string
		allowed bool
	}{
		{name: "own gateway", scope: model.ClientScope{Class: model.ClientEgressGateway, GatewayKey: "demo/egress"}, owner: "demo/egress", allowed: true},
		{name: "other gateway", scope: model.ClientScope{Class: model.ClientEgressGateway, GatewayKey: "demo/other"}, owner: "demo/egress"},
		{name: "unowned resource", scope: model.ClientScope{Class: model.ClientEgressGateway, GatewayKey: "demo/egress"}},
		{name: "empty gateway key", scope: model.ClientScope{Class: model.ClientEgressGateway}},
		{name: "dedicated client", scope: model.ClientScope{Class: model.ClientDedicatedZTunnel, GatewayKey: "demo/egress"}, owner: "demo/egress"},
		{name: "shared client", scope: model.ClientScope{Class: model.ClientSharedZTunnel, GatewayKey: "demo/egress"}, owner: "demo/egress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource := model.Resource{
				Key: model.ResourceKey{
					TypeURL: model.SecretType,
					Name:    "secret",
				},
				Facts: model.ResourceFacts{
					GatewayOwner: tc.owner,
				},
			}
			if got := scopeAllows(tc.scope, resource); got != tc.allowed {
				t.Fatalf("scopeAllows() = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestStandaloneSNIPolicyTypeIsUnknown(t *testing.T) {
	for _, class := range []model.ClientClass{model.ClientDedicatedZTunnel, model.ClientSharedZTunnel, model.ClientEgressGateway} {
		if known, allowed := typeAccess(class, model.SniTrafficPolicyType); known || allowed {
			t.Fatalf("standalone SNI type access for %v = (%v, %v), want unknown and denied", class, known, allowed)
		}
	}
}

func TestEPETypeAccess(t *testing.T) {
	for _, typ := range []string{model.WorkloadType, model.TrafficPolicyType, model.SecurityProfileType, model.AddressType, model.SandboxType, model.SecretType, model.ClusterType, model.ListenerType} {
		known, allowed := typeAccess(model.ClientEPE, typ)
		want := typ == model.WorkloadType || typ == model.TrafficPolicyType || typ == model.SecurityProfileType ||
			typ == model.SandboxType
		if !known || allowed != want {
			t.Fatalf("EPE access to %s: known=%v allowed=%v", typ, known, allowed)
		}
	}
}

func TestWorkloadTypeIsGatewayOnly(t *testing.T) {
	for _, class := range []model.ClientClass{
		model.ClientSharedZTunnel,
		model.ClientDedicatedZTunnel,
	} {
		if known, allowed := typeAccess(class, model.WorkloadType); !known || allowed {
			t.Errorf("typeAccess(%q, WorkloadType) must be known and denied", class)
		}
	}
	if known, allowed := typeAccess(model.ClientEgressGateway, model.WorkloadType); !known || !allowed {
		t.Fatal("egress gateway cannot subscribe WorkloadType")
	}
}
