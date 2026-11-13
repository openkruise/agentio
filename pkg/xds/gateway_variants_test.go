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
	"errors"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayClientSelectionRequiresAuthenticatedOwnership(t *testing.T) {
	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			Namespace:      "demo",
			WorkloadName:   "egress-pod",
			WorkloadUID:    "pod-uid",
			ServiceAccount: "egress",
		},
	}
	for _, tc := range []struct {
		id    string
		class model.ClientClass
	}{
		{"waypoint~10.0.0.1~egress-pod.demo~demo.svc.cluster.local", model.ClientEgressGateway},
		{"agentio-egress~10.0.0.1~egress-pod.demo~demo.svc.cluster.local", model.ClientAgentioEgress},
		{"agentio-porter~10.0.0.1~egress-pod.demo~demo.svc.cluster.local", model.ClientAgentioEgress},
	} {
		t.Run(tc.id, func(t *testing.T) {
			resolver := &fakeNodeResolver{scope: gatewayScope()}
			node := nodeWithMetadata(
				map[string]string{"POD_NAME": "egress-pod", "POD_NAMESPACE": "demo", "POD_UID": "pod-uid"},
			)
			node.Id = tc.id
			got, err := KubernetesScopeFunc(resolver)(node, peer)
			if err != nil || got.Class != tc.class || got.GatewayKey != "demo/egress" {
				t.Fatalf("scope=%+v err=%v", got, err)
			}
			node.Metadata = nodeWithMetadata(map[string]string{"POD_UID": "other-pod"}).Metadata
			resolver.calls = 0
			if _, err = KubernetesScopeFunc(resolver)(node, peer); err == nil || resolver.calls != 0 {
				t.Fatal("unbound metadata reached ownership resolver")
			}
			resolver = &fakeNodeResolver{err: errors.New("not a Gateway member")}
			if _, err = KubernetesScopeFunc(resolver)(&corev3.Node{Id: tc.id}, peer); err == nil {
				t.Fatal("node prefix bypassed Gateway ownership")
			}
			resolver = &fakeNodeResolver{scope: ztunnelScope()}
			if _, err = KubernetesScopeFunc(resolver)(&corev3.Node{Id: tc.id}, peer); err == nil {
				t.Fatal("node prefix changed a non-Gateway role")
			}
		})
	}
}

func TestGatewayVariantsRemainIsolatedAcrossSnapshotUpdates(t *testing.T) {
	legacy := gatewayResource(t, "demo/egress", "shared", "legacy")
	agentio := gatewayResource(t, "demo/egress", "shared", "agentio")
	agentio.Key.Name = "demo/egress|agentio-egress|shared"
	agentio.Facts.AgentioEgress = true
	agentio, err := model.NewResource(
		agentio.Key,
		agentio.XDSName,
		testResourceContents(testResourceValue(agentio)),
		nil,
		agentio.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	both := selectionSnapshot(t, []model.Resource{legacy, agentio})
	for _, class := range []model.ClientClass{model.ClientEgressGateway, model.ClientAgentioEgress} {
		t.Run(string(class), func(t *testing.T) {
			scope := gatewayScope()
			scope.Class = class
			want, other := legacy, agentio
			if class == model.ClientAgentioEgress {
				want, other = agentio, legacy
			}
			generator := SnapshotGenerator{}
			delta, err := generator.Generate(t.Context(), GenerationRequest{
				Scope:        scope,
				TypeURL:      model.ClusterType,
				Snapshot:     both,
				Full:         true,
				Subscription: SubscriptionView{wildcard: true},
			})
			if err != nil || len(delta.Resources) != 1 || delta.Resources[0].Hash != want.Hash {
				t.Fatalf("cold start: delta=%+v err=%v", delta, err)
			}
			retained := selectionSnapshot(t, []model.Resource{want})
			delta, err = generator.Generate(t.Context(), GenerationRequest{
				Scope:        scope,
				TypeURL:      model.ClusterType,
				Snapshot:     retained,
				Update:       updateBetween(both, retained, both.Diff(retained)),
				Subscription: SubscriptionView{wildcard: true, sent: map[string]string{want.XDSName: want.Hash}},
			})
			if err != nil || len(delta.Resources) != 0 || len(delta.Removed) != 0 {
				t.Fatalf("other variant removal affected client: delta=%+v err=%v", delta, err)
			}
			replaced := selectionSnapshot(t, []model.Resource{other})
			delta, err = generator.Generate(t.Context(), GenerationRequest{
				Scope:        scope,
				TypeURL:      model.ClusterType,
				Snapshot:     replaced,
				Update:       updateBetween(both, replaced, both.Diff(replaced)),
				Subscription: SubscriptionView{wildcard: true, sent: map[string]string{want.XDSName: want.Hash}},
			})
			if err != nil || len(delta.Resources) != 0 || len(delta.Removed) != 1 || delta.Removed[0] != want.XDSName {
				t.Fatalf("own removal selected other variant: delta=%+v err=%v", delta, err)
			}
		})
	}
}

func TestGatewayVariantSubscriptions(t *testing.T) {
	for _, typ := range []string{model.AddressType, model.WorkloadAuthorizationType, model.ProxyConfigType} {
		if known, allowed := typeAccess(model.ClientEgressGateway, typ); !known || !allowed {
			t.Fatalf("legacy subscription denied: %s", typ)
		}
		if known, allowed := typeAccess(model.ClientAgentioEgress, typ); !known || allowed {
			t.Fatalf("agentio-egress received legacy subscription: %s", typ)
		}
	}
	for _, class := range []model.ClientClass{model.ClientEgressGateway, model.ClientAgentioEgress} {
		for _, typ := range []string{model.WorkloadType, model.TrafficPolicyType, model.SandboxType, model.ClusterType, model.EndpointType, model.ListenerType, model.RouteType, model.SecretType, model.ExtensionConfigurationType} {
			if _, allowed := typeAccess(class, typ); !allowed {
				t.Fatalf("%s cannot subscribe to %s", class, typ)
			}
		}
		scope := gatewayScope()
		scope.Class = class
		secret := model.Resource{
			Key:   model.ResourceKey{TypeURL: model.SecretType},
			Facts: model.ResourceFacts{GatewayOwner: scope.GatewayKey},
		}
		if !scopeAllows(scope, secret) {
			t.Fatalf("%s cannot get own SDS secret", class)
		}
		secret.Facts.GatewayOwner = "demo/other"
		if scopeAllows(scope, secret) {
			t.Fatalf("%s can get another Gateway's SDS secret", class)
		}
	}
}

func TestAgentioEgressCanDemandWorkloadAndSandbox(t *testing.T) {
	scope := gatewayScope()
	scope.Class = model.ClientAgentioEgress
	workload := selectionWorkload(t, "client", "other-namespace", "node-b", "", "")
	sandbox := sandboxResourceWithAttester(t, "sandbox", "client")
	snapshot := selectionSnapshot(t, []model.Resource{workload, sandbox})
	resources := projectedWorkloads(t, scope, snapshot, []string{"client"})
	if len(resources) != 1 || resources[0].XDSName != "client" {
		t.Fatalf("Workload demand returned %v", resources)
	}
	delta, err := (SandboxGenerator{}).Generate(t.Context(), GenerationRequest{
		Scope:        scope,
		Snapshot:     snapshot,
		TypeURL:      model.SandboxType,
		Full:         true,
		Subscription: SubscriptionView{names: []string{"sandbox"}},
	})
	if err != nil || len(delta.Resources) != 1 || delta.Resources[0].XDSName != "sandbox" {
		t.Fatalf("Sandbox demand returned %+v, error=%v", delta, err)
	}
}
