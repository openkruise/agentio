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
	"net"
	"reflect"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	registrykube "github.com/openkruise/agentio/pkg/registry/kubernetes"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// TestSandboxPriorityEndToEnd exercises informer -> registry -> compiler ->
// publication -> real gRPC Delta ADS. Only the Kubernetes API and authentication
// are fake; no compiled resources or expected ordering are injected into xDS.
func TestSandboxPriorityEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const sandboxUID = "demo--priority"
	client := priorityKubeClient{Client: kube.NewFakeClient()}
	_, err := client.AgentsAPI().AgentsV1alpha1().Sandboxes("demo").Create(ctx, &agentsv1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name: "priority", Namespace: "demo", UID: "sandbox-object-uid",
			Labels: map[string]string{"app": "priority-client"},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := registrykube.New(client, registrykube.Options{
		SandboxMode: true, ClusterID: "test", TrustDomain: "cluster.local",
		RootNamespace: "agentio-system", DebounceAfter: time.Millisecond,
		DebounceMax: 5 * time.Millisecond,
	}, ctx.Done())
	if err != nil {
		t.Fatal(err)
	}
	client.Run(ctx.Done())
	resourceCompiler, err := compiler.New(compiler.Inputs{
		SandboxMode: true, ClusterID: "test", TrustDomain: "cluster.local",
		RootNamespace: "agentio-system", DiscoveryAddress: "agentiod:15012",
		Pods: registry.Pods, KubernetesServices: registry.KubernetesServices,
		EndpointSlices: registry.EndpointSlices, Sandboxes: registry.Sandboxes,
		Workloads: registry.Workloads, Services: registry.Services,
		Endpoints: registry.Endpoints, Gateways: registry.Gateways,
		TrafficPolicies: registry.TrafficPolicies, SecurityProfiles: registry.SecurityProfiles,
		GatewayPatches: registry.GatewayPatches, Telemetry: registry.Telemetry,
		TelemetryProviderOverrides: registry.TelemetryProviderOverrides,
		AgentioConfig:              registry.AgentioConfig,
	}, krt.NewOptionsBuilder(ctx.Done(), "priority-e2e", nil))
	if err != nil {
		t.Fatal(err)
	}
	store := xdsstore.New(selectionSnapshot(t, nil))
	controller, err := NewController(resourceCompiler, store, time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-controllerDone; err != nil {
			t.Errorf("publication controller: %v", err)
		}
	})

	// Gateway scope can observe unbound Sandboxes. No runtime readiness or
	// backing Pod is needed to validate the complete published policy view.
	scope := gatewayScope()
	server, err := NewServer(fakeAuthenticator{caller: model.PeerIdentity{
		Principal: scope.Principal, AttestedBy: model.AttestationKubernetes,
	}}, fakeResolver{scope: scope}.scopeFuncs(), store, resourceCompiler.HasSynced,
		16, map[string]ResourceGenerator{model.SandboxType: SandboxGenerator{}}, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	serveDone := make(chan error, 1)
	go func() { serveDone <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		// Serve closes the listener before returning, including when Stop wins startup.
		if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve Delta ADS: %v", err)
		}
	})
	conn, err := grpc.NewClient("passthrough:///priority-e2e",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close Delta ADS connection: %v", err)
		}
	})

	// Create the larger value first: creation/arrival order must not win.
	local, err := client.AgentsAPI().AgentsV1alpha1().TrafficPolicies("demo").Create(ctx,
		&agentsv1alpha1.TrafficPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "a-local-allow", Namespace: "demo"},
			Spec:       priorityPolicySpec(100, agentsv1alpha1.RuleActionAllow),
		}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	global, err := client.AgentsAPI().AgentsV1alpha1().GlobalTrafficPolicies().Create(ctx,
		&agentsv1alpha1.GlobalTrafficPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "z-global-deny"},
			Spec:       priorityPolicySpec(10, agentsv1alpha1.RuleActionReject),
		}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !resourceCompiler.WaitUntilSynced(ctx.Done()) {
		t.Fatal("compiler did not sync")
	}
	stream, err := discoveryv3.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(nodeRequest(model.SandboxType, "*")); err != nil {
		t.Fatal(err)
	}

	type policyOrder struct {
		Name     string
		Priority int32
		Action   securityv1.TrafficPolicy_Action
	}
	globalPolicy := policyOrder{"globaltrafficpolicy/z-global-deny", 10, securityv1.TrafficPolicy_DENY}
	localPolicy := policyOrder{"trafficpolicy/demo/a-local-allow", 100, securityv1.TrafficPolicy_ALLOW}
	await := func(want ...policyOrder) string {
		t.Helper()
		for {
			response, err := stream.Recv()
			if err != nil {
				t.Fatalf("receive Sandbox policies %v: %v; compiler failures: %v", want, err, resourceCompiler.Failures())
			}
			if err := stream.Send(&discoveryv3.DeltaDiscoveryRequest{
				TypeUrl: response.TypeUrl, ResponseNonce: response.Nonce,
			}); err != nil {
				t.Fatal(err)
			}
			for _, resource := range response.Resources {
				if resource.Name != sandboxUID {
					continue
				}
				var sandbox sandboxv1.Sandbox
				if err := resource.Resource.UnmarshalTo(&sandbox); err != nil {
					t.Fatal(err)
				}
				got := make([]policyOrder, 0, len(sandbox.TrafficPolicies))
				for _, policy := range sandbox.TrafficPolicies {
					if len(policy.GetEgress().GetRules()) != 1 {
						t.Fatalf("unexpected compiled rules: %v", policy)
					}
					got = append(got, policyOrder{policy.Name, policy.Priority, policy.Egress.Rules[0].Action})
				}
				// Ignore an earlier publication until all requested source values
				// have arrived; then check order exactly, without sorting the result.
				if len(got) != len(want) {
					continue
				}
				complete := true
				for _, expected := range want {
					found := false
					for _, actual := range got {
						if actual == expected {
							found = true
							break
						}
					}
					complete = complete && found
				}
				if !complete {
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("Sandbox TrafficPolicy order = %v, want %v", got, want)
				}
				return resource.Version
			}
		}
	}
	previous := await(globalPolicy, localPolicy)
	for _, priority := range []int32{0, 10, 100} {
		local.Spec.Priority = priority
		local, err = client.AgentsAPI().AgentsV1alpha1().TrafficPolicies("demo").Update(ctx, local, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		localPolicy.Priority = priority
		want := []policyOrder{globalPolicy, localPolicy}
		if priority < globalPolicy.Priority {
			want = []policyOrder{localPolicy, globalPolicy}
		}
		version := await(want...)
		if version == previous {
			t.Fatal("priority update did not change the delivered resource version")
		}
		previous = version
	}
	if err := client.AgentsAPI().AgentsV1alpha1().GlobalTrafficPolicies().Delete(ctx, global.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	await(localPolicy)
}

func priorityPolicySpec(priority int32, action agentsv1alpha1.RuleAction) agentsv1alpha1.TrafficPolicySpec {
	return agentsv1alpha1.TrafficPolicySpec{
		Priority: priority,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "priority-client"}},
		Egress:   &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: action}}},
	}
}

// Keep the production delayed informer path, exposing only the installed Agents APIs.
type priorityKubeClient struct{ kube.Client }

func (priorityKubeClient) CrdWatcher() kube.CrdWatcher { return priorityCRDs{} }

type priorityCRDs struct{}

func (priorityCRDs) HasSynced() bool { return true }
func (priorityCRDs) KnownOrCallback(gvr schema.GroupVersionResource, _ func(<-chan struct{})) bool {
	return gvr.Group == agentsv1alpha1.GroupVersion.Group
}
func (priorityCRDs) WaitForCRD(gvr schema.GroupVersionResource, _ <-chan struct{}) bool {
	return gvr.Group == agentsv1alpha1.GroupVersion.Group
}
func (priorityCRDs) Run(stop <-chan struct{}) { <-stop }
