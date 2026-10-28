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
	"slices"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestClientTypeAccess(t *testing.T) {
	for _, class := range []model.ClientClass{model.ClientResourceConsumer, model.ClientDedicatedZTunnel, model.ClientEgressGateway} {
		for _, tc := range []struct {
			name      string
			resources []string
			typ       string
			allowed   bool
		}{
			{"explicit", []string{"Workload", "TrafficPolicy"}, model.WorkloadType, true},
			{"not granted", []string{"Workload", "TrafficPolicy"}, model.SecretType, false},
			{"empty", nil, model.WorkloadType, false},
			{"wildcard workload", []string{"*"}, model.WorkloadType, true},
			{"wildcard secret", []string{"*"}, model.SecretType, true},
			{"unknown denied", []string{"*"}, "type.googleapis.com/unknown.Type", false},
		} {
			t.Run(string(class)+"/"+tc.name, func(t *testing.T) {
				_, allowed := clientTypeAccess(
					model.ClientScope{Class: class, Access: &configv1.XDSClient{Resources: tc.resources}},
					tc.typ,
				)
				if allowed != tc.allowed {
					t.Fatalf("allowed = %v", allowed)
				}
			})
		}
	}
}

func TestGenericClientAuthenticatesThroughRegisteredAttestation(t *testing.T) {
	principal := mustTestPrincipal("example.com", "services/policy-reader")
	scope := model.ClientScope{Class: model.ClientResourceConsumer, Principal: principal}
	resource := addressResource(t, "cluster//Pod/other/pod-a", "pod-a")
	server := newTestServer(t, scope, []model.Resource{resource}, nil)
	const attestation = model.Attestation("external-mtls")
	server.server.authenticator = fakeAuthenticator{caller: model.PeerIdentity{AttestedBy: attestation}}
	server.server.scopeFuncs = ScopeFuncs{
		attestation: func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) { return scope, nil },
	}
	for _, tc := range []struct {
		name             string
		grantedPrincipal string
		typ              string
		resources        []string
		allowed          bool
	}{
		{"unregistered", "spiffe://example.com/other", model.WorkloadType, []string{"*"}, false},
		{"empty", principal.String(), model.WorkloadType, nil, false},
		{"explicit workload", principal.String(), model.WorkloadType, []string{"Workload"}, true},
		{"wrong type", principal.String(), model.SecretType, []string{"Workload"}, false},
		{"wildcard workload", principal.String(), model.WorkloadType, []string{"*"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server.server.SetClientAccess(
				[]*configv1.XDSClient{{Principal: tc.grantedPrincipal, Resources: tc.resources}},
			)
			stream := newFakeStream(t.Context(), 1)
			request := nodeRequest(tc.typ, resource.XDSName)
			// Self-reported principal metadata cannot override the attested principal.
			request.Node = nodeWithMetadata(map[string]string{"PRINCIPAL": tc.grantedPrincipal})
			stream.send(request)
			err := server.run(t, stream)
			if tc.allowed {
				if err != nil {
					t.Fatal(err)
				}
				responses := stream.responsesFor(tc.typ)
				if len(responses) != 1 || len(responses[0].Resources) != 1 {
					t.Fatalf("missing cluster workload: %v", responses)
				}
			} else if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want PermissionDenied", err)
			}
		})
	}
}

func TestGenericConsumerPolicyDiscoveryAndOwnership(t *testing.T) {
	policy := sharedTrafficResource(t, "trafficPolicies/other/p", securityv1.TrafficPolicy_DENY)
	worker := workloadWithTrafficRefs(t, workerResource(t, "pod-1"), policy.Key.Name)
	unused := sharedTrafficResource(t, "trafficPolicies/unreferenced", securityv1.TrafficPolicy_DENY)
	owned := gatewayResourceOfType(t, model.ClusterType, "demo/egress", "backend", "cluster")
	scope := model.ClientScope{
		Class:     model.ClientResourceConsumer,
		Principal: mustTestPrincipal("example.com", "consumer"),
	}
	server := newTestServer(t, scope, []model.Resource{worker, policy, unused, owned}, nil)
	server.server.SetClientAccess(
		[]*configv1.XDSClient{{Principal: scope.Principal.String(), Resources: []string{"*"}}},
	)
	stream := newFakeStream(t.Context(), 3)
	stream.send(nodeRequest(model.TrafficPolicyType, policy.Key.Name, unused.Key.Name))
	stream.send(
		&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResourceNamesSubscribe: []string{"backend"}},
	)
	stream.send(
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                model.WorkloadType,
			ResourceNamesSubscribe: []string{worker.XDSName},
		},
	)
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}
	policies := stream.responsesFor(model.TrafficPolicyType)
	if len(policies) != 1 || !slices.Equal(resourceNames(policies[0]), []string{policy.XDSName}) {
		t.Fatalf("policies = %v", policies)
	}
	clusters := stream.responsesFor(model.ClusterType)
	if len(clusters) != 1 || len(clusters[0].Resources) != 0 {
		t.Fatalf("gateway resource escaped ownership: %v", clusters)
	}
	workloads := stream.responsesFor(model.WorkloadType)
	if len(workloads) != 1 || len(workloads[0].Resources) != 1 {
		t.Fatalf("workloads = %v", workloads)
	}
}

func TestClientGrantChangesReauthorizeOpenStreams(t *testing.T) {
	for _, change := range []string{"remove", "restrict", "unrelated"} {
		t.Run(change, func(t *testing.T) {
			scope := model.ClientScope{
				Class:     model.ClientResourceConsumer,
				Principal: mustTestPrincipal("example.com", "reader"),
			}
			server := newTestServer(t, scope, nil, nil)
			grant := &configv1.XDSClient{
				Principal: scope.Principal.String(),
				Resources: []string{"Workload", "TrafficPolicy"},
			}
			server.server.SetClientAccess([]*configv1.XDSClient{grant})
			stream := newFakeStream(t.Context(), 4)
			done := server.start(stream)
			stream.send(nodeRequest(model.WorkloadType))
			stream.awaitResponses(t, model.WorkloadType, 1)
			switch change {
			case "remove":
				server.server.SetClientAccess(nil)
			case "restrict":
				server.server.SetClientAccess(
					[]*configv1.XDSClient{{Principal: grant.Principal, Resources: []string{"TrafficPolicy"}}},
				)
			case "unrelated":
				server.server.SetClientAccess(
					[]*configv1.XDSClient{grant, {Principal: "spiffe://example.com/other", Resources: []string{"*"}}},
				)
				stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType})
				stream.awaitResponses(t, model.TrafficPolicyType, 1)
				if err := server.finish(t, stream, done); err != nil {
					t.Fatal(err)
				}
				return
			}
			select {
			case err := <-done:
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("err = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("revoked stream stayed open")
			}
		})
	}
}
