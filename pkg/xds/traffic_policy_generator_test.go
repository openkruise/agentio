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
	"reflect"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func sharedTrafficResource(t testing.TB, name string, action securityv1.TrafficPolicy_Action) model.Resource {
	t.Helper()
	body, err := anypb.New(
		&securityv1.TrafficPolicy{
			Egress: &securityv1.TrafficPolicy_RuleSet{
				Rules: []*securityv1.TrafficPolicy_Rule{{Action: action, Match: &securityv1.TrafficPolicy_Match{}}},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	r, err := model.NewResource(
		model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: name},
		"",
		testResourceContents(body),
		nil,
		model.ResourceFacts{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func workloadWithTrafficRefs(t testing.TB, workload model.Resource, names ...string) model.Resource {
	t.Helper()
	address := new(workloadv1.Address)
	if err := testResourceValue(workload).UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	reference, err := anypb.New(
		&extensionsv1.PolicyReference{TypeUrl: model.TrafficPolicyType, Resources: policyResources(names...)},
	)
	if err != nil {
		t.Fatal(err)
	}
	address.GetWorkload().Extensions = append(address.GetWorkload().Extensions,
		&workloadv1.Extension{Name: "traffic-policy-reference", Config: reference})
	body, err := anypb.New(address)
	if err != nil {
		t.Fatal(err)
	}
	facts := *workload.Facts.Workload
	facts.TrafficPolicyRefs = names
	result, err := model.NewResource(workload.Key, workload.XDSName, testResourceContents(body), workload.Aliases,
		model.ResourceFacts{Workload: &facts})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSharedTrafficPolicyWildcardUpdatesAndScope(t *testing.T) {
	worker := workerResource(t, "pod-1")
	name := "namespaces/demo/trafficPolicies/shared"
	shared := sharedTrafficResource(t, name, securityv1.TrafficPolicy_ALLOW)
	private := sharedTrafficResource(t, "namespaces/other/trafficPolicies/private", securityv1.TrafficPolicy_DENY)
	outside := workloadWithTrafficRefs(
		t,
		selectionWorkload(t, "outside", "other", "other-node", "", ""),
		private.Key.Name,
	)
	server := newTestServer(t, workerScope(worker), []model.Resource{worker, shared, private, outside}, nil)
	stream := newFakeStream(t.Context(), 8)
	done := server.start(stream)
	stream.send(nodeRequest(model.TrafficPolicyType))
	first := stream.awaitResponses(t, model.TrafficPolicyType, 1)[0]
	if len(first.Resources) != 0 {
		t.Fatalf("warm pool received unrelated policies: %v", first)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: first.Nonce})
	bound := workloadWithTrafficRefs(t, worker, name, name)
	server.resources.publish(selectionSnapshot(t, []model.Resource{bound, shared, private, outside}))
	response := stream.awaitResponses(t, model.TrafficPolicyType, 2)[1]
	if !reflect.DeepEqual(resourceNames(response), []string{name}) {
		t.Fatalf("shared policy should be delivered once: %v", response)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
	changed := sharedTrafficResource(t, name, securityv1.TrafficPolicy_DENY)
	server.resources.publish(selectionSnapshot(t, []model.Resource{bound, changed, private, outside}))
	response = stream.awaitResponses(t, model.TrafficPolicyType, 3)[2]
	if len(response.Resources) != 1 || response.Resources[0].Version != changed.Hash {
		t.Fatalf("body update missing: %v", response)
	}
	stream.send(
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                model.TrafficPolicyType,
			ResponseNonce:          response.Nonce,
			ResourceNamesSubscribe: []string{private.Key.Name},
		},
	)
	response = stream.awaitResponses(t, model.TrafficPolicyType, 4)[3]
	if len(response.Resources) != 0 || !reflect.DeepEqual(response.RemovedResources, []string{private.Key.Name}) {
		t.Fatalf("named subscribe widened scope: %v", response)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                model.TrafficPolicyType,
		ResponseNonce:          response.Nonce,
		ResourceNamesSubscribe: []string{name, name},
	})
	response = stream.awaitResponses(t, model.TrafficPolicyType, 5)[4]
	if !reflect.DeepEqual(resourceNames(response), []string{name}) || len(response.RemovedResources) != 0 {
		t.Fatalf("repeated subscribe must resend cached policy once: %v", response)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
	// The same Pod name with another source UID is no longer this client's host.
	replacement := workloadWithTrafficRefs(t, workerResource(t, "pod-2"), name)
	server.resources.publish(selectionSnapshot(t, []model.Resource{replacement, changed, private, outside}))
	response = stream.awaitResponses(t, model.TrafficPolicyType, 6)[5]
	if len(response.Resources) != 0 || !reflect.DeepEqual(response.RemovedResources, []string{name}) {
		t.Fatalf("lost scope did not withdraw policy: %v", response)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatal(err)
	}
}

func TestSharedTrafficPolicyReferencesAuthorizeOnlyTheirResources(t *testing.T) {
	worker := workerResource(t, "pod-1")
	p := sharedTrafficResource(t, "trafficPolicies/global", securityv1.TrafficPolicy_DENY)
	bound := workloadWithTrafficRefs(t, worker, p.Key.Name)
	generator := TrafficPolicyGenerator{}
	for _, tc := range []struct {
		name      string
		resources []model.Resource
		want      int
	}{
		{"unreferenced", []model.Resource{worker, p}, 0},
		{"missing body", []model.Resource{bound}, 0},
		{"resolved", []model.Resource{bound, p}, 1},
		{"removed reference", []model.Resource{workloadWithTrafficRefs(t, worker), p}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delta, err := generator.Generate(
				t.Context(),
				GenerationRequest{
					Scope:        workerScope(worker),
					TypeURL:      model.TrafficPolicyType,
					Snapshot:     selectionSnapshot(t, tc.resources),
					Full:         true,
					Subscription: SubscriptionView{wildcard: true, sent: map[string]string{p.Key.Name: "old"}},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(delta.Resources) != tc.want {
				t.Fatalf("resources: %v", delta.Resources)
			}
			if tc.want == 0 && !reflect.DeepEqual(delta.Removed, []string{p.Key.Name}) {
				t.Fatalf("removal: %v", delta.Removed)
			}
		})
	}
}

func TestWorkloadTrafficPolicyReferenceUpdates(t *testing.T) {
	worker := workerResource(t, "pod-1")
	name := "trafficPolicies/global"
	body := sharedTrafficResource(t, name, securityv1.TrafficPolicy_ALLOW)
	bound := workloadWithTrafficRefs(t, worker, name)
	nativeGateway := gatewayScope()
	nativeGateway.Class = model.ClientAgentioEgress
	for _, scope := range []model.ClientScope{workerScope(worker), gatewayScope(), nativeGateway} {
		server := newTestServer(t, scope, []model.Resource{worker, body}, nil)
		stream := newFakeStream(t.Context(), 8)
		done := server.start(stream)
		stream.send(nodeRequest(model.TrafficPolicyType))
		response := stream.awaitResponses(t, model.TrafficPolicyType, 1)[0]
		if len(response.Resources) != 0 {
			t.Fatal("unreferenced policy was exposed")
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
		server.resources.publish(selectionSnapshot(t, []model.Resource{bound, body}))
		response = stream.awaitResponses(t, model.TrafficPolicyType, 2)[1]
		if !reflect.DeepEqual(resourceNames(response), []string{name}) {
			t.Fatalf("Workload reference did not grant visibility: %v", response)
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
		body = sharedTrafficResource(t, name, securityv1.TrafficPolicy_DENY)
		server.resources.publish(selectionSnapshot(t, []model.Resource{bound, body}))
		response = stream.awaitResponses(t, model.TrafficPolicyType, 3)[2]
		if len(response.Resources) != 1 || response.Resources[0].Version != body.Hash {
			t.Fatalf("Workload policy body update missing: %v", response)
		}
		stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
		server.resources.publish(
			selectionSnapshot(t, []model.Resource{workloadWithTrafficRefs(t, worker), body}),
		)
		response = stream.awaitResponses(t, model.TrafficPolicyType, 4)[3]
		if !reflect.DeepEqual(response.RemovedResources, []string{name}) {
			t.Fatalf("removed Workload reference retained visibility: %v", response)
		}
		if err := server.finish(t, stream, done); err != nil {
			t.Fatal(err)
		}
		body = sharedTrafficResource(t, name, securityv1.TrafficPolicy_ALLOW)
	}
}

func TestSharedTrafficPolicyLastWorkloadReferenceRemoval(t *testing.T) {
	policy := sharedTrafficResource(t, "trafficPolicies/shared", securityv1.TrafficPolicy_ALLOW)
	a := workloadWithTrafficRefs(t, selectionWorkload(t, "a", "demo", "node-a", "", ""), policy.Key.Name)
	b := workloadWithTrafficRefs(t, selectionWorkload(t, "b", "demo", "node-a", "", ""), policy.Key.Name)
	both := selectionSnapshot(t, []model.Resource{a, b, policy})
	one := selectionSnapshot(t, []model.Resource{b, policy})
	none := selectionSnapshot(t, []model.Resource{policy})
	for _, scope := range []model.ClientScope{{Class: model.ClientSharedZTunnel, NodeName: "node-a"}, gatewayScope()} {
		for _, tc := range []struct {
			before  model.ResourceSet
			after   model.ResourceSet
			removed bool
		}{{both, one, false}, {one, none, true}} {
			delta, err := (TrafficPolicyGenerator{}).Generate(t.Context(), GenerationRequest{
				Scope:   scope,
				TypeURL: model.TrafficPolicyType,
				Subscription: initializedSubscription(
					t,
					TrafficPolicyGenerator{},
					scope,
					model.TrafficPolicyType,
					tc.before,
					SubscriptionView{wildcard: true},
				),
				Snapshot: tc.after,
				Update:   updateBetween(tc.before, tc.after, tc.before.Diff(tc.after)),
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(delta.Resources) != 0 || (len(delta.Removed) == 1) != tc.removed ||
				(tc.removed && delta.Removed[0] != policy.Key.Name) {
				t.Fatalf("scope %v, last reference=%v: delta=%+v", scope.Class, tc.removed, delta)
			}
		}
	}
}

func TestNativeGatewayNamedTrafficPolicySubscriptions(t *testing.T) {
	name := "namespaces/demo/trafficPolicies/shared"
	shared := sharedTrafficResource(t, name, securityv1.TrafficPolicy_ALLOW)
	unbound := sharedTrafficResource(t, "unbound", securityv1.TrafficPolicy_DENY)
	worker := workloadWithTrafficRefs(t, workerResource(t, "pod-1"), name)
	scope := gatewayScope()
	scope.Class = model.ClientAgentioEgress
	server := newTestServer(t, scope, []model.Resource{worker, shared, unbound}, nil)
	stream := newFakeStream(t.Context(), 8)
	done := server.start(stream)
	stream.send(nodeRequest(model.TrafficPolicyType, name, unbound.Key.Name))
	response := stream.awaitResponses(t, model.TrafficPolicyType, 1)[0]
	if !reflect.DeepEqual(resourceNames(response), []string{name}) ||
		!reflect.DeepEqual(response.RemovedResources, []string{unbound.Key.Name}) {
		t.Fatalf("native gateway named scope = %v", response)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.TrafficPolicyType, ResponseNonce: response.Nonce})
	server.resources.publish(
		selectionSnapshot(t, []model.Resource{workloadWithTrafficRefs(t, worker), shared, unbound}),
	)
	response = stream.awaitResponses(t, model.TrafficPolicyType, 2)[1]
	if !reflect.DeepEqual(response.RemovedResources, []string{name}) {
		t.Fatalf("native gateway retained policy after binding removal: %v", response)
	}
	if err := server.finish(t, stream, done); err != nil {
		t.Fatal(err)
	}
}

func policyResources(names ...string) []*extensionsv1.PolicyResourceReference {
	resources := make([]*extensionsv1.PolicyResourceReference, 0, len(names))
	for _, name := range names {
		resources = append(resources, &extensionsv1.PolicyResourceReference{Name: name})
	}
	return resources
}
