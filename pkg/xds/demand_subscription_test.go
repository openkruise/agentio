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
	"slices"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

type demandRecordingGenerator struct {
	inner ResourceGenerator
	last  GenerationRequest
}

func (g *demandRecordingGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	g.last = request
	return g.inner.Generate(ctx, request)
}

func TestDemandSubscriptionPreservesOtherResources(t *testing.T) {
	for _, typeURL := range []string{model.WorkloadType, model.TrafficPolicyType, model.SandboxType} {
		t.Run(typeURL, func(t *testing.T) {
			a := addressResource(t, "a", "old")
			b := addressResource(t, "b", "b")
			changed := addressResource(t, "a", "new")
			demandName := func(name string) string { return name }
			if typeURL == model.WorkloadType {
				a.Aliases = []string{"alias-a"}
				b.Aliases = []string{"alias-b"}
				changed.Aliases = []string{"alias-a"}
				demandName = func(name string) string { return "alias-" + name }
			}
			var dependencies []model.Resource
			switch typeURL {
			case model.TrafficPolicyType:
				dependencies = []model.Resource{workloadWithTrafficRefs(t, a, "a", "b")}
				a = sharedTrafficResource(t, "a", securityv1.TrafficPolicy_ALLOW)
				b = sharedTrafficResource(t, "b", securityv1.TrafficPolicy_ALLOW)
				changed = sharedTrafficResource(t, "a", securityv1.TrafficPolicy_DENY)
			case model.SandboxType:
				a = sandboxResource(t, "a")
				b = sandboxResource(t, "b")
				changed = sandboxResourceWithAttester(t, "a", "new-attester")
			}
			recorder := &demandRecordingGenerator{inner: testGenerators(nil)[typeURL]}
			server := newTestServerWithGenerators(t, gatewayScope(), append(dependencies, a, b),
				map[string]ResourceGenerator{typeURL: recorder})
			stream := newFakeStream(t.Context(), 1)
			subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
			watches := map[string]*watchState{}
			send := func(request *discoveryv3.DeltaDiscoveryRequest) *discoveryv3.DeltaDiscoveryResponse {
				t.Helper()
				before := len(stream.sent())
				if err := server.server.handleRequest(
					stream,
					server.scope,
					log,
					watches,
					subscription,
					request,
				); err != nil {
					t.Fatal(err)
				}
				responses := stream.sent()
				if len(responses) != before+1 {
					t.Fatalf("got %d new responses, want 1", len(responses)-before)
				}
				return responses[len(responses)-1]
			}
			response := send(nodeRequest(typeURL, demandName("a")))
			for _, name := range []string{"b", "b"} {
				response = send(&discoveryv3.DeltaDiscoveryRequest{
					TypeUrl:                typeURL,
					ResourceNamesSubscribe: []string{demandName(name)},
					ResponseNonce:          response.Nonce,
				})
				if !slices.Equal(resourceNames(response), []string{name}) || len(response.RemovedResources) != 0 {
					t.Fatalf("demand must only resend %s: %v", name, response)
				}
				if !slices.Equal(recorder.last.Subscription.Names(), []string{demandName(name)}) {
					t.Fatalf("demand regenerated unrelated subscriptions: %v", recorder.last.Subscription.Names())
				}
				if len(watches[typeURL].sent) != 2 || len(watches[typeURL].names) != 2 {
					t.Fatalf("demand lost previous stream state: %+v", watches[typeURL])
				}
			}
			// The earlier subscription must still receive changes and deletions.
			for _, next := range []*model.Resource{&changed, nil} {
				before := server.resources.Snapshot()
				change := model.ResourceChange{Key: a.Key, Old: &a, New: next}
				changes := []model.ResourceChange{change}
				if next == nil && typeURL == model.TrafficPolicyType {
					unbound := workloadWithTrafficRefs(t, addressResource(t, dependencies[0].Key.Name, "unbound"), "b")
					changes = append(
						changes,
						model.ResourceChange{Key: unbound.Key, Old: &dependencies[0], New: &unbound},
					)
				}
				after, _, err := before.Apply(changes)
				if err != nil {
					t.Fatal(err)
				}
				server.resources.publish(after)
				if err := server.server.pushUpdate(stream, server.scope, log, watches,
					updateBetween(before, after, changes)); err != nil {
					t.Fatal(err)
				}
				responses := stream.sent()
				response = responses[len(responses)-1]
				if next != nil {
					if !slices.Equal(resourceNames(response), []string{"a"}) {
						t.Fatalf("lost update: %v", response)
					}
					a = *next
				} else if !slices.Equal(response.RemovedResources, []string{"a"}) {
					t.Fatalf("lost deletion: %v", response)
				}
			}
			response = send(&discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:                  typeURL,
				ResourceNamesUnsubscribe: []string{demandName("b")},
				ResponseNonce:            response.Nonce,
			})
			if len(response.RemovedResources) != 0 || len(watches[typeURL].sent) != 0 {
				t.Fatalf("unsubscribe must forget sent state without deleting the resource: %v", response)
			}
			// The client can reacquire b before receiving the unsubscribe response.
			// Even with an unchanged version, resubscription must return b.
			response = send(&discoveryv3.DeltaDiscoveryRequest{
				TypeUrl:                typeURL,
				ResourceNamesSubscribe: []string{demandName("b")},
			})
			if !slices.Equal(resourceNames(response), []string{"b"}) || len(response.RemovedResources) != 0 {
				t.Fatalf("resubscribe lost resource: %v", response)
			}
			// Initial versions must reconcile the whole restored subscription,
			// including a cached resource deleted while the client was offline.
			watches = map[string]*watchState{}
			reconnect := nodeRequest(typeURL, demandName("b"))
			reconnect.InitialResourceVersions = map[string]string{"a": "cached-before-deletion"}
			response = send(reconnect)
			if !slices.Equal(response.RemovedResources, []string{"a"}) {
				t.Fatalf("reconnect lost cached removal: %v", response)
			}
		})
	}
}

func TestDemandSubscriptionKeepsExpandedSelection(t *testing.T) {
	workload := addressResource(t, "a", "a")
	workload.Aliases = []string{"alias"}
	snapshot := selectionSnapshot(t, []model.Resource{workload, selectionService(t, "service")})
	for _, names := range [][]string{nil, {"*"}, {"service"}} {
		if _, ok := demandSubscriptionView(snapshot, model.WorkloadType, names); ok {
			t.Fatalf("%v should use complete selection", names)
		}
	}
	if _, ok := demandSubscriptionView(snapshot, model.AddressType, []string{"a"}); ok {
		t.Fatal("Address selection must retain its scope and Service expansion semantics")
	}
}

func TestDemandTrafficPolicyStillRequiresWorkloadReference(t *testing.T) {
	a := sharedTrafficResource(t, "a", securityv1.TrafficPolicy_ALLOW)
	orphan := sharedTrafficResource(t, "orphan", securityv1.TrafficPolicy_ALLOW)
	workload := workloadWithTrafficRefs(t, addressResource(t, "w", "w"), "a")
	server := newTestServer(t, gatewayScope(), []model.Resource{a, orphan, workload}, nil)
	stream := newFakeStream(t.Context(), 1)
	subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
	watches := map[string]*watchState{}
	for _, name := range []string{"a", "orphan"} {
		if err := server.server.handleRequest(stream, server.scope, log, watches, subscription,
			nodeRequest(model.TrafficPolicyType, name)); err != nil {
			t.Fatal(err)
		}
	}
	response := stream.sent()[1]
	if len(response.Resources) != 0 || !slices.Equal(response.RemovedResources, []string{"orphan"}) {
		t.Fatalf("named demand widened policy visibility: %v", response)
	}
	if _, ok := watches[model.TrafficPolicyType].sent["a"]; !ok {
		t.Fatal("denied demand removed earlier policy")
	}
}

func TestMissingTrafficPolicyDemandFlushesWorkloadBinding(t *testing.T) {
	for _, deleteBody := range []bool{false, true} {
		policy := sharedTrafficResource(t, "p", securityv1.TrafficPolicy_ALLOW)
		w := workloadWithTrafficRefs(t, addressResource(t, "w", "w"), "p")
		server := newTestServer(t, gatewayScope(), []model.Resource{policy, w}, nil)
		stream := newFakeStream(t.Context(), 1)
		subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
		watches := map[string]*watchState{}
		if err := server.server.handleRequest(stream, server.scope, log, watches, subscription,
			nodeRequest(model.WorkloadType, "w")); err != nil {
			t.Fatal(err)
		}
		unbound := workloadWithTrafficRefs(t, addressResource(t, "w", "unbound"))
		resources := []model.Resource{unbound}
		if !deleteBody {
			resources = append(resources, policy)
		}
		next, err := model.NewResourceSet(resources)
		if err != nil {
			t.Fatal(err)
		}
		server.resources.publish(next) // Deliberately leave the Workload push queued.
		if err := server.server.handleRequest(stream, server.scope, log, watches, subscription,
			nodeRequest(model.TrafficPolicyType, "p")); err != nil {
			t.Fatal(err)
		}
		sent := stream.sent()
		if len(sent) != 3 || sent[1].TypeUrl != model.WorkloadType || sent[2].TypeUrl != model.TrafficPolicyType ||
			!slices.Equal(
				resourceNames(sent[1]),
				[]string{"w"},
			) || !slices.Equal(sent[2].RemovedResources, []string{"p"}) {
			t.Fatalf("binding must precede missing policy (delete=%v): %v", deleteBody, sent)
		}
		if sent[1].SystemVersionInfo != sent[2].SystemVersionInfo {
			t.Fatal("responses used different publications")
		}
	}
}

func TestTrafficPolicyEvictionReconcilesOnlyNewDemands(t *testing.T) {
	a := sharedTrafficResource(t, "a", securityv1.TrafficPolicy_ALLOW)
	b := sharedTrafficResource(t, "b", securityv1.TrafficPolicy_ALLOW)
	c := sharedTrafficResource(t, "c", securityv1.TrafficPolicy_ALLOW)
	orphan := sharedTrafficResource(t, "orphan", securityv1.TrafficPolicy_ALLOW)
	workload := workloadWithTrafficRefs(t, addressResource(t, "w", "w"), "a", "b", "c")
	recorder := &demandRecordingGenerator{inner: TrafficPolicyGenerator{}}
	scope := gatewayScope()
	scope.Class = model.ClientAgentioEgress
	server := newTestServerWithGenerators(t, scope, []model.Resource{a, b, c, orphan, workload},
		map[string]ResourceGenerator{model.TrafficPolicyType: recorder})
	stream := newFakeStream(t.Context(), 1)
	subscription := server.resources.Subscribe(t.Context(), model.ClientScope{})
	watches := map[string]*watchState{}
	send := func(subscribed, unsubscribed []string) *discoveryv3.DeltaDiscoveryResponse {
		t.Helper()
		req := nodeRequest(model.TrafficPolicyType, subscribed...)
		req.ResourceNamesUnsubscribe = unsubscribed
		if err := server.server.handleRequest(stream, scope, log, watches, subscription, req); err != nil {
			t.Fatal(err)
		}
		responses := stream.sent()
		return responses[len(responses)-1]
	}
	send([]string{"a", "b"}, nil)
	response := send([]string{"c", "missing", "orphan"}, []string{"a"})
	if !slices.Equal(recorder.last.Subscription.Names(), []string{"c", "missing", "orphan"}) {
		t.Fatalf("eviction reselected retained policies: %v", recorder.last.Subscription.Names())
	}
	if !slices.Equal(resourceNames(response), []string{"c"}) ||
		!slices.Equal(response.RemovedResources, []string{"missing", "orphan"}) {
		t.Fatalf("eviction lost new demand or widened scope: %v", response)
	}
	watch := watches[model.TrafficPolicyType]
	if _, retained := watch.sent["a"]; retained || watch.sent["b"] != b.Hash || watch.sent["c"] != c.Hash {
		t.Fatalf("eviction corrupted sent versions: %v", watch.sent)
	}
	response = send(nil, []string{"c"})
	if len(recorder.last.Subscription.Names()) != 0 || len(response.Resources) != 0 ||
		len(response.RemovedResources) != 0 || watch.sent["b"] != b.Hash {
		t.Fatalf("unsubscribe-only request must preserve unrelated policies without regeneration: %v", response)
	}
	response = send([]string{"c"}, nil)
	if !slices.Equal(resourceNames(response), []string{"c"}) {
		t.Fatalf("unchanged policy was not returned after eviction: %v", response)
	}
	// A retained subscription must still receive subsequent policy updates.
	changed := sharedTrafficResource(t, "b", securityv1.TrafficPolicy_DENY)
	before := server.resources.Snapshot()
	change := model.ResourceChange{Key: b.Key, Old: &b, New: &changed}
	after, _, err := before.Apply([]model.ResourceChange{change})
	if err != nil {
		t.Fatal(err)
	}
	server.resources.publish(after)
	if err := server.server.pushUpdate(stream, scope, log, watches,
		updateBetween(before, after, []model.ResourceChange{change})); err != nil {
		t.Fatal(err)
	}
	responses := stream.sent()
	response = responses[len(responses)-1]
	if !slices.Equal(resourceNames(response), []string{"b"}) || watch.sent["b"] != changed.Hash {
		t.Fatalf("retained policy stopped receiving updates: %v", response)
	}
}

func TestTrafficPolicyEvictionPreservesExpandedReconciliation(t *testing.T) {
	a := sharedTrafficResource(t, "a", securityv1.TrafficPolicy_ALLOW)
	a.Aliases = []string{"alias-a"}
	b := sharedTrafficResource(t, "b", securityv1.TrafficPolicy_ALLOW)
	snapshot := selectionSnapshot(t, []model.Resource{a, b})
	for _, unsubscribed := range []string{"a", "alias-a", "*", "missing", "b"} {
		// b also appears in subscribed: unsubscribe precedence stays on the full path.
		if _, ok := demandReconciliationView(snapshot, model.TrafficPolicyType,
			gatewayScope(), &watchState{}, []string{"b"}, []string{unsubscribed}); ok {
			t.Fatalf("unsubscribe %q must retain full reconciliation semantics", unsubscribed)
		}
	}
}
