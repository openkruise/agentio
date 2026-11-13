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

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSecurityProfileDiscoveryScope(t *testing.T) {
	var resources []model.Resource
	for _, name := range []string{"requested", "unused"} {
		r, err := model.NewResource(
			model.ResourceKey{TypeURL: model.SecurityProfileType, Name: name},
			"",
			testResourceContents(mustAny(&securityv1.SecurityProfile{Name: name})),
			nil,
			model.ResourceFacts{},
		)
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, r)
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range []model.ClientClass{model.ClientEPE, model.ClientEgressGateway, model.ClientAgentioEgress, model.ClientDedicatedZTunnel, model.ClientSharedZTunnel} {
		known, allowed := typeAccess(class, model.SecurityProfileType)
		if !known ||
			allowed != (class == model.ClientEPE || class == model.ClientEgressGateway || class == model.ClientAgentioEgress) {
			t.Fatalf("profile type access for %s: %v %v", class, known, allowed)
		}
		delta, err := (SecurityProfileGenerator{}).Generate(
			t.Context(),
			GenerationRequest{
				Scope:        model.ClientScope{Class: class},
				TypeURL:      model.SecurityProfileType,
				Snapshot:     snapshot,
				Full:         true,
				Subscription: SubscriptionView{names: []string{"requested"}},
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if class == model.ClientEPE {
			want = 1
		}
		if len(delta.Resources) != want || want == 1 && delta.Resources[0].Key.Name != "requested" {
			t.Fatalf("profile selection for %s: %v", class, delta.Resources)
		}
	}
}

func TestSecurityProfileBodyDeltaLifecycle(t *testing.T) {
	name := "namespaced/demo/shared"
	body := func(action securityv1.TCPAction) model.Resource {
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.SecurityProfileType, Name: name},
			"",
			testResourceContents(mustAny(&securityv1.SecurityProfile{
				Name: name,
				Uid:  "uid",
				TcpPolicy: &securityv1.TCPPolicy{
					Rules: []*securityv1.TCPRule{{Name: "all", Action: action, Match: []*securityv1.TCPMatch{{}}}},
				},
			})),
			nil,
			model.ResourceFacts{},
		)
		if err != nil {
			t.Fatal(err)
		}
		return resource
	}
	worker := workerResource(t, "pod-1")
	facts := worker.Facts
	facts.References = &model.ResourceReferences{
		Keys: []model.ResourceKey{{TypeURL: model.SecurityProfileType, Name: name}},
	}
	bound, err := model.NewResource(
		worker.Key,
		worker.XDSName,
		testResourceContents(testResourceValue(worker)),
		worker.Aliases,
		facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range []model.ClientClass{model.ClientEgressGateway, model.ClientAgentioEgress} {
		t.Run(string(class), func(t *testing.T) {
			scope := gatewayScope()
			scope.Class = class
			allow := body(securityv1.TCPAction_TCP_ACTION_ALLOW)
			server := newTestServer(t, scope, []model.Resource{worker, allow}, nil)
			stream := newFakeStream(t.Context(), 8)
			done := server.start(stream)
			req := nodeRequest(model.SecurityProfileType)
			req.ResourceNamesSubscribe = []string{name}
			stream.send(req)
			next := func(n int) *discoveryv3.DeltaDiscoveryResponse {
				response := stream.awaitResponses(t, model.SecurityProfileType, n)[n-1]
				stream.send(
					&discoveryv3.DeltaDiscoveryRequest{
						TypeUrl:       model.SecurityProfileType,
						ResponseNonce: response.Nonce,
					},
				)
				return response
			}
			if r := next(1); len(r.Resources) != 0 || len(r.RemovedResources) != 1 {
				t.Fatalf("unattached profile exposed: %v", r)
			}
			server.resources.publish(selectionSnapshot(t, []model.Resource{bound, allow}))
			if r := next(2); len(r.Resources) != 1 || r.Resources[0].Version != allow.Hash {
				t.Fatalf("binding did not expose profile: %v", r)
			}
			deny := body(securityv1.TCPAction_TCP_ACTION_DENY)
			server.resources.publish(selectionSnapshot(t, []model.Resource{bound, deny}))
			if r := next(3); len(r.Resources) != 1 || r.Resources[0].Version != deny.Hash {
				t.Fatalf("body update missing: %v", r)
			}
			server.resources.publish(selectionSnapshot(t, []model.Resource{worker, deny}))
			if r := next(4); len(r.Resources) != 0 || len(r.RemovedResources) != 1 {
				t.Fatalf("detached profile retained: %v", r)
			}
			if err := server.finish(t, stream, done); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, class := range []model.ClientClass{model.ClientDedicatedZTunnel} {
		known, allowed := typeAccess(class, model.SecurityProfileType)
		if !known || allowed {
			t.Fatalf("class %v: known=%v allowed=%v", class, known, allowed)
		}
	}
}
