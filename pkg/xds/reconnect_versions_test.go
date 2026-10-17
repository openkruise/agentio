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

	"github.com/openkruise/agentio/pkg/model"
)

func TestReconnectVersionsExplicitDemandStillResends(t *testing.T) {
	for _, typ := range []string{model.WorkloadType, model.SandboxType} {
		t.Run(typ, func(t *testing.T) {
			resource := addressResource(t, "canonical", "pod", "instance/one", "/10.0.0.1")
			names := []string{"canonical", "instance/one", "/10.0.0.1"}
			if typ == model.SandboxType {
				resource = sandboxResource(t, "canonical")
				names = names[:1]
			}
			server := newTestServer(t, gatewayScope(), []model.Resource{resource}, nil)
			for _, name := range names {
				t.Run(name, func(t *testing.T) {
					stream := newFakeStream(t.Context(), 4)
					subscription := server.resources.Subscribe(t.Context())
					watches := map[string]*watchState{}
					first := nodeRequest(typ, name)
					if err := server.server.handleRequest(
						stream,
						server.scope,
						log,
						watches,
						subscription,
						first,
					); err != nil {
						t.Fatal(err)
					}
					initial := stream.sent()[0]
					if len(initial.Resources) != 1 {
						t.Fatalf("initial response: %v", initial)
					}
					cached := initial.Resources[0]
					reconnect := nodeRequest(typ, name)
					reconnect.InitialResourceVersions = map[string]string{cached.Name: cached.Version}
					if err := server.server.handleRequest(
						stream,
						server.scope,
						log,
						map[string]*watchState{},
						subscription,
						reconnect,
					); err != nil {
						t.Fatal(err)
					}
					restored := stream.sent()[1]
					if len(restored.Resources) != 1 || restored.Resources[0].Version != cached.Version {
						t.Fatalf("explicit subscribe must resend the unchanged resource: %v", restored)
					}
					t.Logf("same-version explicit demand: resource=%s responses=%d", name, len(restored.Resources))
				})
			}
		})
	}
}

func TestReconnectVersionsWildcardSkipsUnchangedButWidensScope(t *testing.T) {
	a := addressResource(t, "a", "a", "instance/a")
	b := addressResource(t, "b", "b", "instance/b")
	server := newTestServer(t, gatewayScope(), []model.Resource{a, b}, nil)
	stream := newFakeStream(t.Context(), 4)
	subscription := server.resources.Subscribe(t.Context())
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		map[string]*watchState{},
		subscription,
		nodeRequest(model.WorkloadType, "instance/a"),
	); err != nil {
		t.Fatal(err)
	}
	cached := stream.sent()[0].Resources[0]
	req := nodeRequest(model.WorkloadType, "*")
	req.InitialResourceVersions = map[string]string{cached.Name: cached.Version}
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		map[string]*watchState{},
		subscription,
		req,
	); err != nil {
		t.Fatal(err)
	}
	got := stream.sent()[1]
	if !slices.Equal(resourceNames(got), []string{"b"}) {
		t.Fatalf("wildcard should skip cached a but fetch unrelated b: %v", got)
	}
	req.InitialResourceVersions["b"] = got.Resources[0].Version
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		map[string]*watchState{},
		subscription,
		req,
	); err != nil {
		t.Fatal(err)
	}
	if got := stream.sent()[2]; len(got.Resources) != 0 || len(got.RemovedResources) != 0 {
		t.Fatalf("fully known wildcard should get an empty initial response: %v", got)
	}
}

func TestReconnectCanonicalInterestDoesNotTrackNewAliasOwner(t *testing.T) {
	for _, shared := range []string{"instance/one", "/10.0.0.1"} {
		t.Run(shared, func(t *testing.T) {
			a := addressResource(t, "a", "a", shared)
			b := addressResource(t, "b", "b", shared)
			server := newTestServer(t, gatewayScope(), []model.Resource{a}, nil)
			stream := newFakeStream(t.Context(), 4)
			subscription := server.resources.Subscribe(t.Context())
			if err := server.server.handleRequest(
				stream,
				server.scope,
				log,
				map[string]*watchState{},
				subscription,
				nodeRequest(model.WorkloadType, shared),
			); err != nil {
				t.Fatal(err)
			}
			cached := stream.sent()[0].Resources[0]
			// The old owner is unchanged. A second owner appeared while disconnected.
			server.resources.publish(selectionSnapshot(t, []model.Resource{a, b}))
			for _, name := range []string{"a", shared} {
				req := nodeRequest(model.WorkloadType, name)
				req.InitialResourceVersions = map[string]string{cached.Name: cached.Version}
				if err := server.server.handleRequest(
					stream,
					server.scope,
					log,
					map[string]*watchState{},
					subscription,
					req,
				); err != nil {
					t.Fatal(err)
				}
				responses := stream.sent()
				got := responses[len(responses)-1]
				want := []string{"a"}
				if name == shared {
					want = append(want, "b")
				}
				if !slices.Equal(resourceNames(got), want) {
					t.Fatalf("subscription %q: got %v want %v", name, resourceNames(got), want)
				}
				t.Logf("subscription=%q resolved owners=%v", name, resourceNames(got))
			}
		})
	}
}

func TestReconnectVersionsReconcilesAliasRebindingAndRemoval(t *testing.T) {
	old := addressResource(t, "old", "old", "instance/one")
	replacement := addressResource(t, "replacement", "replacement", "instance/one")
	server := newTestServer(t, gatewayScope(), []model.Resource{old}, nil)
	stream := newFakeStream(t.Context(), 4)
	subscription := server.resources.Subscribe(t.Context())
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		map[string]*watchState{},
		subscription,
		nodeRequest(model.WorkloadType, "instance/one"),
	); err != nil {
		t.Fatal(err)
	}
	cached := stream.sent()[0].Resources[0]
	server.resources.publish(selectionSnapshot(t, []model.Resource{replacement}))
	req := nodeRequest(model.WorkloadType, "instance/one")
	req.InitialResourceVersions = map[string]string{cached.Name: cached.Version}
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		map[string]*watchState{},
		subscription,
		req,
	); err != nil {
		t.Fatal(err)
	}
	got := stream.sent()[1]
	if !slices.Equal(resourceNames(got), []string{"replacement"}) ||
		!slices.Equal(got.RemovedResources, []string{"old"}) {
		t.Fatalf("reconnect lost rebinding or deletion: %v", got)
	}
}
