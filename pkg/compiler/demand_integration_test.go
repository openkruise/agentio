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

package compiler

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry"
	"github.com/openkruise/agentio/pkg/xds"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

type demandAuthenticator struct{}

func (demandAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	return model.PeerIdentity{AttestedBy: model.AttestationKubernetes}, nil
}

func TestDemandCompletion(t *testing.T) {
	for _, action := range []string{"publish", "delete", "delete-before-projection"} {
		t.Run(action, func(t *testing.T) {
			f := newIncrementalFixture(t)
			raw := krt.NewMutableCollection[model.Sandbox](nil, nil, krt.WithStop(t.Context().Done()))
			sourceRegistry := registry.NewSource(f.sandboxes.AsCollection()).Registry
			if action == "delete-before-projection" {
				sourceRegistry = registry.NewSource(raw.AsCollection()).Registry
			}

			workload := testWorkload("demo", "worker", "10.0.0.1")
			f.workloads.ConditionalUpdateObject(workload)
			sandbox := model.Sandbox{
				UID:            "kruise:pending",
				Namespace:      "demo",
				Policies:       &model.SandboxPolicies{InputError: "invalid inline policy"},
				Attester:       &model.Attester{WorkloadUID: workload.UID},
				SourceIdentity: model.SourceIdentity{UID: "source"}}
			if action != "delete-before-projection" {
				f.sandboxes.ConditionalUpdateObject(sandbox)
			} else {
				raw.UpdateObject(sandbox)
			}

			waitSynced(t, f.compiler)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			empty, err := model.NewResourceSet(nil)
			if err != nil {
				t.Fatal(err)
			}
			store := xdsstore.New(empty)
			t.Cleanup(sourceRegistry.RegisterDeletes(store.NotifyKeys))
			controller, err := xds.NewController(f.compiler, store, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			controllerDone := make(chan error, 1)
			go func() { controllerDone <- controller.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				if err := <-controllerDone; err != nil {
					t.Error(err)
				}
			})
			scope := model.ClientScope{
				Class:       model.ClientEgressGateway,
				WorkloadUID: "gateway",
				GatewayKey:  "demo/gateway",
				Source:      model.SourceRef{Registry: "kubernetes/test", Key: "gateway"},
				Principal:   model.MustPrincipal("cluster.local", "ns/demo/sa/gateway"),
			}
			observed := make(chan struct{}, 1)
			source := observedSourceReader{SourceReader: sourceRegistry, observed: observed}
			server, err := xds.NewServer(demandAuthenticator{}, xds.ScopeFuncs{
				model.AttestationKubernetes: func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) { return scope, nil },
			}, store, func() bool { return true }, 16, map[string]xds.ResourceGenerator{
				model.SandboxType: xds.SandboxGenerator{Source: source},
			}, 2, 0)
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
				if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
					t.Error(err)
				}
			})
			conn, err := grpc.NewClient(
				"passthrough:///demand",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
			)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
			})
			client, err := xdsclient.New(
				conn,
				xdsclient.Config{
					Node:    &corev3.Node{Id: "test"},
					Watches: []xdsclient.Watch{{TypeURL: model.SandboxType}},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			runDone := make(chan error, 1)
			go func() { runDone <- client.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				if err := <-runDone; err != nil {
					t.Error(err)
				}
			})
			pending := make(chan error, 1)
			go func() {
				_, err := client.Demand(ctx, model.SandboxType, sandbox.UID)
				pending <- err
			}()
			// The missing request completes on the same ADS stream while the observed
			// Sandbox remains pending; the server does not block Generate or the stream.
			if _, err := client.Demand(ctx, model.SandboxType, "missing"); !errors.Is(err, xdsclient.ErrNotFound) {
				t.Fatalf("missing: %v", err)
			}
			select {
			case err := <-pending:
				t.Fatalf("pending demand completed before policy publication: %v", err)
			default:
			}
			if action != "publish" {
				select {
				case <-observed:
				case <-ctx.Done():
					t.Fatal("pending demand was not observed")
				}
				if action == "delete-before-projection" {
					raw.DeleteObject(sandbox.UID)
				} else {
					f.sandboxes.DeleteObject(sandbox.UID)
				}
				select {
				case err := <-pending:
					if !errors.Is(err, xdsclient.ErrNotFound) {
						t.Fatalf("deleted pending demand: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("deleted source did not complete pending demand")
				}
				return
			}
			sandbox.Policies = nil
			f.sandboxes.UpdateObject(sandbox)
			select {
			case err := <-pending:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			key := model.ResourceKey{TypeURL: model.SandboxType, Name: sandbox.UID}
			resource, found := store.Snapshot().Get(key)
			if !found || resource.Facts.SourceIdentity != sandbox.SourceIdentity {
				t.Fatalf("demand returned before publication: %v, %v", resource.Facts.SourceIdentity, found)
			}
			f.sandboxes.DeleteObject(sandbox.UID)
			testutil.Eventually(t, func() bool {
				_, ok := store.Snapshot().Get(key)
				return !ok
			}, "source deletion reaches publication")
			testutil.Eventually(
				t,
				func() bool { return client.Snapshot().Resources[model.SandboxType][sandbox.UID] == nil },
				"source deletion reaches client",
			)
			if _, err := client.Demand(ctx, model.SandboxType, sandbox.UID); !errors.Is(err, xdsclient.ErrNotFound) {
				t.Fatalf("deleted: %v", err)
			}
			sandbox.UID = "kruise:timeout"
			sandbox.Policies = &model.SandboxPolicies{InputError: "invalid inline policy"}
			f.sandboxes.ConditionalUpdateObject(sandbox)
			deadline, stop := context.WithTimeout(ctx, 40*time.Millisecond)
			defer stop()
			if _, err := client.Demand(
				deadline,
				model.SandboxType,
				sandbox.UID,
			); !errors.Is(
				err,
				context.DeadlineExceeded,
			) {
				t.Fatalf("pending cancellation: %v", err)
			}
		})
	}
}

type observedSourceReader struct {
	model.SourceReader
	observed chan struct{}
}

func (s observedSourceReader) Lookup(key model.ResourceKey) (model.SourceIdentity, bool) {
	version, found := s.SourceReader.Lookup(key)
	if key.Name == "kruise:pending" && found {
		select {
		case s.observed <- struct{}{}:
		default:
		}
	}
	return version, found
}
