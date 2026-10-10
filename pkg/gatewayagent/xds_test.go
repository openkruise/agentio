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

package gatewayagent

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
)

const sandboxType = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

type discoveryFixture struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	tokens         chan string
	requests       chan *discovery.DeltaDiscoveryRequest
	canceled       chan struct{}
	expectedHeader string
}

func (s *discoveryFixture) DeltaAggregatedResources(
	stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	if len(md.Get("authorization")) != 1 {
		return fmt.Errorf("missing authorization metadata")
	}
	if s.expectedHeader != "" && len(md.Get("x-route")) != 1 {
		return fmt.Errorf("missing custom routing header")
	}
	if s.expectedHeader != "" && md.Get("x-route")[0] != s.expectedHeader {
		return fmt.Errorf("wrong custom routing header")
	}
	s.tokens <- md.Get("authorization")[0]
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	s.requests <- request
	if err := stream.Send(&discovery.DeltaDiscoveryResponse{
		TypeUrl: sandboxType,
		Nonce:   "nonce-1",
		Resources: []*discovery.Resource{{
			Name:     "sandbox-a",
			Version:  "version-a",
			Resource: &anypb.Any{TypeUrl: sandboxType},
		}},
	}); err != nil {
		return err
	}
	ack, err := stream.Recv()
	if err != nil {
		return err
	}
	s.requests <- ack
	if err := stream.Send(&discovery.DeltaDiscoveryResponse{
		TypeUrl:          sandboxType,
		Nonce:            "nonce-2",
		RemovedResources: []string{"sandbox-a"},
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	s.canceled <- struct{}{}
	return stream.Context().Err()
}

func (s *discoveryFixture) StreamAggregatedResources(
	stream discovery.AggregatedDiscoveryService_StreamAggregatedResourcesServer,
) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	return stream.Send(&discovery.DiscoveryResponse{
		TypeUrl:     request.TypeUrl,
		VersionInfo: "sotw-version",
		Nonce:       "sotw-nonce",
		Resources:   []*anypb.Any{{TypeUrl: request.TypeUrl}},
	})
}

func TestADSRelayAndRotatedToken(t *testing.T) {
	upstream := grpc.NewServer()
	fixture := &discoveryFixture{
		tokens:   make(chan string, 2),
		requests: make(chan *discovery.DeltaDiscoveryRequest, 4),
		canceled: make(chan struct{}, 2),
	}
	discovery.RegisterAggregatedDiscoveryServiceServer(upstream, fixture)
	server := httptest.NewUnstartedServer(upstream)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(upstream.Stop)
	c := testConfig(t)
	c.Proxy.DiscoveryAddress = server.Listener.Addr().String()
	c.XDSHeaders = map[string]string{"x-route": "test-route"}
	fixture.expectedHeader = "test-route"
	c.RootCertFile = filepath.Join(t.TempDir(), "root.pem")
	c.TokenFile = filepath.Join(t.TempDir(), "token")
	root := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	if err := os.WriteFile(c.RootCertFile, root, 0o600); err != nil {
		t.Fatal(err)
	}
	c.XDSRootCertFile = c.RootCertFile
	c.RootCertFile = "/unused-workload-root"
	stop, _, err := startXDS(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	conn, err := grpc.NewClient("unix://"+c.XDSSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeResource(conn) })
	client := discovery.NewAggregatedDiscoveryServiceClient(conn)
	for i := range 2 {
		token := fmt.Sprintf("token-%d", i)
		if err := os.WriteFile(c.TokenFile, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := client.DeltaAggregatedResources(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		err = stream.Send(&discovery.DeltaDiscoveryRequest{
			TypeUrl:                 sandboxType,
			ResourceNamesSubscribe:  []string{"*"},
			InitialResourceVersions: map[string]string{"sandbox-b": "old-version"},
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		response, err := stream.Recv()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if response.Nonce != "nonce-1" || len(response.Resources) != 1 || response.Resources[0].Name != "sandbox-a" {
			cancel()
			t.Fatalf("response changed: %v", response)
		}
		ackRequest := &discovery.DeltaDiscoveryRequest{
			TypeUrl:       sandboxType,
			ResponseNonce: response.Nonce,
		}
		if i == 1 {
			ackRequest.ErrorDetail = &statuspb.Status{
				Code:    3,
				Message: "fixture rejected resource",
			}
		}
		if err := stream.Send(ackRequest); err != nil {
			cancel()
			t.Fatal(err)
		}
		removed, err := stream.Recv()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if len(removed.RemovedResources) != 1 || removed.RemovedResources[0] != "sandbox-a" {
			cancel()
			t.Fatal("deletion lost")
		}
		if got := <-fixture.tokens; got != "Bearer "+token {
			cancel()
			t.Fatalf("stale token: %s", got)
		}
		initial := <-fixture.requests
		if initial.InitialResourceVersions["sandbox-b"] != "old-version" {
			cancel()
			t.Fatal("reconnect versions lost")
		}
		ack := <-fixture.requests
		if ack.ResponseNonce != "nonce-1" {
			cancel()
			t.Fatal("ACK changed")
		}
		if ack.ErrorDetail.GetMessage() != ackRequest.ErrorDetail.GetMessage() {
			cancel()
			t.Fatal("NACK error detail was lost")
		}
		cancel()
		select {
		case <-fixture.canceled:
		case <-time.After(5 * time.Second):
			t.Fatal("canceled downstream left upstream running")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.StreamAggregatedResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&discovery.DiscoveryRequest{TypeUrl: sandboxType}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if response.Nonce != "sotw-nonce" || response.VersionInfo != "sotw-version" {
		t.Fatal("SotW response changed")
	}
}

func TestADSSocketDoesNotOverwriteFile(t *testing.T) {
	c := testConfig(t)
	if err := os.WriteFile(c.XDSSocket, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := startXDS(c); err == nil {
		t.Fatal("overwrote a regular file")
	}
	content, err := os.ReadFile(c.XDSSocket)
	if err != nil || string(content) != "keep" {
		t.Fatal("file changed")
	}
}

func TestLoopbackAdministration(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "10.0.0.1"} {
		request := httptest.NewRequest("POST", "/drain", nil)
		request.RemoteAddr = net.JoinHostPort(host, "1234")
		if got := loopbackRequest(request); got != (host != "10.0.0.1") {
			t.Fatalf("loopback(%s)=%v", host, got)
		}
	}
}
