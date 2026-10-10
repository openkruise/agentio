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
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type idleDiscovery struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
}

func (*idleDiscovery) DeltaAggregatedResources(
	stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	if err := stream.Send(&discovery.DeltaDiscoveryResponse{TypeUrl: request.TypeUrl, Nonce: "alive"}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// Real gRPC keepalive has a 10-second lower bound. Keep this slower fault test
// opt-in, and run it in final-image validation as well as the normal short suite.
func TestADSDetectsSilentBlackhole(t *testing.T) {
	if os.Getenv("AGENTIO_TEST_NETWORK_FAULTS") == "" {
		t.Skip("set AGENTIO_TEST_NETWORK_FAULTS=1")
	}
	upstream := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(upstream, &idleDiscovery{})
	server := httptest.NewUnstartedServer(upstream)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer upstream.Stop()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var drop atomic.Bool
	var conns sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			down, err := listener.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				closeResource(down)
				continue
			}
			conns.Go(func() {
				defer closeResource(down)
				defer closeResource(up)
				done := make(chan struct{}, 2)
				copyHalf := func(dst, src net.Conn) {
					defer func() { done <- struct{}{} }()
					b := make([]byte, 32<<10)
					for {
						n, err := src.Read(b)
						if err != nil {
							return
						}
						if !drop.Load() {
							if _, err = dst.Write(b[:n]); err != nil {
								return
							}
						}
					}
				}
				go copyHalf(up, down)
				go copyHalf(down, up)
				<-done
				closeResource(down)
				closeResource(up)
				<-done
			})
		}
	}()
	defer func() {
		closeResource(listener)
		<-stopped
		conns.Wait()
	}()
	c := testConfig(t)
	c.Proxy.DiscoveryAddress = listener.Addr().String()
	c.KeepaliveInterval = 10 * time.Second
	c.KeepaliveTimeout = time.Second
	c.RootCertFile = filepath.Join(t.TempDir(), "root.pem")
	c.TokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(
		c.RootCertFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.TokenFile, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	stop, _, err := startXDS(c)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	conn, err := grpc.NewClient("unix://"+c.XDSSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(conn)
	client := discovery.NewAggregatedDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	open := func() discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesClient {
		stream, err := client.DeltaAggregatedResources(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: extensionType}); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
		return stream
	}
	stream := open()
	drop.Store(true)
	started := time.Now()
	_, err = stream.Recv()
	if err == nil || errors.Is(err, io.EOF) || ctx.Err() != nil {
		t.Fatalf("blackhole was not detected by keepalive: %v", err)
	}
	t.Logf("silent blackhole detected after %s: %v", time.Since(started), err)
	drop.Store(false)
	open()
	t.Log("new ADS stream succeeded after restoring network")
}
