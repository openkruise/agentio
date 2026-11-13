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

// Assembly-level test: proves server.New wires the profile store, plugin
// chain, and audit logger into a working ExternalProcessor over a real
// gRPC transport — the one layer the in-process enginetest harness skips.
package server_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	policysecurityprofile "github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	runserver "github.com/openkruise/agentio/extensions/epe/pkg/server"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
)

// listenLocal binds a loopback socket and keeps it, for handing to
// Config.Listener. Reserving a port by binding and closing one instead leaves it
// unowned until the server binds, so anything else on the machine can take it
// and this test would then dial an impostor.
func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	return l
}

func TestAsRunnable_ServesConfiguredChainOverGRPC(t *testing.T) {
	fixture := securityprofile.NewFixture(t)
	fixture.ApplyYAML(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: grpc-block
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: block
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /grpc/blocked
    actions:
      block:
        statusCode: 451
        body: blocked-over-grpc
`)

	lis := listenLocal(t)
	providers := &extensionprovider.Registry{}
	t.Cleanup(providers.Close)
	deps := wiring.Deps{Providers: providers}
	regs, err := wiring.BuildFilters(deps)
	if err != nil {
		t.Fatalf("BuildFilters: %v", err)
	}
	rn := runserver.New(runserver.Config{
		Listener:      lis,
		Resolve:       policysecurityprofile.NewResolver(fixture.Store, regs, nil, nil),
		Registrations: regs,
	}, logr.Discard())

	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- rn.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("server exited with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := extProcPb.NewExternalProcessorClient(conn)

	run := func(path string) *enginetest.Verdict {
		t.Helper()
		msgs := enginetest.NewRequest("GET", "server.example.com", path).
			Workload("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
			Build()

		var responses []*extProcPb.ProcessingResponse
		var verdict *enginetest.Verdict
		// The socket is bound before Start runs, so a connection queues
		// rather than failing; this retry only covers a transient error
		// during the server's own startup.
		testsupport.Eventually(t, 10*time.Second, func() error {
			responses = responses[:0]
			stream, err := client.Process(ctx)
			if err == nil {
				err = sendAll(stream, msgs)
			}
			if err == nil {
				responses, err = recvAll(stream)
			}
			if err != nil {
				return err
			}
			verdict = enginetest.ParseVerdict(responses, nil)
			return nil
		})
		return verdict
	}

	run("/grpc/blocked").RequireBlockedBody(t, 451, "blocked-over-grpc")
	// This drives the real gRPC server rather than enginetest.Harness, so there
	// is no capturing audit logger and RequirePassthrough (which reads the
	// logged outcome) has nothing to read. The wire shape is what this test is
	// about anyway: the open path must come back unmodified.
	if got := run("/grpc/open"); got.Kind != enginetest.VerdictPassthrough {
		t.Fatalf("verdict = %s, want passthrough over gRPC (raw=%v)", got.Kind, got.Raw)
	}
}

func sendAll(stream extProcPb.ExternalProcessor_ProcessClient, msgs []*extProcPb.ProcessingRequest) error {
	for _, msg := range msgs {
		if err := stream.Send(msg); err != nil {
			return err
		}
	}
	return stream.CloseSend()
}

func recvAll(stream extProcPb.ExternalProcessor_ProcessClient) ([]*extProcPb.ProcessingResponse, error) {
	var responses []*extProcPb.ProcessingResponse
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return responses, nil
		}
		if err != nil {
			return nil, err
		}
		responses = append(responses, resp)
	}
}
