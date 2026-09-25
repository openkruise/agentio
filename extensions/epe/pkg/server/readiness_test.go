// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
)

func TestServingReadinessOnExistingConnection(t *testing.T) {
	const id = "spiffe://cluster.local/ns/system/sa/gateway"
	ca := newTestCA(t)
	serving := ca.issueLeaf(t, 10, "", x509.ExtKeyUsageServerAuth)
	client := ca.issueLeaf(t, 20, id, x509.ExtKeyUsageClientAuth)
	provider := &unavailableProvider{Provider: &staticProvider{cert: &serving, roots: ca.pool}}
	listener := listenLocal(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- New(Config{
			Listener:          listener,
			SecureServing:     true,
			Resolve:           resolveNone,
			CertProvider:      provider,
			RequireClientCert: true}, logr.Discard()).Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	var dials atomic.Int32
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{RootCAs: ca.pool, Certificates: []tls.Certificate{client}}),
		),
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	call := func(want codes.Code) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		stream, err := extprocv3.NewExternalProcessorClient(conn).Process(ctx)
		if err == nil {
			if err := stream.Send(
				&extprocv3.ProcessingRequest{
					Request: &extprocv3.ProcessingRequest_RequestHeaders{
						RequestHeaders: &extprocv3.HttpHeaders{EndOfStream: true},
					},
				},
			); err != nil && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			_, err = stream.Recv()
		}
		if status.Code(err) != want {
			t.Fatalf("stream error = %v, want %v", err, want)
		}
	}
	call(codes.OK)
	provider.unavailable.Store(true)
	call(codes.Unavailable)
	provider.unavailable.Store(false)
	call(codes.OK)
	if dials.Load() != 1 {
		t.Fatalf("used %d TCP connections, want one", dials.Load())
	}
}

// unavailableProvider simulates disappearing trust material without changing
// the certificate on an already authenticated HTTP/2 connection.
type unavailableProvider struct {
	certs.Provider
	unavailable atomic.Bool
}

func (p *unavailableProvider) RootCAs() (*x509.CertPool, error) {
	if p.unavailable.Load() {
		return nil, errors.New("trust bundle unavailable")
	}
	return p.Provider.RootCAs()
}
