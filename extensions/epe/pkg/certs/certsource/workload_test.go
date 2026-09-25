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

package certsource

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	securityapi "istio.io/api/security/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
)

type workloadTestCA struct {
	securityapi.UnimplementedIstioCertificateServiceServer
	mu      sync.Mutex
	ca      *certstest.CA
	serving tls.Certificate
	fail    bool
	mode    string
	token   string
	serial  int64
}

func (c *workloadTestCA) CreateCertificate(
	ctx context.Context,
	req *securityapi.IstioCertificateRequest,
) (*securityapi.IstioCertificateResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return nil, status.Error(codes.Unavailable, "CA temporarily unavailable")
	}
	token := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(token) != 1 {
		return nil, status.Error(codes.Unauthenticated, "token missing")
	}
	c.token = token[0]
	block, _ := pem.Decode([]byte(req.Csr))
	if block == nil {
		return nil, status.Error(codes.InvalidArgument, "CSR missing")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	c.serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(c.serial),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Duration(req.ValidityDuration) * time.Second),
		URIs:         csr.URIs,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	publicKey := csr.PublicKey
	switch c.mode {
	case "wrong identity":
		template.URIs = []*url.URL{{Scheme: "spiffe", Host: "cluster.local", Path: "/ns/system/sa/other"}}
	case "expired":
		template.NotAfter = time.Now().Add(-time.Second)
	case "wrong usage":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "wrong key":
		publicKey = c.ca.Key.Public()
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.ca.Cert, publicKey, c.ca.Key)
	if err != nil {
		return nil, err
	}
	return &securityapi.IstioCertificateResponse{
		CertChain: []string{
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			string(c.ca.CAPEM()),
		},
	}, nil
}

func workloadFixture(t *testing.T, lifetime time.Duration) (*Workload, *workloadTestCA) {
	t.Helper()
	ca := certstest.New(t)
	server := &workloadTestCA{ca: ca, serving: ca.Loopback(t, 100, x509.ExtKeyUsageServerAuth)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer(
		grpc.Creds(
			credentials.NewTLS(
				&tls.Config{
					MinVersion: tls.VersionTLS13,
					GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
						server.mu.Lock()
						defer server.mu.Unlock()
						return &server.serving, nil
					},
				},
			),
		),
	)
	securityapi.RegisterIstioCertificateServiceServer(grpcServer, server)
	done := make(chan error, 1)
	go func() { done <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	dir := t.TempDir()
	w, err := NewWorkload(
		WorkloadOptions{
			Address:   listener.Addr().String(),
			TokenPath: filepath.Join(dir, "token"),
			RootPath:  filepath.Join(dir, "roots"),
			SPIFFEID:  "spiffe://cluster.local/ns/system/sa/epe",
			Lifetime:  lifetime,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	writeWorkloadFile(t, w.options.TokenPath, []byte("token-one"))
	writeWorkloadFile(t, w.options.RootPath, ca.CAPEM())
	return w, server
}

func writeWorkloadFile(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path+".new", value, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadAutomaticallyRenewsAndRecovers(t *testing.T) {
	w, ca := workloadFixture(t, 4*time.Second)
	if certs.CheckServing(w, true) == nil {
		t.Fatal("ready before initial issuance")
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	testsupport.Eventually(t, 15*time.Second, func() error { return certs.CheckServing(w, true) })
	first := w.current.Load().cert
	writeWorkloadFile(t, w.options.TokenPath, []byte("token-two"))
	testsupport.Eventually(t, 15*time.Second, func() error {
		if w.current.Load().cert == first {
			return fmt.Errorf("serving certificate has not rotated")
		}
		return nil
	})
	next := w.current.Load().cert
	if bytes.Equal(first.Leaf.RawSubjectPublicKeyInfo, next.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("renewal reused private key")
	}
	ca.mu.Lock()
	token := ca.token
	ca.fail = true
	ca.mu.Unlock()
	if token != "Bearer token-two" {
		t.Fatal("renewal did not reload projected token")
	}
	if certs.CheckServing(w, true) != nil {
		t.Fatal("CA outage invalidated an unexpired identity")
	}
	testsupport.Eventually(t, 15*time.Second, func() error {
		if certs.CheckServing(w, true) == nil {
			return fmt.Errorf("serving certificate has not expired")
		}
		return nil
	})
	ca.mu.Lock()
	ca.fail = false
	ca.mu.Unlock()
	testsupport.Eventually(t, 15*time.Second, func() error { return certs.CheckServing(w, true) })
}

func TestWorkloadRejectsInvalidIssuedCertificates(t *testing.T) {
	w, ca := workloadFixture(t, time.Minute)
	roots, digest, err := w.loadRoots()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.renew(t.Context(), roots, digest); err != nil {
		t.Fatal(err)
	}
	initial := w.current.Load()
	for _, mode := range []string{"wrong identity", "expired", "wrong usage", "wrong key"} {
		t.Run(mode, func(t *testing.T) {
			ca.mu.Lock()
			ca.mode = mode
			ca.mu.Unlock()
			if err := w.renew(t.Context(), roots, digest); err == nil {
				t.Fatal("accepted invalid certificate")
			}
			if w.current.Load() != initial {
				t.Fatal("invalid response replaced the usable identity")
			}
		})
	}
}

func TestWorkloadReloadsTrustAndAuthenticatesCA(t *testing.T) {
	w, server := workloadFixture(t, time.Minute)
	roots, digest, err := w.loadRoots()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.renew(t.Context(), roots, digest); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, []byte("invalid"), append(server.ca.CAPEM(), []byte("invalid trailing content")...)} {
		writeWorkloadFile(t, w.options.RootPath, raw)
		if certs.CheckServing(w, true) == nil {
			t.Fatal("accepted invalid trust bundle")
		}
	}
	if err := os.Remove(w.options.RootPath); err != nil {
		t.Fatal(err)
	}
	if _, err := w.RootCAs(); err == nil {
		t.Fatal("retained deleted trust bundle")
	}
	next := certstest.New(t)
	serving := next.Loopback(t, 101, x509.ExtKeyUsageServerAuth)
	server.mu.Lock()
	server.ca = next
	server.serving = serving
	serial := server.serial
	server.mu.Unlock()
	if err := w.renew(t.Context(), roots, digest); err == nil {
		t.Fatal("accepted CA under an untrusted root")
	}
	server.mu.Lock()
	issued := server.serial
	server.mu.Unlock()
	if issued != serial {
		t.Fatal("sent an issuance RPC to an untrusted CA")
	}
	writeWorkloadFile(t, w.options.RootPath, next.CAPEM())
	roots, digest, err = w.loadRoots()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.renew(t.Context(), roots, digest); err != nil {
		t.Fatal(err)
	}
	if err := certs.CheckServing(w, true); err != nil {
		t.Fatal(fmt.Errorf("new root did not recover: %w", err))
	}
}
