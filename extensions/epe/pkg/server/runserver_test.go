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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

func resolveNone(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
	return engine.Resolution{}, nil
}

// listenLocal binds a loopback socket and keeps it, for handing to Config.Listener.
//
// Deliberately not the usual bind-then-close port reservation: that leaves the
// port unowned until the server binds it, and anything else on the machine can
// take it in the meantime. The test then dials an impostor and sees a bare
// connection reset — which is exactly how this suite once flaked.
func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return l
}

// TestNew_PlainServingStartsAndStops covers the non-TLS branch end to
// end (no cert generation cost) and the cancel-driven shutdown.
func TestNew_PlainServingStartsAndStops(t *testing.T) {
	rn := New(Config{
		Listener: listenLocal(t),
		Resolve:  resolveNone,
	}, logr.Discard())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rn.Start(ctx) }()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil on graceful shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runnable did not stop within 2s")
	}
}

// testCA is a throwaway ECDSA certificate authority for handshake tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "runserver-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issueLeaf signs a leaf certificate with the test CA. spiffeID may be empty.
func (ca *testCA) issueLeaf(t *testing.T, serial int64, spiffeID string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "runserver-test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		if err != nil {
			t.Fatalf("parsing SPIFFE ID %q: %v", spiffeID, err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// staticProvider is a fixed-material certs.Provider for runner tests.
type staticProvider struct {
	cert  *tls.Certificate
	roots *x509.CertPool
}

func (p *staticProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.cert, nil
}

func (p *staticProvider) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if p.cert == nil {
		// An empty certificate tells crypto/tls to send no client certificate.
		return &tls.Certificate{}, nil
	}
	return p.cert, nil
}

func (p *staticProvider) RootCAs() (*x509.CertPool, error) {
	return p.roots, nil
}

// TestNew_SecureServing covers the injected-provider TLS branch: the
// server must serve the injected certificate (not self-signed) and enforce
// required client certificate verification without identity restrictions.
func TestNew_SecureServing(t *testing.T) {
	const envoyID = "spiffe://cluster.local/ns/default/sa/envoy"
	const strangerID = "spiffe://cluster.local/ns/default/sa/stranger"

	tests := []struct {
		name              string
		requireClientCert bool
		clientCert        func(t *testing.T, ca *testCA) *tls.Certificate
		expectError       bool
	}{
		{
			name:       "injected provider certificate is served",
			clientCert: func(*testing.T, *testCA) *tls.Certificate { return nil },
		},
		{
			name:              "mTLS rejects a client without a certificate",
			requireClientCert: true,
			clientCert:        func(*testing.T, *testCA) *tls.Certificate { return nil },
			expectError:       true,
		},
		{
			name:              "mTLS accepts a trusted gateway",
			requireClientCert: true,
			clientCert: func(t *testing.T, ca *testCA) *tls.Certificate {
				cert := ca.issueLeaf(t, 20, envoyID, x509.ExtKeyUsageClientAuth)
				return &cert
			},
		},
		{
			name:              "mTLS accepts another trusted workload",
			requireClientCert: true,
			clientCert: func(t *testing.T, ca *testCA) *tls.Certificate {
				cert := ca.issueLeaf(t, 21, strangerID, x509.ExtKeyUsageClientAuth)
				return &cert
			},
		},
		{
			name:              "mTLS accepts a trusted client without a SPIFFE ID",
			requireClientCert: true,
			clientCert: func(t *testing.T, ca *testCA) *tls.Certificate {
				cert := ca.issueLeaf(t, 22, "", x509.ExtKeyUsageClientAuth)
				return &cert
			},
		},
		{
			name:              "mTLS rejects an untrusted certificate with a gateway identity",
			requireClientCert: true,
			clientCert: func(t *testing.T, _ *testCA) *tls.Certificate {
				cert := newTestCA(t).issueLeaf(t, 23, envoyID, x509.ExtKeyUsageClientAuth)
				return &cert
			},
			expectError: true,
		},
		{
			name:              "mTLS rejects a certificate restricted to server authentication",
			requireClientCert: true,
			clientCert: func(t *testing.T, ca *testCA) *tls.Certificate {
				cert := ca.issueLeaf(t, 24, envoyID, x509.ExtKeyUsageServerAuth)
				return &cert
			},
			expectError: true,
		},
		{
			name:              "mTLS rejects an expired client certificate",
			requireClientCert: true,
			clientCert: func(t *testing.T, ca *testCA) *tls.Certificate {
				cert := ca.issueLeaf(t, 25, envoyID, x509.ExtKeyUsageClientAuth)
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				leaf.NotAfter = time.Now().Add(-time.Minute)
				der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, leaf.PublicKey, ca.key)
				if err != nil {
					t.Fatal(err)
				}
				cert.Certificate = [][]byte{der}
				return &cert
			},
			expectError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newTestCA(t)
			serverCert := ca.issueLeaf(t, 10, "", x509.ExtKeyUsageServerAuth)

			// Hand the server a listener this test still holds rather than a
			// port number obtained by binding and closing: the latter leaves the
			// port unowned until the server binds, and a concurrent process that
			// takes it in between becomes an impostor this test then dials,
			// reporting a bare connection reset instead of the conflict.
			lis := listenLocal(t)
			rn := New(Config{
				Listener:          lis,
				SecureServing:     true,
				Resolve:           resolveNone,
				CertProvider:      &staticProvider{cert: &serverCert, roots: ca.pool},
				RequireClientCert: tt.requireClientCert,
			}, logr.Discard())

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- rn.Start(ctx) }()
			// A startup failure must never be swallowed. Reporting it from a
			// cleanup covers the paths where an assertion below fatals first,
			// which is how a listen error used to hide behind a dial symptom.
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("server Start: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Error("runnable did not stop within 2s")
				}
			})
			// No wait before dialing: the socket is already listening, so the
			// connection sits in the accept queue until Serve picks it up.

			clientCfg := &tls.Config{RootCAs: ca.pool, NextProtos: []string{"h2"}}
			if cert := tt.clientCert(t, ca); cert != nil {
				// Always present the supplied certificate so rejection tests exercise
				// server verification, rather than client-side issuer selection.
				clientCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return cert, nil
				}
			}
			conn, err := tls.Dial("tcp", lis.Addr().String(), clientCfg)
			if err == nil {
				// TLS 1.3 client authentication completes on the server after
				// Dial returns. Read the HTTP/2 preface to observe acceptance or
				// the TLS alert, including in successful cases.
				if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatalf("setting read deadline: %v", err)
				}
				_, err = conn.Read(make([]byte, 1))
				if err == nil {
					state := conn.ConnectionState()
					if len(state.PeerCertificates) == 0 {
						t.Fatal("no peer certificates in connection state")
					}
					if got := state.PeerCertificates[0].SerialNumber.Int64(); got != 10 {
						t.Errorf("peer certificate serial = %d, want injected certificate serial 10", got)
					}
				}
				if closeErr := conn.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if tt.expectError {
				if err == nil {
					t.Fatal("expected client certificate rejection, got nil")
				}
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					t.Fatalf("timed out instead of rejecting the certificate: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Shutdown and the Start error are asserted by the cleanup above.
		})
	}
}
