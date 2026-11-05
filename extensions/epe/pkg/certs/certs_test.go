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
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
)

// mustErrorContains fails the test when err is nil or does not mention want.
func mustErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err.Error(), want)
	}
}

// staticProvider is a fixed-material Provider used to exercise the
// verification pipeline without touching the filesystem.
type staticProvider struct {
	cert     *tls.Certificate
	roots    *x509.CertPool
	rootsErr error
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
	return p.roots, p.rootsErr
}

// doHandshake performs a real TLS handshake over a TCP loopback connection
// and returns the client connection state. Errors from both sides are joined
// so assertions can match whichever side failed closed.
func doHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	deadline := time.Now().Add(4 * time.Second)

	srvErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			srvErrCh <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(deadline); err != nil {
			srvErrCh <- err
			return
		}
		srvErrCh <- tls.Server(conn, serverCfg).Handshake()
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatalf("setting client deadline: %v", err)
	}
	client := tls.Client(conn, clientCfg)
	clientErr := client.Handshake()
	srvErr := <-srvErrCh
	if joined := errors.Join(clientErr, srvErr); joined != nil {
		return tls.ConnectionState{}, joined
	}
	return client.ConnectionState(), nil
}

// pinLeaf returns a peer verifier that pins the expected leaf certificate.
// ClientTLSConfig requires explicit identity verification, and this keeps
// SAN-less handshake scenarios testable.
func pinLeaf(expected *x509.Certificate) func(chains [][]*x509.Certificate) error {
	return func(chains [][]*x509.Certificate) error {
		if len(chains) == 0 || len(chains[0]) == 0 || !chains[0][0].Equal(expected) {
			return errors.New("peer leaf does not match the pinned certificate")
		}
		return nil
	}
}

func TestOptionValidation(t *testing.T) {
	provider := &staticProvider{}
	verifier := func([][]*x509.Certificate) error { return nil }
	tests := []struct {
		name        string
		build       func() (*tls.Config, error)
		expectError string
	}{
		{
			name: "client with server name and peer verifier is rejected",
			build: func() (*tls.Config, error) {
				return ClientTLSConfig(provider, WithServerName("example.com"), WithPeerVerifier(verifier))
			},
			expectError: "mutually exclusive",
		},
		{
			name: "server with server name and peer verifier is rejected",
			build: func() (*tls.Config, error) {
				return ServerTLSConfig(provider, WithServerName("example.com"), WithPeerVerifier(verifier))
			},
			expectError: "mutually exclusive",
		},
		{
			name: "client with only server name is accepted",
			build: func() (*tls.Config, error) {
				return ClientTLSConfig(provider, WithServerName("example.com"))
			},
		},
		{
			name: "client with only peer verifier is accepted",
			build: func() (*tls.Config, error) {
				return ClientTLSConfig(provider, WithPeerVerifier(verifier))
			},
		},
		{
			name: "client with zero identity options is rejected",
			build: func() (*tls.Config, error) {
				return ClientTLSConfig(provider)
			},
			expectError: "exactly one of",
		},
		{
			name: "server with peer verifier but non-verifying client auth is rejected",
			build: func() (*tls.Config, error) {
				return ServerTLSConfig(provider, WithPeerVerifier(verifier), WithClientAuth(tls.RequireAnyClientCert))
			},
			expectError: "WithPeerVerifier on a server requires WithClientAuth(tls.VerifyClientCertIfGiven) or stronger",
		},
		{
			name: "server with peer verifier and verifying client auth is accepted",
			build: func() (*tls.Config, error) {
				return ServerTLSConfig(provider, WithPeerVerifier(verifier), WithClientAuth(tls.RequireAndVerifyClientCert))
			},
		},
		{
			name: "server with zero options is accepted",
			build: func() (*tls.Config, error) {
				return ServerTLSConfig(provider)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.build()
			if tc.expectError != "" {
				mustErrorContains(t, err, tc.expectError)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg == nil {
				t.Fatal("expected a non-nil tls.Config")
			}
		})
	}
}

func TestClientConfigInternals(t *testing.T) {
	// The pipeline replaces stdlib verification with an unconditional
	// VerifyPeerCertificate; InsecureSkipVerify must be set internally and the
	// callback must always be installed.
	cfg, err := ClientTLSConfig(&staticProvider{}, WithServerName("example.com"))
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify must be set internally so the manual pipeline runs")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Errorf("VerifyPeerCertificate must be unconditionally installed")
	}
}

// Both constructors pin the floor explicitly rather than inheriting whatever
// the stdlib default happens to be for the role and Go version.
func TestTLSConfigsPinMinVersion(t *testing.T) {
	clientCfg, err := ClientTLSConfig(&staticProvider{}, WithServerName("example.com"))
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if clientCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("ClientTLSConfig MinVersion = %#x, want %#x", clientCfg.MinVersion, tls.VersionTLS12)
	}

	serverCfg, err := ServerTLSConfig(&staticProvider{})
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	if serverCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("ServerTLSConfig MinVersion = %#x, want %#x", serverCfg.MinVersion, tls.VersionTLS12)
	}
}

func TestHandshake(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) (serverCfg, clientCfg *tls.Config)
		expectError string
	}{
		{
			name: "self-signed server with client trusting provider roots succeeds",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				p, err := SelfSigned()
				if err != nil {
					t.Fatalf("SelfSigned: %v", err)
				}
				serverCfg, err := ServerTLSConfig(p)
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				cert, err := p.GetCertificate(nil)
				if err != nil {
					t.Fatalf("GetCertificate: %v", err)
				}
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Fatalf("parsing leaf certificate: %v", err)
				}
				// The self-signed leaf carries no SANs, so pin it explicitly.
				clientCfg, err := ClientTLSConfig(p, WithPeerVerifier(pinLeaf(leaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
		},
		{
			name: "client rejects server presenting an unrelated certificate",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				serverCA := certstest.New(t)
				serverCert, serverLeaf := serverCA.Issue(t, certstest.LeafSpec{Serial: 100})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCA := certstest.New(t)
				// The pinned identity never runs: chain verification against the
				// unrelated CA fails first.
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: clientCA.Pool}, WithPeerVerifier(pinLeaf(serverLeaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "certificate",
		},
		{
			name: "client fails closed when provider trust anchors are unavailable",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := certstest.New(t)
				serverCert, serverLeaf := ca.Issue(t, certstest.LeafSpec{Serial: 101})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				// The pinned identity never runs: trust anchor resolution fails
				// before chain verification.
				clientCfg, err := ClientTLSConfig(&staticProvider{rootsErr: errors.New("trust anchors unavailable")}, WithPeerVerifier(pinLeaf(serverLeaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "trust anchors unavailable",
		},
		{
			name: "peer verifier replaces hostname verification for URI SAN identity",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := certstest.New(t)
				serverCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 102, URIs: []string{"spiffe://cluster.local/ns/default/sa/traffic"}})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.Pool}, WithPeerVerifier(func(chains [][]*x509.Certificate) error {
					leaf := chains[0][0]
					if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://cluster.local/ns/default/sa/traffic" {
						return errors.New("unexpected peer identity")
					}
					return nil
				}))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
		},
		{
			name: "hostname verification fails without peer verifier when no DNS SAN matches",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := certstest.New(t)
				serverCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 103, URIs: []string{"spiffe://cluster.local/ns/default/sa/traffic"}})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.Pool}, WithServerName("example.com"))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "certificate",
		},
		{
			name: "peer verifier rejection fails the handshake",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := certstest.New(t)
				serverCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 104})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.Pool}, WithPeerVerifier(func([][]*x509.Certificate) error {
					return errors.New("identity mismatch")
				}))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "identity mismatch",
		},
		{
			name: "matching DNS SAN passes hostname verification with server name",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := certstest.New(t)
				serverCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 105, DNSNames: []string{"traffic.local"}})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.Pool}, WithServerName("traffic.local"))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
		},
		{
			name: "mutual TLS succeeds when server rebuilds client CAs per handshake",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := certstest.New(t)
				serverCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 106, DNSNames: []string{"traffic.local"}})
				clientCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 107, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
				serverCfg, err := ServerTLSConfig(
					&staticProvider{cert: &serverCert, roots: ca.Pool},
					WithClientAuth(tls.RequireAndVerifyClientCert),
				)
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{cert: &clientCert, roots: ca.Pool}, WithServerName("traffic.local"))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
		},
		{
			name: "mutual TLS rejects a client certificate from an unrelated CA",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := certstest.New(t)
				otherCA := certstest.New(t)
				serverCert, serverLeaf := ca.Issue(t, certstest.LeafSpec{Serial: 108})
				clientCert, _ := otherCA.Issue(t, certstest.LeafSpec{Serial: 109, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
				serverCfg, err := ServerTLSConfig(
					&staticProvider{cert: &serverCert, roots: ca.Pool},
					WithClientAuth(tls.RequireAndVerifyClientCert),
				)
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				// The SAN-less server leaf is pinned; the failure comes from the
				// server rejecting the unrelated client chain.
				clientCfg, err := ClientTLSConfig(&staticProvider{cert: &clientCert, roots: ca.Pool}, WithPeerVerifier(pinLeaf(serverLeaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "certificate",
		},
		{
			name: "mutual TLS fails closed when server provider has no trust anchors",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := certstest.New(t)
				serverCert, serverLeaf := ca.Issue(t, certstest.LeafSpec{Serial: 110})
				clientCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 111, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
				serverCfg, err := ServerTLSConfig(
					&staticProvider{cert: &serverCert},
					WithClientAuth(tls.RequireAndVerifyClientCert),
				)
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				// The SAN-less server leaf is pinned; the failure comes from the
				// server side missing trust anchors.
				clientCfg, err := ClientTLSConfig(&staticProvider{cert: &clientCert, roots: ca.Pool}, WithPeerVerifier(pinLeaf(serverLeaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "trust anchors",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverCfg, clientCfg := tc.setup(t)
			_, err := doHandshake(t, serverCfg, clientCfg)
			if tc.expectError != "" {
				mustErrorContains(t, err, tc.expectError)
				return
			}
			if err != nil {
				t.Fatalf("unexpected handshake error: %v", err)
			}
		})
	}
}

func TestSelfSignedProvider(t *testing.T) {
	// The generated certificate must parse and carry the subject
	// organization.
	p, err := SelfSigned()
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}

	cert, err := p.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil certificate")
	}
	if cert.PrivateKey == nil {
		t.Fatal("certificate has no private key")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	if got, want := parsed.Subject.Organization[0], "OpenKruise Agents Egress Policy Enforcer"; got != want {
		t.Errorf("subject organization = %q, want %q", got, want)
	}

	clientCert, err := p.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if !reflect.DeepEqual(cert, clientCert) {
		t.Errorf("GetClientCertificate must return the same certificate as GetCertificate")
	}

	pool, err := p.RootCAs()
	if err != nil {
		t.Fatalf("RootCAs: %v", err)
	}
	if pool == nil {
		t.Fatal("RootCAs returned nil pool")
	}
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("verifying certificate against provider roots: %v", err)
	}
}
