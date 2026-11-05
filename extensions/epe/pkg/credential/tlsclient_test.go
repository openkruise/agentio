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
package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// swappableSource is a certs.Provider whose material can appear or change while
// an http.Client built from it is already in use, standing in for a file or
// Secret source that fills in later.
type swappableSource struct {
	cert atomic.Pointer[tls.Certificate]
	pool atomic.Pointer[x509.CertPool]
}

func (s *swappableSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := s.cert.Load()
	if cert == nil {
		return nil, errors.New("no certificate loaded")
	}
	return cert, nil
}

func (s *swappableSource) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert := s.cert.Load()
	if cert == nil {
		// An empty certificate presents no client identity.
		return &tls.Certificate{}, nil
	}
	return cert, nil
}

func (s *swappableSource) RootCAs() (*x509.CertPool, error) {
	return s.pool.Load(), nil
}

func (s *swappableSource) set(cert tls.Certificate, pool *x509.CertPool) {
	s.pool.Store(pool)
	s.cert.Store(&cert)
}

// transportTLSConfig returns the TLS config behind an HTTP client's transport.
func transportTLSConfig(t *testing.T, c *http.Client) *tls.Config {
	t.Helper()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	return tr.TLSClientConfig
}

// tlsFixture is a throwaway CA plus the leaves a loopback mTLS handshake needs.
type tlsFixture struct {
	caPool     *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "credential-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	issue := func(serial int64, usage x509.ExtKeyUsage, ips []net.IP) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating leaf key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "credential-test-leaf"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("creating leaf certificate: %v", err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parsing leaf certificate: %v", err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	}

	return &tlsFixture{
		caPool: pool,
		// The provider is reached at https://127.0.0.1:port, so the server leaf
		// needs the matching IP SAN for hostname verification to pass.
		serverCert: issue(2, x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}),
		clientCert: issue(3, x509.ExtKeyUsageClientAuth, nil),
	}
}

// startMTLSServer starts a TLS server that demands a client certificate and
// records whether the last request carried one.
func startMTLSServer(t *testing.T, f *tlsFixture, sawClientCert *atomic.Bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawClientCert.Store(r.TLS != nil && len(r.TLS.PeerCertificates) > 0)
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{f.serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestBuildHTTPClientPresentsProviderCertificate(t *testing.T) {
	f := newTLSFixture(t)
	var sawClientCert atomic.Bool
	srv := startMTLSServer(t, f, &sawClientCert)

	src := &swappableSource{}
	src.set(f.clientCert, f.caPool)

	resp, err := NewHTTPClient(src, srv.URL, false).Get(srv.URL)
	if err != nil {
		t.Fatalf("request against the mTLS provider failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !sawClientCert.Load() {
		t.Error("provider saw no client certificate")
	}
}

// The regression test for the defect this change exists to fix: material that
// appears after the http.Client was built is used, with no rebuild and no
// restart.
func TestBuildHTTPClientUsesMaterialThatAppearsLater(t *testing.T) {
	f := newTLSFixture(t)
	var sawClientCert atomic.Bool
	srv := startMTLSServer(t, f, &sawClientCert)

	src := &swappableSource{}
	client := NewHTTPClient(src, srv.URL, false)

	// Nothing loaded yet: no client identity and no trust anchors.
	if resp, err := client.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded before any material was available")
	}

	src.set(f.clientCert, f.caPool)

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed after material became available: %v", err)
	}
	defer resp.Body.Close()
	if !sawClientCert.Load() {
		t.Error("provider saw no client certificate after material became available")
	}
}

// insecureSkipVerify turns off server verification only. The client identity is
// orthogonal and must still be presented, which is the combination a
// self-signed provider requiring mTLS needs.
func TestBuildHTTPClientInsecureStillPresentsClientCertificate(t *testing.T) {
	f := newTLSFixture(t)
	var sawClientCert atomic.Bool
	srv := startMTLSServer(t, f, &sawClientCert)

	src := &swappableSource{}
	// No trust anchors at all: insecure mode must not need them.
	src.set(f.clientCert, nil)

	client := NewHTTPClient(src, srv.URL, true)
	cfg := transportTLSConfig(t, client)
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is not set")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS12)
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("insecure request against an mTLS provider failed: %v", err)
	}
	defer resp.Body.Close()
	if !sawClientCert.Load() {
		t.Error("provider saw no client certificate in insecure mode")
	}
}

func TestBuildHTTPClientWithoutProviderPresentsNoIdentity(t *testing.T) {

	client := NewHTTPClient(nil, "https://provider.example.com", false)

	cfg := transportTLSConfig(t, client)
	if cfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate is not installed")
	}
	cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if len(cert.Certificate) != 0 {
		t.Errorf("presented %d certificates with no provider, want 0", len(cert.Certificate))
	}
}

func TestNewHTTPClientDerivesServerNameFromURL(t *testing.T) {
	client := NewHTTPClient(nil, "https://provider.example.com/creds", false)
	if got := transportTLSConfig(t, client).ServerName; got != "provider.example.com" {
		t.Errorf("ServerName = %q, want the provider host", got)
	}
}

// Per-handshake material only takes effect on a new handshake, so idle
// connection reuse has to be bounded or a rotated certificate can sit unused
// for as long as the provider keeps the connection open.
func TestBuildHTTPClientBoundsIdleConnectionReuse(t *testing.T) {
	tr, ok := NewHTTPClient(nil, "https://provider.example.com", false).Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", NewHTTPClient(nil, "", false).Transport)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
	}
}

// A provider URL that parses but carries no host must not silently produce a
// client that fails every handshake with an opaque TLS error.
func TestProviderHostRejectsHostlessURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{name: "absolute https URL", url: "https://provider.example.com/creds", want: "provider.example.com"},
		{name: "host and port", url: "https://provider.example.com:8443/creds", want: "provider.example.com"},
		{name: "unset is not an error", url: "", want: ""},
		{name: "no scheme has no host", url: "provider.example.com:8443/creds", wantErr: true},
		{name: "bare host has no host", url: "provider.example.com/creds", wantErr: true},
		{name: "malformed", url: "http://[::1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := providerHost(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("providerHost(%q) = %q, want an error", tc.url, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("providerHost(%q): %v", tc.url, err)
			}
			if got != tc.want {
				t.Errorf("providerHost(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}
