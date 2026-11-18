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
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
	"github.com/openkruise/agentio/pkg/security/pki"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// This opt-in test uses the shipped Envoy binary with the production MITM signer,
// issuer and Delta ADS server. Kubernetes CA events and gateway identity are faked;
// certificate delivery, TTL removal, reconnects and TLS handshakes use real sockets.
func TestSDSEnvoyECDSACompatibility(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY to run the Envoy integration test")
	}
	ctx := t.Context()
	ca, err := pki.NewSelfSignedCA("compat-old", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "mitm", Namespace: "compat", UID: "compat-ca"},
		Data: map[string][]byte{"ca.crt": ca.CertificatePEM(), "ca.key": ca.PrivateKeyPEM()}}
	client := kube.NewFakeClient(secret)
	go client.Run(ctx.Done())
	signer, err := mitm.NewMITMSigner(ctx, client, mitm.MITMSignerOptions{
		Mode:       mitm.MITMSignModeSecret,
		Namespace:  secret.Namespace,
		SecretName: secret.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	waitEnvoyCompatibility(t, func() bool { return signer.State().Get() != nil }, "initial CA")
	// Keep the X.509 lifetime above the signer's one-minute minimum, while making
	// the SDS usable deadline short enough to test actual Envoy TTL eviction.
	issuer, err := mitm.NewOnDemandIssuer(
		ctx,
		mitm.DomainSignerSource{Signer: signer, State: signer.State()},
		allowCompatibilityGateway{},
		mitm.OnDemandOptions{LeafLifetime: 90 * time.Second, RenewBefore: 80 * time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}
	provider := &compatibilityCertificates{legacyCA: ca}
	provider.current.Store(issuer)
	fixture := newTestServer(t, gatewayScope(), nil, provider)
	store := xdsstore.New(fixture.resources.Snapshot())
	fixture.server.resources = store
	registration := issuer.Changes().
		Register(func(krt.Event[mitm.CertificateGeneration]) { store.NotifyType(model.SecretType) })
	t.Cleanup(registration.UnregisterHandler)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adsAddress := listener.Addr().String()
	adsPort := listener.Addr().(*net.TCPAddr).Port
	var transport *grpc.Server
	wire := &compatibilityWireCounts{}
	unavailable := make(chan struct{}, 1)
	startADS := func(l net.Listener) {
		current := grpc.NewServer(
			// Match agentiod: a large reconnect carries all initial resource versions.
			grpc.MaxRecvMsgSize(math.MaxInt32),
			grpc.StreamInterceptor(
				func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
					err := handler(srv, &compatibilityWireStream{ServerStream: stream, counts: wire})
					if status.Code(err) == codes.Unavailable {
						select {
						case unavailable <- struct{}{}:
						default:
						}
					}
					return err
				},
			),
		)
		transport = current
		discoveryv3.RegisterAggregatedDiscoveryServiceServer(current, fixture.server)
		go func() {
			if err := current.Serve(l); err != nil {
				t.Errorf("ADS serve: %v", err)
			}
		}()
	}
	startADS(listener)
	t.Cleanup(func() { transport.Stop() })
	restartADS := func() {
		transport.Stop()
		l, err := net.Listen("tcp", adsAddress)
		if err != nil {
			t.Fatal(err)
		}
		startADS(l)
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "envoy.yaml")
	adminFile := filepath.Join(dir, "admin-address")
	if err := os.WriteFile(config, []byte(fmt.Sprintf(compatibilityEnvoyBootstrap, adsPort)), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "envoy.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(
		binary,
		"-c",
		config,
		"--concurrency",
		"2",
		"--log-level",
		"warning",
		"--admin-address-path",
		adminFile,
	)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			t.Log(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Logf("Envoy exit: %v", err)
		}
		if err := logFile.Close(); err != nil {
			t.Error(err)
		}
		if t.Failed() {
			data, err := os.ReadFile(logFile.Name())
			if err != nil {
				t.Error(err)
			} else {
				t.Logf("Envoy log:\n%s", data)
			}
		}
	})
	waitEnvoyCompatibility(t, func() bool {
		_, err := os.Stat(adminFile)
		return err == nil
	}, "Envoy startup")
	waitEnvoyCompatibility(t, func() bool {
		c, err := net.DialTimeout("tcp", "127.0.0.1:18443", time.Second)
		if err != nil {
			return false
		}
		if err := c.Close(); err != nil {
			t.Error(err)
		}
		return true
	}, "TLS listener ready")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertificatePEM())
	dial := func(domain string, version uint16, ciphers []uint16) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", "127.0.0.1:18443", &tls.Config{
			RootCAs:      roots,
			ServerName:   domain,
			MinVersion:   version,
			MaxVersion:   version,
			CipherSuites: ciphers,
		})
	}
	handshake := func(t *testing.T, domain string, version uint16) *tls.Conn {
		t.Helper()
		conn, err := dial(domain, version, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeCompatibilityConnection(t, conn) })
		return conn
	}
	rsaOnly := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	old, err := dial("upgrade.example.com", tls.VersionTLS12, rsaOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCompatibilityConnection(t, old)
	if old.ConnectionState().PeerCertificates[0].PublicKeyAlgorithm != x509.RSA {
		t.Fatal("baseline was not RSA")
	}
	t.Log("PASS: original RSA certificate and RSA-only TLS 1.2 client")
	provider.ecdsa.Store(true)
	restartADS()
	var upgraded *x509.Certificate
	waitEnvoyCompatibility(t, func() bool {
		c, err := dial("upgrade.example.com", tls.VersionTLS13, nil)
		if err != nil {
			return false
		}
		defer closeCompatibilityConnection(t, c)
		leaf := c.ConnectionState().PeerCertificates[0]
		if leaf.PublicKeyAlgorithm != x509.ECDSA {
			return false
		}
		upgraded = leaf
		return true
	}, "RSA to ECDSA replacement after ADS reconnect")
	t.Log("PASS: RSA -> ECDSA on the same secret after ADS reconnect")
	// An established RSA connection must remain usable across secret replacement.
	assertCompatibilityHTTP(t, old, "upgrade.example.com")
	t.Log("PASS: existing RSA TLS connection survives ECDSA replacement")
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		c := handshake(t, "second.example.com", version)
		leaf := c.ConnectionState().PeerCertificates[0]
		key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Equal(upgraded.PublicKey) {
			t.Fatal("different domains reused an ECDSA public key")
		}
	}
	if c, err := dial("second.example.com", tls.VersionTLS12, rsaOnly); err == nil {
		closeCompatibilityConnection(t, c)
		t.Fatal("RSA-only client unexpectedly accepted ECDSA")
	}
	t.Log("PASS: verified TLS 1.2/1.3, independent domain keys, RSA-only client rejected as expected")
	if _, err := exec.LookPath("curl"); err == nil {
		caFile := filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(caFile, ca.CertificatePEM(), 0600); err != nil {
			t.Fatal(err)
		}
		for _, version := range []string{"1.2", "1.3"} {
			out, err := exec.Command("curl", "--silent", "--show-error", "--fail", "--noproxy", "*", "--max-time", "5", "--cacert", caFile,
				"--resolve", "curl.example.com:18443:127.0.0.1", "--tlsv"+version, "--tls-max", version, "https://curl.example.com:18443/").
				CombinedOutput()
			if err != nil || string(out) != "ok" {
				t.Fatalf("curl TLS %s: %s %v", version, out, err)
			}
		}
		t.Log("PASS: curl verified TLS 1.2 and TLS 1.3")
	} else {
		t.Log("curl not installed; Go TLS clients exercised both versions")
	}
	// Reconnect close to expiry must not give the cached certificate a fresh TTL.
	usableUntil := upgraded.NotAfter.Add(-80 * time.Second)
	if delay := time.Until(usableUntil.Add(-2 * time.Second)); delay > 0 {
		time.Sleep(delay)
	}
	restartADS()
	waitEnvoyCompatibility(t, func() bool {
		c, err := dial("upgrade.example.com", tls.VersionTLS13, nil)
		if err != nil {
			return false
		}
		defer closeCompatibilityConnection(t, c)
		next := c.ConnectionState().PeerCertificates[0]
		return !bytes.Equal(next.Raw, upgraded.Raw) &&
			!bytes.Equal(next.RawSubjectPublicKeyInfo, upgraded.RawSubjectPublicKeyInfo)
	}, "TTL removal and on-demand renewal across reconnect")
	t.Log("PASS: SDS TTL expiry across reconnect triggers a fresh certificate")
	nextCA, err := pki.NewSelfSignedCA("compat-new", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots.AppendCertsFromPEM(nextCA.CertificatePEM())
	secret.Data = map[string][]byte{"ca.crt": nextCA.CertificatePEM(), "ca.key": nextCA.PrivateKeyPEM()}
	if _, err := client.Kube().
		CoreV1().
		Secrets(secret.Namespace).
		Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitEnvoyCompatibility(t, func() bool {
		c, err := dial("upgrade.example.com", tls.VersionTLS13, nil)
		if err != nil {
			return false
		}
		defer closeCompatibilityConnection(t, c)
		leaf := c.ConnectionState().PeerCertificates[0]
		return leaf.Issuer.CommonName == "compat-new" && !leaf.PublicKey.(*ecdsa.PublicKey).Equal(upgraded.PublicKey)
	}, "CA rotation and leaf key replacement")
	t.Log("PASS: CA rotation replaces the CA and leaf key through live SDS")

	t.Run("issuer cancellation across ADS reconnect", func(t *testing.T) {
		source := mitm.DomainSignerSource{Signer: signer, State: signer.State()}
		newIssuer := func(ctx context.Context) *mitm.OnDemandIssuer {
			issuer, err := mitm.NewOnDemandIssuer(ctx, source, allowCompatibilityGateway{}, mitm.OnDemandOptions{
				LeafLifetime: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			return issuer
		}
		issuerCtx, cancelIssuer := context.WithCancel(t.Context())
		defer cancelIssuer()
		provider.current.Store(newIssuer(issuerCtx))
		const warmHost = "warm-before-cancel.example.com"
		held := handshake(t, warmHost, tls.VersionTLS13)
		before := held.ConnectionState().PeerCertificates[0]
		replacement := newIssuer(ctx)
		cancelIssuer()

		// Make one uncached handshake and keep it pending while the ADS stream
		// fails over. Retrying the TLS request would mask a fatal SDS removal.
		done := make(chan error, 1)
		go func() {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:18443", &tls.Config{
				RootCAs: roots, ServerName: "cold-after-cancel.example.com", MinVersion: tls.VersionTLS13,
			})
			if err == nil {
				err = c.Close()
			}
			done <- err
		}()
		select {
		case <-unavailable:
			provider.current.Store(replacement)
		case err := <-done:
			t.Fatalf("cold TLS handshake ended before ADS reconnect: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("canceled issuer did not close ADS stream with Unavailable")
		}
		if err := <-done; err != nil {
			t.Fatalf("cold TLS handshake did not recover on the new ADS stream: %v", err)
		}
		warm := handshake(t, warmHost, tls.VersionTLS13)
		if !bytes.Equal(warm.ConnectionState().PeerCertificates[0].Raw, before.Raw) {
			t.Fatal("ADS reconnect replaced a valid cached certificate")
		}
		assertCompatibilityHTTP(t, held, warmHost)
	})

	if os.Getenv("AGENTIO_TEST_SDS_HARD_EXPIRY") == "1" {
		hardIssuer, err := mitm.NewOnDemandIssuer(ctx,
			mitm.DomainSignerSource{Signer: signer, State: signer.State()}, allowCompatibilityGateway{},
			mitm.OnDemandOptions{LeafLifetime: 65 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		provider.current.Store(hardIssuer)
		before, err := dial("hard-expiry.example.com", tls.VersionTLS13, nil)
		if err != nil {
			t.Fatal(err)
		}
		expired := before.ConnectionState().PeerCertificates[0]
		closeCompatibilityConnection(t, before)
		transport.Stop()
		delay := time.Until(expired.NotAfter.Add(time.Second))
		t.Logf("HARD_EXPIRY ADS offline for %s until X.509 NotAfter", delay)
		time.Sleep(delay)
		if _, err := expired.Verify(x509.VerifyOptions{Roots: roots, DNSName: "hard-expiry.example.com"}); err == nil {
			t.Fatal("old certificate has not actually expired")
		}
		if conn, err := dial("hard-expiry.example.com", tls.VersionTLS13, nil); err == nil {
			closeCompatibilityConnection(t, conn)
			t.Fatal("handshake succeeded with ADS offline after certificate expiration")
		}
		restartADS()
		waitEnvoyCompatibility(t, func() bool {
			conn, err := dial("hard-expiry.example.com", tls.VersionTLS13, nil)
			if err != nil {
				return false
			}
			defer closeCompatibilityConnection(t, conn)
			return !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, expired.Raw)
		}, "fresh certificate after offline X.509 expiry")
		t.Log("PASS: actual X.509 expiry during ADS outage; reconnect issues a fresh valid certificate")
	}
	runEnvoyCertificateLoad(t, provider, wire, func() *mitm.MITMSigner {
		next, err := mitm.NewMITMSigner(
			ctx,
			client,
			mitm.MITMSignerOptions{Mode: mitm.MITMSignModeSecret, Namespace: secret.Namespace, SecretName: secret.Name},
		)
		if err != nil {
			t.Fatal(err)
		}
		waitEnvoyCompatibility(t, func() bool { return next.State().Get() != nil }, "new replica signer")
		return next
	}, restartADS, dial, adminFile, cmd.Process.Pid)
}

type allowCompatibilityGateway struct{}

func (allowCompatibilityGateway) Authorize(model.ClientScope) error { return nil }

type compatibilityCertificates struct {
	current  atomic.Pointer[mitm.OnDemandIssuer]
	legacyCA pki.SigningCA
	ecdsa    atomic.Bool
}

func (p *compatibilityCertificates) Authorize(scope model.ClientScope) error {
	return p.current.Load().Authorize(scope)
}
func (p *compatibilityCertificates) SignerRevision() string {
	if !p.ecdsa.Load() {
		return "legacy-rsa/" + p.legacyCA.Revision()
	}
	return p.current.Load().SignerRevision()
}
func (p *compatibilityCertificates) SignerGeneration() uint64 {
	return p.current.Load().SignerGeneration()
}

func (p *compatibilityCertificates) Get(
	ctx context.Context,
	scope model.ClientScope,
	name string,
) (mitm.SignedCertificate, error) {
	if p.ecdsa.Load() {
		return p.current.Load().Get(ctx, scope, name)
	}
	cert, err := p.legacyCA.GenerateRSA(
		ctx,
		pki.LeafOptions{CommonName: name, DNSNames: []string{name}, Lifetime: time.Hour, Server: true},
	)
	if err != nil {
		return mitm.SignedCertificate{}, err
	}
	return mitm.SignedCertificate{
		CertificateChain: pki.AppendCertificateChain(cert.CertificatePEM, p.legacyCA.BundlePEM()),
		PrivateKey:       cert.PrivateKeyPEM,
		NotAfter:         cert.NotAfter,
		UsableUntil:      cert.NotAfter,
		SignedAt:         cert.IssuedAt,
		SignerRevision:   "legacy-rsa/" + p.legacyCA.Revision(),
	}, nil
}
func closeCompatibilityConnection(t *testing.T, conn *tls.Conn) {
	t.Helper()
	if err := conn.Close(); err != nil {
		t.Logf("close TLS connection: %v", err)
	}
}

func assertCompatibilityHTTP(t *testing.T, conn *tls.Conn, host string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("existing connection response: %d %q", response.StatusCode, body)
	}
}

func waitEnvoyCompatibility(t *testing.T, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

const compatibilityEnvoyBootstrap = `
node: {id: compat, cluster: compat}
admin:
  address: {socket_address: {address: 127.0.0.1, port_value: 0}}
dynamic_resources:
  ads_config:
    api_type: DELTA_GRPC
    transport_api_version: V3
    grpc_services:
    - envoy_grpc:
        cluster_name: ads
        # Keep reconnect backoff below the test's 15s recovery deadline after a long outage.
        retry_policy:
          retry_back_off: {base_interval: 0.1s, max_interval: 1s}
static_resources:
  clusters:
  - name: ads
    type: STATIC
    connect_timeout: 1s
    http2_protocol_options: {}
    load_assignment:
      cluster_name: ads
      endpoints:
      - lb_endpoints:
        - endpoint: {address: {socket_address: {address: 127.0.0.1, port_value: %d}}}
  listeners:
  - name: tls
    address: {socket_address: {address: 127.0.0.1, port_value: 18443}}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          disable_stateless_session_resumption: true
          disable_stateful_session_resumption: true
          common_tls_context:
            custom_tls_certificate_selector:
              name: envoy.tls.certificate_selectors.on_demand_secret
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.cert_selectors.on_demand_secret.v3.Config
                config_source: {ads: {}, resource_api_version: V3}
                certificate_mapper:
                  name: envoy.tls.certificate_mappers.sni
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.cert_mappers.sni.v3.SNI
                    default_value: no-sni
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: compat
          route_config:
            name: local
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes: [{match: {prefix: "/"}, direct_response: {status: 200, body: {inline_string: ok}}}]
          http_filters:
          - name: envoy.filters.http.router
            typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}
`
