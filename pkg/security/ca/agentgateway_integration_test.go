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

package ca

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	securityapi "istio.io/api/security/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/pki"
)

// Tests agentgateway certificate issuance and rotation against Agentiod's CA over TLS.
// TokenReview and target authorization are faked; the proxy obtains its own certificates.
// Run with AGENTIO_AGENTGATEWAY_BINARY=/absolute/path/to/agentgateway-v1.7.0.
func TestAgentgatewayNativeCACertificateRotation(t *testing.T) {
	binary := os.Getenv("AGENTIO_AGENTGATEWAY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_AGENTGATEWAY_BINARY to run native CA interoperability")
	}
	version, err := exec.Command(binary, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	var build struct {
		Version     string `json:"version"`
		GitRevision string `json:"git_revision"`
	}
	const upstreamRevision = "26f5aebe99a36a037fe54f8080a608aca5547e15" // v1.7.0
	if err := json.Unmarshal(
		version,
		&build,
	); err != nil ||
		(build.Version != "1.7.0" && !strings.HasPrefix(build.Version, "1.7.0-agentio") && build.GitRevision != upstreamRevision) {
		t.Fatalf("this contract pins agentgateway 1.7.0, got %s (%v)", version, err)
	}

	const audience = "gateway-test-ca"
	const identity = "spiffe://mesh.example/ns/gateway-ns/sa/gateway-account"
	const token1, token2 = "synthetic-gateway-token-1", "synthetic-gateway-token-2"
	var sawRotatedToken, denyToken, rejected atomic.Bool
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		req := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		ok := len(req.Spec.Audiences) == 1 && req.Spec.Audiences[0] == audience &&
			(req.Spec.Token == token1 || req.Spec.Token == token2) && !denyToken.Load()
		if req.Spec.Token == token2 {
			sawRotatedToken.Store(true)
		}
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
			Authenticated: ok,
			Audiences:     []string{audience},
			User: authenticationv1.UserInfo{
				Username: "system:serviceaccount:gateway-ns:gateway-account",
				Groups:   []string{"system:serviceaccounts"},
			},
		}}, nil
	})
	reviewer, err := attestation.NewTokenReviewer(client, []string{audience})
	if err != nil {
		t.Fatal(err)
	}
	authority := newTestAuthority(t, time.Hour, 20*time.Minute)
	authority.authenticator = reviewer
	authority.options.TrustDomain = "mesh.example"
	authority.UseDelegatedIdentityAuthorizer(&fakeDelegatedIdentityAuthorizer{
		authorize: func(_ context.Context, _ model.PeerIdentity, target model.Principal) error {
			if target.String() != identity {
				return fmt.Errorf("unexpected gateway identity %s", target)
			}
			return nil
		},
	})
	// With Agentiod's one-minute clock skew, this reaches the native client's
	// half-life renewal point before its first 30-second refresh tick.
	authority.leafLifetime = 90 * time.Second
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(authority.TLSConfig())),
		grpc.UnaryInterceptor(
			func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				resp, err := handler(ctx, req)
				if err != nil {
					rejected.Store(true)
				}
				return resp, err
			},
		),
	)
	securityapi.RegisterIstioCertificateServiceServer(server, authority)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-serveErr; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve CA: %v", err)
		}
	})

	dir := t.TempDir()
	rootPath, tokenPath := filepath.Join(dir, "root-cert.pem"), filepath.Join(dir, "token")
	writeFile := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(rootPath, authority.rootPEM)
	writeFile(tokenPath, []byte(token1))
	port := agentgatewayTestPort(t)
	config := fmt.Sprintf(`config:
  adminAddr: 127.0.0.1:0
  statsAddr: 127.0.0.1:0
  readinessAddr: 127.0.0.1:0
binds:
- port: %d
  tunnelProtocol: hboneGateway
  listeners:
  - protocol: HBONE
- port: 18080
  mode: internal
  protocol: AUTO
  listeners:
  - protocol: HTTP
    routes:
    - policies:
        directResponse:
          status: 200
          body: native-ca-hbone
`, port)
	configPath := filepath.Join(dir, "config.yaml")
	writeFile(configPath, []byte(config))
	logs, err := os.Create(filepath.Join(dir, "agentgateway.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-f", configPath)
	// Keep the test independent of any mesh or proxy settings on the host.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"NAMESPACE=gateway-ns", "SERVICE_ACCOUNT=gateway-account", "TRUST_DOMAIN=mesh.example",
		"CLUSTER_ID=test", "CA_ADDRESS=https://localhost:" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port),
		"CA_AUTH_TOKEN=" + tokenPath, "CA_ROOT_CA=" + rootPath,
		"IPV6_ENABLED=false", "WORKER_THREADS=1",
	}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		agentgatewayClose(t, logs)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("stop agentgateway: %v", err)
		}
		if err := cmd.Wait(); err != nil {
			// Killing the test process normally produces an ExitError.
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Errorf("wait for agentgateway: %v", err)
			}
		}
		agentgatewayClose(t, logs)
		if t.Failed() {
			data, err := os.ReadFile(logs.Name())
			if err != nil {
				t.Logf("read agentgateway output: %v", err)
				return
			}
			t.Logf("agentgateway output:\n%s", data)
		}
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientID := &url.URL{Scheme: "spiffe", Host: "mesh.example", Path: "/ns/client/sa/app"}
	leaf, err := authority.ca.Sign(
		context.Background(),
		&key.PublicKey,
		pki.LeafOptions{URIs: []*url.URL{clientID}, Lifetime: time.Hour, Client: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := tls.X509KeyPair(
		leaf.CertificatePEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(authority.rootPEM)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{clientCert},
		// SPIFFE identities use URI SAN verification instead of DNS names.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			cert := state.PeerCertificates[0]
			intermediates := x509.NewCertPool()
			for _, c := range state.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			if _, err := cert.Verify(
				x509.VerifyOptions{
					Roots:         roots,
					Intermediates: intermediates,
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				},
			); err != nil {
				return err
			}
			if len(cert.URIs) != 1 || cert.URIs[0].String() != identity {
				return fmt.Errorf("unexpected gateway identity: %v", cert.URIs)
			}
			return nil
		},
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	var firstSerial string
	agentgatewayEventually(t, 15*time.Second, func() error {
		serial, err := agentgatewayHBONERequest(t, address, tlsConfig)
		if err == nil {
			firstSerial = serial
		}
		return err
	})
	t.Log("native CA issued gateway identity; mTLS HTTP/2 CONNECT reached internal HTTP route")
	withoutClient := tlsConfig.Clone()
	withoutClient.Certificates = nil
	if _, err := agentgatewayHBONERequest(t, address, withoutClient); err == nil {
		t.Fatal("HBONE accepted a client without a workload certificate")
	}
	otherID := &url.URL{Scheme: "spiffe", Host: "other.example", Path: "/ns/client/sa/app"}
	otherLeaf, err := authority.ca.Sign(
		context.Background(),
		&key.PublicKey,
		pki.LeafOptions{URIs: []*url.URL{otherID}, Lifetime: time.Hour, Client: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	otherCert, err := tls.X509KeyPair(
		otherLeaf.CertificatePEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	otherDomain := tlsConfig.Clone()
	otherDomain.Certificates = []tls.Certificate{otherCert}
	if _, err := agentgatewayHBONERequest(t, address, otherDomain); err == nil {
		t.Fatal("HBONE accepted a client from an untrusted SPIFFE trust domain")
	}
	// Rename models the projected token volume switching to its next token.
	writeFile(tokenPath+".next", []byte(token2))
	if err := os.Rename(tokenPath+".next", tokenPath); err != nil {
		t.Fatal(err)
	}
	agentgatewayEventually(t, 50*time.Second, func() error {
		serial, err := agentgatewayHBONERequest(t, address, tlsConfig)
		if err != nil {
			return err
		}
		if serial == firstSerial || !sawRotatedToken.Load() {
			return fmt.Errorf("waiting for renewed certificate and token reload")
		}
		return nil
	})
	t.Log("renewed certificate served on new HBONE connections without restarting the process")

	// Pin upstream's fail-closed behavior on renewal errors and its retry recovery.
	// v1.7.0 replaces the cached certificate state with the CA error, even before
	// the previous certificate expires. Do not promise old-certificate fallback.
	denyToken.Store(true)
	agentgatewayEventually(t, 50*time.Second, func() error {
		if !rejected.Load() {
			return fmt.Errorf("waiting for rejected renewal")
		}
		if _, err := agentgatewayHBONERequest(t, address, tlsConfig); err == nil {
			return fmt.Errorf("gateway still accepting new connections")
		}
		return nil
	})
	denyToken.Store(false)
	agentgatewayEventually(
		t,
		40*time.Second,
		func() error {
			_, err := agentgatewayHBONERequest(t, address, tlsConfig)
			return err
		},
	)
	t.Log("rejected renewal blocks new HBONE connections; automatic retry restores service")
}

func agentgatewayTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	agentgatewayClose(t, listener)
	return port
}

func agentgatewayEventually(t *testing.T, timeout time.Duration, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := check()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func agentgatewayClose(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close %T: %v", closer, err)
	}
}

func agentgatewayHBONERequest(t *testing.T, address string, config *tls.Config) (string, error) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, config)
	if err != nil {
		return "", err
	}
	defer agentgatewayClose(t, conn)
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	serial := conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	transport := &http2.Transport{}
	client, err := transport.NewClientConn(conn)
	if err != nil {
		return "", err
	}
	defer agentgatewayClose(t, client)
	reader, writer := io.Pipe()
	defer agentgatewayClose(t, reader)
	defer agentgatewayClose(t, writer)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := (&http.Request{Method: http.MethodConnect, URL: &url.URL{Host: "127.0.0.1:18080"}, Host: "127.0.0.1:18080", Body: reader}).WithContext(ctx)
	resp, err := client.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer agentgatewayClose(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("CONNECT status: %s", resp.Status)
	}
	if _, err := io.WriteString(writer, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"); err != nil {
		return "", err
	}
	inner, err := http.ReadResponse(bufio.NewReader(resp.Body), nil)
	if err != nil {
		return "", err
	}
	defer agentgatewayClose(t, inner.Body)
	body, err := io.ReadAll(inner.Body)
	if err != nil {
		return "", err
	}
	if inner.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "native-ca-hbone" {
		return "", fmt.Errorf("unexpected tunneled response: %s %q", inner.Status, body)
	}
	return serial, nil
}
