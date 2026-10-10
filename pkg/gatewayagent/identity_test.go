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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	ca "github.com/openkruise/agentio/pkg/gatewayagent/internal/caproto"
)

type testCA struct {
	ca.UnimplementedIstioCertificateServiceServer
	key            *ecdsa.PrivateKey
	cert           *x509.Certificate
	root           []byte
	tokens         chan string
	wrongIdentity  atomic.Bool
	fail           atomic.Bool
	beforeSign     func(context.Context) error
	expectedSigner string
	expectedHeader string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{
		key:    key,
		cert:   cert,
		root:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		tokens: make(chan string, 16),
	}
}

func (c *testCA) CreateCertificate(
	ctx context.Context,
	request *ca.IstioCertificateRequest,
) (*ca.IstioCertificateResponse, error) {
	if c.beforeSign != nil {
		if err := c.beforeSign(ctx); err != nil {
			return nil, err
		}
	}
	if c.expectedSigner != "" && request.Metadata.GetFields()["CertSigner"].GetStringValue() != c.expectedSigner {
		return nil, fmt.Errorf("wrong certificate signer")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	if c.expectedHeader != "" && (len(md.Get("x-ca-route")) != 1 || md.Get("x-ca-route")[0] != c.expectedHeader) {
		return nil, fmt.Errorf("missing CA routing header")
	}
	if len(md.Get("authorization")) != 1 || len(md.Get("clusterid")) != 1 {
		return nil, fmt.Errorf("missing CA authentication")
	}
	c.tokens <- md.Get("authorization")[0]
	if c.fail.Load() {
		return nil, status.Error(codes.Unavailable, "CA unavailable")
	}
	block, _ := pem.Decode([]byte(request.Csr))
	if block == nil {
		return nil, fmt.Errorf("missing CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	if len(csr.URIs) != 1 {
		return nil, fmt.Errorf("missing SPIFFE URI")
	}
	if c.wrongIdentity.Load() {
		csr.URIs[0].Path = "/ns/other/sa/other"
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Minute),
		URIs:        csr.URIs,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return &ca.IstioCertificateResponse{
		CertChain: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(c.root)},
	}, nil
}

func (c *testCA) serve(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(
		grpc.Creds(
			credentials.NewTLS(
				&tls.Config{
					Certificates: []tls.Certificate{{Certificate: [][]byte{c.cert.Raw}, PrivateKey: c.key}},
					MinVersion:   tls.VersionTLS12,
				},
			),
		),
	)
	ca.RegisterIstioCertificateServiceServer(server, c)
	go func() {
		if err := server.Serve(listener); err != nil {
			t.Errorf("CA server failed: %v", err)
		}
	}()
	t.Cleanup(server.Stop)
	return listener.Addr().String()
}

func TestLocalIdentityAndSDSRotation(t *testing.T) {
	c := testConfig(t)
	issuer := newTestCA(t)
	c.CAAddress = issuer.serve(t)
	c.CAHeaders = map[string]string{"x-ca-route": "issuer-a"}
	issuer.expectedHeader = "issuer-a"
	c.CertSigner = "workload"
	issuer.expectedSigner = "workload"
	c.ECCCurve = "P256"
	c.PKCS8 = true
	c.TokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(c.TokenFile, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	projection := t.TempDir()
	project := func(version string, root []byte) {
		t.Helper()
		dir := filepath.Join(projection, version)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "root-cert.pem"), root, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(version, filepath.Join(projection, "next")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(projection, "next"), filepath.Join(projection, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	project("v1", issuer.root)
	c.RootCertFile = filepath.Join(projection, "root-cert.pem")
	if err := os.Symlink("..data/root-cert.pem", c.RootCertFile); err != nil {
		t.Fatal(err)
	}
	c.CARootCertFile = c.RootCertFile
	m, err := startIdentity(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	deadline := time.Now().Add(5 * time.Second)
	for m.ready() != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := m.ready(); err != nil {
		t.Fatal(err)
	}
	if token := <-issuer.tokens; token != "Bearer first" {
		t.Fatal("incorrect initial CA token")
	}
	conn, err := grpc.NewClient("unix://"+c.SDSSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(conn)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	stream, err := sds.NewSecretDiscoveryServiceClient(conn).StreamSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(
		&discovery.DiscoveryRequest{TypeUrl: secretType, ResourceNames: []string{"default", "ROOTCA"}},
	); err != nil {
		t.Fatal(err)
	}
	responses := make(chan *discovery.DiscoveryResponse, 8)
	errors := make(chan error, 1)
	go func() {
		for {
			r, err := stream.Recv()
			if err != nil {
				errors <- err
				return
			}
			select {
			case responses <- r:
			case <-ctx.Done():
				return
			}
		}
	}()
	receive := func() *discovery.DiscoveryResponse {
		t.Helper()
		select {
		case r := <-responses:
			return r
		case err := <-errors:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		return nil
	}
	first := receive()
	if len(first.Resources) != 2 {
		t.Fatal("SDS did not return both secrets")
	}
	for _, detail := range []*rpcstatus.Status{nil, {Code: int32(codes.InvalidArgument), Message: "test NACK"}} {
		if err := stream.Send(
			&discovery.DiscoveryRequest{
				TypeUrl:       secretType,
				ResourceNames: []string{"default", "ROOTCA"},
				ResponseNonce: first.Nonce,
				VersionInfo:   first.VersionInfo,
				ErrorDetail:   detail,
			},
		); err != nil {
			t.Fatal(err)
		}
		select {
		case <-responses:
			t.Fatal("SDS replied to an ACK/NACK without a change")
		case err := <-errors:
			t.Fatal(err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := os.WriteFile(c.TokenFile, []byte("rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := append(bytes.Clone(issuer.root), newTestCA(t).root...)
	project("v2", bundle)
	for {
		r := receive()
		if r.VersionInfo == first.VersionInfo || r.Nonce == first.Nonce {
			t.Fatal("rotation reused SDS version or nonce")
		}
		var root, cert *tlsv3.Secret
		for _, resource := range r.Resources {
			value := &tlsv3.Secret{}
			if err := resource.UnmarshalTo(value); err != nil {
				t.Fatal(err)
			}
			if value.Name == "ROOTCA" {
				root = value
			} else {
				cert = value
			}
		}
		if root == nil || cert == nil ||
			!bytes.Equal(root.GetValidationContext().GetTrustedCa().GetInlineBytes(), bundle) {
			continue
		}
		original := &tlsv3.Secret{}
		for _, resource := range first.Resources {
			value := &tlsv3.Secret{}
			if err := resource.UnmarshalTo(value); err != nil {
				t.Fatal(err)
			}
			if value.Name == "default" {
				original = value
			}
		}
		if bytes.Equal(
			cert.GetTlsCertificate().GetCertificateChain().GetInlineBytes(),
			original.GetTlsCertificate().GetCertificateChain().GetInlineBytes(),
		) {
			continue
		}
		break
	}
	if token := <-issuer.tokens; token != "Bearer rotated" {
		t.Fatal("renewal reused the old CA token")
	}
	issuer.wrongIdentity.Store(true)
	if _, _, err := requestWorkloadCertificate(t.Context(), c); err == nil {
		t.Fatal("accepted a certificate for another identity")
	}
	issuer.wrongIdentity.Store(false)
	issuer.fail.Store(true)
	if _, _, err := requestWorkloadCertificate(t.Context(), c); err == nil {
		t.Fatal("CA outage reported success")
	}
	if err := m.ready(); err != nil {
		t.Fatal("CA outage discarded the valid cached certificate")
	}
	m.mu.Lock()
	m.expires = time.Now().Add(-time.Second)
	m.mu.Unlock()
	if m.ready() == nil {
		t.Fatal("expired certificate remained ready")
	}
	if _, err := m.generate([]string{"default"}); status.Code(err) != codes.Unavailable {
		t.Fatal("expired certificate remained available over SDS")
	}
	for _, name := range []string{"file-cert:/etc/private", "domain.example"} {
		other, err := sds.NewSecretDiscoveryServiceClient(conn).StreamSecrets(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := other.Send(
			&discovery.DiscoveryRequest{TypeUrl: secretType, ResourceNames: []string{name}},
		); err != nil {
			t.Fatal(err)
		}
		if _, err := other.Recv(); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("unexpected local SDS access for %s: %v", name, err)
		}
	}
}

func TestRootUpdateWhileCASigningBlocked(t *testing.T) {
	c := testConfig(t)
	issuer := newTestCA(t)
	blocked := make(chan struct{}, 1)
	issuer.beforeSign = func(ctx context.Context) error {
		select {
		case blocked <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}
	c.CAAddress = issuer.serve(t)
	c.RootCertFile = filepath.Join(t.TempDir(), "root.pem")
	c.CARootCertFile = c.RootCertFile
	c.TokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(c.RootCertFile, issuer.root, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.TokenFile, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := startIdentity(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-blocked:
	case <-ctx.Done():
		t.Fatal("CA request did not start")
	}
	bundle := append(bytes.Clone(issuer.root), newTestCA(t).root...)
	if err := os.WriteFile(c.RootCertFile, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient("unix://"+c.SDSSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(conn)
	stream, err := sds.NewSecretDiscoveryServiceClient(conn).StreamSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(
		&discovery.DiscoveryRequest{TypeUrl: secretType, ResourceNames: []string{"ROOTCA"}},
	); err != nil {
		t.Fatal(err)
	}
	for {
		response, err := stream.Recv()
		if err != nil {
			t.Fatalf("root update blocked by CA signing: %v", err)
		}
		root := &tlsv3.Secret{}
		if len(response.Resources) != 1 {
			t.Fatal("expected ROOTCA resource")
		}
		if err := response.Resources[0].UnmarshalTo(root); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(root.GetValidationContext().GetTrustedCa().GetInlineBytes(), bundle) {
			break
		}
	}
}
