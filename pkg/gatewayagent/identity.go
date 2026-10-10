// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"

	ca "github.com/openkruise/agentio/pkg/gatewayagent/internal/caproto"
)

// The CSR, cache, renewal and SDS responsibilities are extracted from
// release-0.1 security/pkg/nodeagent. Only default and ROOTCA are supported.
// This is maintained locally; see internal/UPSTREAM.md for the extraction boundary.
type identityManager struct {
	config      Config
	mu          sync.RWMutex
	certificate *tlsv3.Secret
	root        *tlsv3.Secret
	expires     time.Time
	version     uint64
	clients     map[chan struct{}]struct{}
	stop        context.CancelFunc
	done        chan struct{}
	server      *grpc.Server
	serverDone  chan error
}

func startIdentity(c Config) (*identityManager, error) {
	root, err := readRoot(c.RootCertFile)
	if err != nil {
		return nil, err
	}
	listener, err := listenSocket(c.SDSSocket)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &identityManager{config: c,
		root:       rootSecret(root),
		version:    1,
		clients:    make(map[chan struct{}]struct{}),
		stop:       cancel,
		done:       make(chan struct{}),
		server:     grpc.NewServer(),
		serverDone: make(chan error, 1)}
	sds.RegisterSecretDiscoveryServiceServer(m.server, &localSDS{identity: m})
	go func() { m.serverDone <- m.server.Serve(listener) }()
	go m.run(ctx)
	return m, nil
}

func (m *identityManager) Close() {
	m.stop()
	m.server.Stop()
	<-m.done
}

func (m *identityManager) ready() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.certificate == nil || !time.Now().Before(m.expires) {
		return fmt.Errorf("workload certificate is unavailable or expired")
	}
	return nil
}

func (m *identityManager) notifyLocked() {
	m.version++
	for client := range m.clients {
		select {
		case client <- struct{}{}:
		default:
		}
	}
}

func (m *identityManager) run(ctx context.Context) {
	defer close(m.done)
	rootChanged := make(chan struct{}, 1)
	rootDone := make(chan struct{})
	go func() {
		defer close(rootDone)
		m.watchRoots(ctx, rootChanged)
	}()
	defer func() { <-rootDone }()
	renew := time.NewTimer(0)
	defer renew.Stop()
	retry := 100 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		case <-rootChanged:
			renew.Reset(0)
		case <-renew.C:
			started := time.Now()
			secret, expires, err := requestWorkloadCertificate(ctx, m.config)
			if metrics := m.config.metrics; metrics != nil {
				metrics.certificateRequests.Inc()
				metrics.certificateLatency.Observe(time.Since(started).Seconds())
				if err != nil {
					metrics.certificateFailures.Inc()
				} else {
					metrics.certificateExpiry.Store(expires.Unix())
					metrics.certificateSuccess.SetToCurrentTime()
				}
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Warn("gateway certificate renewal failed", "error", err)
				renew.Reset(retry)
				retry = min(30*time.Second, retry*2)
				continue
			}
			m.mu.Lock()
			m.certificate, m.expires = secret, expires
			m.notifyLocked()
			m.mu.Unlock()
			retry = 100 * time.Millisecond
			renew.Reset(
				rotateTime(
					time.Now(),
					expires,
					floatOption(m.config.RotationGraceRatio, .5),
					floatOption(m.config.RotationJitter, .01),
				),
			)
			slog.Info("gateway workload certificate renewed", "expires", expires)
		}
	}
}

// Keep trust-bundle updates independent of slow CA signing requests.
func (m *identityManager) watchRoots(ctx context.Context, changed chan<- struct{}) {
	// Poll projected files to follow Kubernetes ..data symlink swaps.
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			root, err := readRoot(m.config.RootCertFile)
			if err != nil {
				if m.config.metrics != nil {
					m.config.metrics.rootReloadFailures.Inc()
				}
				slog.Warn("gateway trust bundle reload failed", "error", err)
				continue
			}
			m.mu.Lock()
			if !bytes.Equal(root, m.root.GetValidationContext().GetTrustedCa().GetInlineBytes()) {
				m.root = rootSecret(root)
				m.notifyLocked()
				select {
				case changed <- struct{}{}:
				default:
				}
			}
			m.mu.Unlock()
		}
	}
}

// Adapted from release-0.1 cache.rotateTime: use the actual returned certificate
// lifetime, a 50% grace period and jitter, rather than assuming CA honors TTL.
func rotateTime(created, expires time.Time, graceRatio, jitterRatio float64) time.Duration {
	jitter := mathrand.Float64() * jitterRatio * float64(mathrand.IntN(2)*2-1)
	ratio := min(1.0, max(0.0, graceRatio+jitter))
	delay := time.Until(expires.Add(-time.Duration(ratio * float64(expires.Sub(created)))))
	return max(time.Millisecond, delay)
}

// Adapted from cache.generateNewSecret and citadel.CSRSign. Keys stay local;
// every signing attempt reloads the projected token and current CA trust bundle.
func requestWorkloadCertificate(ctx context.Context, c Config) (*tlsv3.Secret, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	key, keyPEM, err := generateWorkloadKey(c)
	if err != nil {
		return nil, time.Time{}, err
	}
	identity := &url.URL{Scheme: "spiffe", Host: c.TrustDomain, Path: "/ns/" + c.Namespace + "/sa/" + c.ServiceAccount}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{identity}}, key)
	if err != nil {
		return nil, time.Time{}, err
	}
	ctx, conn, err := connectControlPlane(
		ctx,
		c.CAAddress,
		c.CAServerName,
		c.CARootCertFile,
		c.TokenFile,
		c.ClusterID,
		c.CAHeaders,
	)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer closeResource(conn)
	response, err := ca.NewIstioCertificateServiceClient(conn).CreateCertificate(ctx, &ca.IstioCertificateRequest{
		Csr:              string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		ValidityDuration: int64(c.SecretTTL.Seconds()),
		Metadata: &structpb.Struct{
			Fields: map[string]*structpb.Value{"CertSigner": structpb.NewStringValue(c.CertSigner)},
		},
	})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign workload CSR: %w", err)
	}
	if len(response.CertChain) < 2 {
		return nil, time.Time{}, fmt.Errorf("CA returned an incomplete certificate chain")
	}
	chain := []byte(strings.Join(response.CertChain, "\n"))
	pair, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("invalid CA certificate/key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity.String() {
		return nil, time.Time{}, fmt.Errorf("CA returned a different workload identity")
	}
	root, err := readRoot(c.RootCertFile)
	if err != nil {
		return nil, time.Time{}, err
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, time.Time{}, err
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, time.Time{}, fmt.Errorf("verify returned workload chain: %w", err)
	}
	return &tlsv3.Secret{Name: "default",
		Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
			CertificateChain: inlineBytes(chain),
			PrivateKey:       inlineBytes(keyPEM),
		}}}, leaf.NotAfter, nil
}

func readRoot(path string) ([]byte, error) {
	root, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workload trust bundle: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(root) {
		return nil, fmt.Errorf("trust bundle contains no certificates")
	}
	return root, nil
}

func inlineBytes(value []byte) *core.DataSource {
	return &core.DataSource{Specifier: &core.DataSource_InlineBytes{InlineBytes: value}}
}

func rootSecret(root []byte) *tlsv3.Secret {
	return &tlsv3.Secret{
		Name: "ROOTCA",
		Type: &tlsv3.Secret_ValidationContext{
			ValidationContext: &tlsv3.CertificateValidationContext{TrustedCa: inlineBytes(root)},
		},
	}
}

func listenSocket(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("path %s is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		closeResource(listener)
		return nil, err
	}
	return listener, nil
}

func generateWorkloadKey(c Config) (crypto.Signer, []byte, error) {
	var key crypto.Signer
	var err error
	if c.ECCCurve != "" {
		curve := elliptic.P256()
		if c.ECCCurve == "P384" {
			curve = elliptic.P384()
		}
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	} else {
		size := c.RSAKeySize
		if size == 0 {
			size = 2048
		}
		key, err = rsa.GenerateKey(rand.Reader, size)
	}
	if err != nil {
		return nil, nil, err
	}
	var der []byte
	kind := "PRIVATE KEY"
	if c.PKCS8 {
		der, err = x509.MarshalPKCS8PrivateKey(key)
	} else {
		switch value := key.(type) {
		case *rsa.PrivateKey:
			kind = "RSA PRIVATE KEY"
			der = x509.MarshalPKCS1PrivateKey(value)
		case *ecdsa.PrivateKey:
			kind = "EC PRIVATE KEY"
			der, err = x509.MarshalECPrivateKey(value)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), nil
}
