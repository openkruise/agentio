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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	securityapi "istio.io/api/security/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/pkg/model"
)

// WorkloadOptions selects the CA and the ServiceAccount identity to request.
// TokenPath and RootPath are projected, independently rotating Kubernetes files.
type WorkloadOptions struct {
	Address   string
	TokenPath string
	RootPath  string
	SPIFFEID  string
	Lifetime  time.Duration
}

type workloadCertificate struct {
	cert    *tls.Certificate
	renewAt time.Time
	roots   [sha256.Size]byte
}

// Workload requests and renews an in-memory identity through Agentiod's CA API.
// Start owns the renewal loop. Construction performs no network requests.
type Workload struct {
	options   WorkloadOptions
	current   atomic.Pointer[workloadCertificate]
	rootsMu   sync.Mutex
	rootsInfo os.FileInfo
	rootsPEM  []byte
	rootsPool *x509.CertPool
}

// NewWorkload validates the startup configuration without acquiring credentials.
func NewWorkload(options WorkloadOptions) (*Workload, error) {
	if host, port, err := net.SplitHostPort(options.Address); err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("workload CA address must be host:port")
	}
	id, err := url.Parse(options.SPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("invalid workload identity: %w", err)
	}
	if _, err := model.ParsePrincipal(options.SPIFFEID, id.Host); err != nil {
		return nil, err
	}
	if options.TokenPath == "" || options.RootPath == "" {
		return nil, fmt.Errorf("workload token and trust bundle paths are required")
	}
	if options.Lifetime == 0 {
		options.Lifetime = 24 * time.Hour
	}
	if options.Lifetime < time.Second {
		return nil, fmt.Errorf("workload certificate lifetime must be at least one second")
	}
	return &Workload{options: options}, nil
}

// Start retries temporary CA failures while keeping the last unexpired identity.
// Polling also observes trust changes independently of the leaf's renewal time.
func (w *Workload) Start(ctx context.Context) error {
	retry := time.Second
	for {
		roots, digest, err := w.loadRoots()
		current := w.current.Load()
		delay := reloadPollInterval
		if err == nil && (current == nil || time.Now().After(current.renewAt) || current.roots != digest) {
			err = w.renew(ctx, roots, digest)
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.FromContext(ctx).Error(err, "renewing EPE workload certificate failed")
			delay = retry + time.Duration(mathrand.Float64()*float64(retry)/5)
			retry = min(retry*2, 30*time.Second)
		} else {
			retry = time.Second
			if current = w.current.Load(); current != nil {
				delay = min(delay, max(time.Until(current.renewAt), time.Millisecond))
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (w *Workload) renew(ctx context.Context, roots *x509.CertPool, digest [sha256.Size]byte) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	token, err := os.ReadFile(w.options.TokenPath)
	if err != nil {
		return fmt.Errorf("read workload token: %w", err)
	}
	if len(bytes.TrimSpace(token)) == 0 {
		return fmt.Errorf("workload token is empty")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	identity, err := url.Parse(w.options.SPIFFEID)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{identity}}, key)
	if err != nil {
		return err
	}
	// A fresh connection uses the current trust bundle even after a CA rotation.
	// DNS verification authenticates Agentiod before any bearer token is sent.
	host, _, err := net.SplitHostPort(w.options.Address)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(w.options.Address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: host,
	})))
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.FromContext(ctx).Error(err, "closing workload CA connection")
		}
	}()
	response, err := securityapi.NewIstioCertificateServiceClient(conn).CreateCertificate(
		metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+strings.TrimSpace(string(token))),
		&securityapi.IstioCertificateRequest{
			Csr:              string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
			ValidityDuration: int64(w.options.Lifetime / time.Second),
		},
	)
	if err != nil {
		return fmt.Errorf("request workload certificate: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	cert, err := parseKeyPair(
		[]byte(strings.Join(response.CertChain, "\n")),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	)
	if err != nil {
		return fmt.Errorf("load issued workload certificate: %w", err)
	}
	leaf := cert.Leaf
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != w.options.SPIFFEID {
		return fmt.Errorf("issued certificate does not identify %s", w.options.SPIFFEID)
	}
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse issued workload certificate chain: %w", err)
		}
		intermediates.AddCert(parsed)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(
			x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}},
		); err != nil {
			return fmt.Errorf("verify issued workload certificate: %w", err)
		}
	}
	// Renew with approximately one third of the actual remaining lifetime left.
	renewAt := time.Now().Add(time.Duration(float64(time.Until(leaf.NotAfter)) * (0.63 + mathrand.Float64()*0.07)))
	w.current.Store(&workloadCertificate{cert: cert, renewAt: renewAt, roots: digest})
	log.FromContext(ctx).
		Info("installed EPE workload certificate", "identity", w.options.SPIFFEID, "expires", leaf.NotAfter, "renewAt", renewAt)
	return nil
}

// GetCertificate returns the latest unexpired serving identity.
func (w *Workload) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	current := w.current.Load()
	if current == nil {
		return nil, fmt.Errorf("workload certificate has not been issued")
	}
	now := time.Now()
	if now.Before(current.cert.Leaf.NotBefore) || !now.Before(current.cert.Leaf.NotAfter) {
		return nil, fmt.Errorf("workload certificate is outside its validity period")
	}
	return current.cert, nil
}

// GetClientCertificate returns the same workload identity for client TLS.
func (w *Workload) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return w.GetCertificate(nil)
}

// RootCAs loads the projected trust bundle; missing or malformed roots are errors.
func (w *Workload) RootCAs() (*x509.CertPool, error) {
	roots, _, err := w.loadRoots()
	return roots, err
}

// loadRoots never falls back to system CAs or retains a removed trust bundle.
// Kubernetes projection swaps change inode; stat avoids reparsing unchanged PEM.
func (w *Workload) loadRoots() (*x509.CertPool, [sha256.Size]byte, error) {
	w.rootsMu.Lock()
	defer w.rootsMu.Unlock()
	info, err := os.Stat(w.options.RootPath)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("read workload trust bundle: %w", err)
	}
	if w.rootsInfo == nil || !os.SameFile(info, w.rootsInfo) || info.ModTime() != w.rootsInfo.ModTime() ||
		info.Size() != w.rootsInfo.Size() {
		raw, err := os.ReadFile(w.options.RootPath)
		if err != nil {
			return nil, [sha256.Size]byte{}, err
		}
		pool := x509.NewCertPool()
		remaining := bytes.TrimSpace(raw)
		count := 0
		for len(remaining) != 0 {
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" ||
				!bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, [sha256.Size]byte{}, fmt.Errorf("invalid workload trust bundle PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, [sha256.Size]byte{}, fmt.Errorf(
					"parse workload trust bundle %q: %w",
					w.options.RootPath,
					err,
				)
			}
			if !cert.IsCA {
				return nil, [sha256.Size]byte{}, fmt.Errorf("workload trust bundle contains a non-CA certificate")
			}
			pool.AddCert(cert)
			count++
			remaining = bytes.TrimSpace(rest)
		}
		if count == 0 {
			return nil, [sha256.Size]byte{}, fmt.Errorf("workload trust bundle is empty")
		}
		w.rootsInfo, w.rootsPEM, w.rootsPool = info, raw, pool
	}
	return w.rootsPool, sha256.Sum256(w.rootsPEM), nil
}
