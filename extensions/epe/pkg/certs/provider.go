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
// Package certs provides certificate Providers and a hardened TLS
// verification pipeline for EPE servers and clients.
//
// A Provider abstracts where certificate material comes from (self-signed at
// startup, files on disk with hot reload, ...). ServerTLSConfig and
// ClientTLSConfig turn a Provider into *tls.Config values whose trust anchors
// are re-resolved on every handshake, so rotated CAs take effect without a
// process restart.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// Provider supplies certificate material and trust anchors for TLS
// configurations built by ServerTLSConfig and ClientTLSConfig.
type Provider interface {
	// GetCertificate returns the certificate presented by a server.
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// GetClientCertificate returns the certificate presented by a client.
	GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	// RootCAs returns the trust anchors used to verify the peer: RootCAs
	// semantics on clients, ClientCAs semantics on servers. It is called on
	// every handshake so implementations may return fresh (rotated) pools.
	// A nil pool with a nil error means the provider has no custom CA;
	// clients then fall back to the system certificate pool.
	RootCAs() (*x509.CertPool, error)
}

// CheckServing checks availability for readiness and new streams on existing
// TLS connections. Existing streams may finish after the certificate expires.
func CheckServing(provider Provider, requireClientCA bool) error {
	cert, err := provider.GetCertificate(nil)
	if err != nil {
		return err
	}
	if cert == nil || len(cert.Certificate) == 0 {
		return fmt.Errorf("serving certificate is unavailable")
	}
	leaf := cert.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("serving certificate is outside its validity period")
	}
	if requireClientCA {
		roots, err := provider.RootCAs()
		if err != nil {
			return err
		}
		if roots == nil {
			return fmt.Errorf("client trust bundle is unavailable")
		}
	}
	return nil
}
