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

package pki

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"time"
)

type LeafOptions struct {
	CommonName            string
	DNSNames              []string
	IPAddresses           []net.IP
	URIs                  []*url.URL
	CRLDistributionPoints []string
	ExtraExtensions       []pkix.Extension
	CurrentTime           time.Time
	Lifetime              time.Duration
	IssuerExpiryMargin    time.Duration
	MinimumLifetime       time.Duration
	Client                bool
	Server                bool
}

type IssuedCertificate struct {
	Certificate    *x509.Certificate
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	IssuedAt       time.Time
	NotAfter       time.Time
}

// Sign creates a leaf certificate for a caller-owned public key.
func (ca SigningCA) Sign(ctx context.Context, publicKey any, options LeafOptions) (IssuedCertificate, error) {
	return ca.sign(ctx, publicKey, nil, options)
}

// GenerateRSA generates an RSA subject key and signs its leaf certificate.
func (ca SigningCA) GenerateRSA(ctx context.Context, options LeafOptions) (IssuedCertificate, error) {
	if ctx == nil {
		return IssuedCertificate{}, fmt.Errorf("certificate signing context is required")
	}
	if err := ctx.Err(); err != nil {
		return IssuedCertificate{}, err
	}
	key, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("generate leaf key: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return IssuedCertificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return ca.sign(ctx, &key.PublicKey, keyPEM, options)
}

func (ca SigningCA) sign(ctx context.Context, publicKey any, privateKeyPEM []byte, options LeafOptions) (IssuedCertificate, error) {
	if ctx == nil {
		return IssuedCertificate{}, fmt.Errorf("certificate signing context is required")
	}
	if err := ctx.Err(); err != nil {
		return IssuedCertificate{}, err
	}
	if !ca.Available() {
		return IssuedCertificate{}, fmt.Errorf("signing CA is not available")
	}
	if publicKey == nil {
		return IssuedCertificate{}, fmt.Errorf("certificate public key is required")
	}
	if options.Lifetime <= 0 {
		return IssuedCertificate{}, fmt.Errorf("certificate lifetime must be positive")
	}
	if options.IssuerExpiryMargin < 0 || options.MinimumLifetime < 0 {
		return IssuedCertificate{}, fmt.Errorf("certificate expiry margins cannot be negative")
	}

	now := options.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	notAfter := now.Add(options.Lifetime)
	if limit := ca.chainNotAfter.Add(-options.IssuerExpiryMargin); notAfter.After(limit) {
		notAfter = limit
	}
	if !notAfter.After(now.Add(options.MinimumLifetime)) {
		return IssuedCertificate{}, fmt.Errorf("signing CA expires too soon to issue a certificate")
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("generate leaf serial: %w", err)
	}
	extKeyUsage := make([]x509.ExtKeyUsage, 0, 2)
	if options.Server {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if options.Client {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: options.CommonName},
		NotBefore:             now.Add(-ClockSkew),
		NotAfter:              notAfter,
		DNSNames:              append([]string(nil), options.DNSNames...),
		IPAddresses:           append([]net.IP(nil), options.IPAddresses...),
		URIs:                  append([]*url.URL(nil), options.URIs...),
		CRLDistributionPoints: options.CRLDistributionPoints,
		ExtraExtensions:       append([]pkix.Extension(nil), options.ExtraExtensions...),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
	}
	if _, ok := publicKey.(*rsa.PublicKey); ok {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, publicKey, ca.privateKey)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("sign leaf certificate: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return IssuedCertificate{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	return IssuedCertificate{
		Certificate:    certificate,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  append([]byte(nil), privateKeyPEM...),
		IssuedAt:       now,
		NotAfter:       notAfter,
	}, nil
}
