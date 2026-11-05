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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestValidateCAKeyPair(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	validCert, validKey := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	_, otherKey := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)

	tests := []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
		wantErr string
	}{
		{name: "valid", certPEM: validCert, keyPEM: validKey},
		{name: "mismatched key", certPEM: validCert, keyPEM: otherKey, wantErr: "private key does not match"},
		{
			name: "missing CA basic constraints",
			certPEM: func() []byte {
				cert, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, false, x509.KeyUsageCertSign)
				return cert
			}(),
			keyPEM:  validKey,
			wantErr: "valid CA basic constraints",
		},
		{
			name: "not a CA",
			certPEM: func() []byte {
				cert, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), false, true, x509.KeyUsageDigitalSignature)
				return cert
			}(),
			keyPEM:  validKey,
			wantErr: "valid CA basic constraints",
		},
		{
			name: "missing cert sign usage",
			certPEM: func() []byte {
				cert, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageDigitalSignature)
				return cert
			}(),
			keyPEM:  validKey,
			wantErr: "certificate signing key usage",
		},
		{
			name: "expired",
			certPEM: func() []byte {
				cert, _ := testCAKeyPair(t, now.Add(-2*time.Hour), now.Add(-time.Hour), true, true, x509.KeyUsageCertSign)
				return cert
			}(),
			keyPEM:  validKey,
			wantErr: "expired",
		},
		{
			name: "not yet valid",
			certPEM: func() []byte {
				cert, _ := testCAKeyPair(t, now.Add(time.Hour), now.Add(2*time.Hour), true, true, x509.KeyUsageCertSign)
				return cert
			}(),
			keyPEM:  validKey,
			wantErr: "not valid before",
		},
		{name: "certificate trailing data", certPEM: append(append([]byte(nil), validCert...), []byte("trailing")...), keyPEM: validKey, wantErr: "invalid PEM"},
		{name: "extra certificate", certPEM: append(append([]byte(nil), validCert...), validCert...), keyPEM: validKey, wantErr: "trailing data"},
		{name: "key trailing data", certPEM: validCert, keyPEM: append(append([]byte(nil), validKey...), []byte("trailing")...), wantErr: "trailing data"},
		{name: "certificate prefixed garbage", certPEM: append([]byte("garbage\n"), validCert...), keyPEM: validKey, wantErr: "invalid PEM"},
		{name: "key prefixed garbage", certPEM: validCert, keyPEM: append([]byte("garbage\n"), validKey...), wantErr: "leading data"},
		{name: "leading and trailing ASCII whitespace", certPEM: withASCIIWhitespace(validCert), keyPEM: withASCIIWhitespace(validKey)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := ParseSigningCA(tc.certPEM, tc.keyPEM, now)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ParseSigningCA() error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !ca.Available() {
				t.Fatal("ParseSigningCA() returned an unavailable CA")
			}
		})
	}
}

func withASCIIWhitespace(value []byte) []byte {
	result := append([]byte(" \t\r\n\v\f"), value...)
	return append(result, []byte(" \t\r\n\v\f")...)
}

func TestValidateCAKeyPairRejectsUnsupportedPrivateKeyPEMType(t *testing.T) {
	now := time.Now()
	certPEM, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	_, err = ParseSigningCA(certPEM, keyPEM, now)
	if err == nil || !strings.Contains(err.Error(), "unsupported CA private key PEM type") {
		t.Fatalf("ParseSigningCA() error = %v, want unsupported private key type error", err)
	}
}

func TestValidateTrustBundle(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	activePEM, activeKey := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	active, err := ParseSigningCA(activePEM, activeKey, now)
	if err != nil {
		t.Fatal(err)
	}
	previousPEM, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	unrelatedPEM, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	nonCAPEM, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), false, true, x509.KeyUsageDigitalSignature)
	missingCertSignPEM, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageDigitalSignature)
	expiredPEM, _ := testCAKeyPair(t, now.Add(-2*time.Hour), now.Add(-time.Hour), true, true, x509.KeyUsageCertSign)
	nonSelfSignedPEM := testSignedCACertificate(t, activePEM, activeKey, now)

	for _, tc := range []struct {
		name    string
		bundle  []byte
		wantErr string
	}{
		{name: "active root", bundle: withASCIIWhitespace(activePEM)},
		{name: "dual-root overlap", bundle: append(append(append([]byte(nil), activePEM...), '\n'), previousPEM...)},
		{name: "empty", wantErr: "empty"},
		{name: "malformed", bundle: []byte("not a certificate"), wantErr: "invalid PEM"},
		{name: "prefixed data", bundle: append([]byte("garbage\n"), activePEM...), wantErr: "invalid PEM"},
		{name: "trailing data", bundle: append(append([]byte(nil), activePEM...), []byte("garbage")...), wantErr: "invalid PEM"},
		{name: "non-certificate block", bundle: activeKey, wantErr: "PEM block has type"},
		{name: "unrelated root", bundle: unrelatedPEM, wantErr: "active signing certificate"},
		{name: "non-CA entry", bundle: append(append([]byte(nil), activePEM...), nonCAPEM...), wantErr: "valid CA basic constraints"},
		{name: "missing cert sign usage", bundle: append(append([]byte(nil), activePEM...), missingCertSignPEM...), wantErr: "certificate signing key usage"},
		{name: "expired entry", bundle: append(append([]byte(nil), activePEM...), expiredPEM...), wantErr: "expired"},
		{name: "non-self-signed entry", bundle: append(append([]byte(nil), activePEM...), nonSelfSignedPEM...), wantErr: "not self-signed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTrustBundle(tc.bundle, active, now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateTrustBundle() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func testSignedCACertificate(t *testing.T, parentPEM, parentKeyPEM []byte, now time.Time) []byte {
	t.Helper()
	parent := parsePEMCertificate(t, parentPEM)
	parentKeyBlock, trailing := pem.Decode(parentKeyPEM)
	if parentKeyBlock == nil || len(bytes.TrimSpace(trailing)) != 0 {
		t.Fatal("parent key is not one PEM block")
	}
	parentKey, err := x509.ParseECPrivateKey(parentKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano() + 1),
		Subject:               pkix.Name{CommonName: "intermediate CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestIssuedLeafDoesNotOutliveCA(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	caPEM, keyPEM := testCAKeyPair(t, now.Add(-time.Hour), now.Add(20*time.Minute), true, true, x509.KeyUsageCertSign)
	ca, err := ParseSigningCA(caPEM, keyPEM, now)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := ca.GenerateRSA(context.Background(), LeafOptions{
		CurrentTime: now,
		Lifetime:    time.Hour,
		Server:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Certificate.NotAfter.After(ca.NotAfter()) {
		t.Fatalf("leaf NotAfter = %s, CA NotAfter = %s", issued.Certificate.NotAfter, ca.NotAfter())
	}
}

func TestSigningCARevisionCoversCompleteBundle(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	activePEM, activeKey := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	trailingOne, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	trailingTwo, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)

	first, err := ParseSigningCABundle(append(append([]byte(nil), activePEM...), trailingOne...), activeKey, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseSigningCABundle(append(append([]byte(nil), activePEM...), trailingTwo...), activeKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision() == second.Revision() {
		t.Fatal("revision did not change when the trailing CA changed")
	}
}

func TestSigningCARevisionIgnoresPEMFormatting(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	activePEM, activeKey := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	trailingPEM, _ := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	bundle := append(append([]byte(nil), activePEM...), trailingPEM...)

	plain, err := ParseSigningCABundle(bundle, activeKey, now)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := ParseSigningCABundle(withASCIIWhitespace(bundle), activeKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Revision() != formatted.Revision() {
		t.Fatalf("semantic bundle revision changed with PEM whitespace: %q != %q", plain.Revision(), formatted.Revision())
	}
}

func testCAKeyPair(t *testing.T, notBefore, notAfter time.Time, isCA, basicConstraintsValid bool, keyUsage x509.KeyUsage) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(notAfter.UnixNano()),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: basicConstraintsValid,
		KeyUsage:              keyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func parsePEMCertificate(t *testing.T, value []byte) *x509.Certificate {
	t.Helper()
	block, trailing := pem.Decode(value)
	if block == nil || len(bytes.TrimSpace(trailing)) != 0 {
		t.Fatal("value is not one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
