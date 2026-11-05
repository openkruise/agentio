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

func TestParseSelfSignedCAForRenewal(t *testing.T) {
	now := time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)
	expiredPEM, expiredKey := testCAKeyPair(
		t,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
		true,
		true,
		x509.KeyUsageCertSign,
	)
	validPEM, validKey := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	futurePEM, futureKey := testCAKeyPair(
		t,
		now.Add(time.Hour),
		now.Add(2*time.Hour),
		true,
		true,
		x509.KeyUsageCertSign,
	)
	nonCAPEM, nonCAKey := testCAKeyPair(
		t,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
		false,
		true,
		x509.KeyUsageCertSign,
	)
	noSignPEM, noSignKey := testCAKeyPair(
		t,
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
		true,
		true,
		x509.KeyUsageDigitalSignature,
	)
	parent, err := ParseSigningCA(validPEM, validKey, now)
	if err != nil {
		t.Fatal(err)
	}
	// Same issuer and subject is insufficient: the self-signature must verify.
	intermediate := testChildCA(t, parent, "test CA", now, time.Hour)
	for _, tc := range []struct {
		name        string
		cert        []byte
		key         []byte
		allowBundle bool
		wantErr     string
	}{
		{name: "expired root", cert: expiredPEM, key: expiredKey},
		{name: "expired active with staged root", cert: append(append([]byte(nil), expiredPEM...), validPEM...), key: expiredKey, allowBundle: true},
		{name: "mismatched key", cert: expiredPEM, key: validKey, wantErr: "private key does not match"},
		{name: "future root", cert: futurePEM, key: futureKey, wantErr: "not valid before"},
		{name: "not a CA", cert: nonCAPEM, key: nonCAKey, wantErr: "valid CA basic constraints"},
		{name: "cannot sign", cert: noSignPEM, key: noSignKey, wantErr: "certificate signing key usage"},
		{name: "self-issued intermediate", cert: intermediate.CertificatePEM(), key: intermediate.PrivateKeyPEM(), wantErr: "not self-signed"},
		{name: "expired trailing root", cert: append(append([]byte(nil), validPEM...), expiredPEM...), key: validKey, allowBundle: true, wantErr: "expired"},
		{name: "bundle disallowed", cert: append(append([]byte(nil), expiredPEM...), validPEM...), key: expiredKey, wantErr: "trailing data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := ParseSelfSignedCAForRenewal(tc.cert, tc.key, now, tc.allowBundle)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parse renewal error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseSigningCABundle(tc.cert, tc.key, now); err == nil {
				t.Fatal("normal loading accepted an expired root")
			}
			if _, err := ca.Sign(
				context.Background(),
				ca.privateKey.Public(),
				LeafOptions{CurrentTime: now, Lifetime: time.Hour},
			); err == nil {
				t.Fatal("renewal snapshot allowed signing with an expired root")
			}
			renewed, err := RenewSelfSignedCA(ca, 24*time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			_, oldTrailing := pem.Decode(tc.cert)
			_, newTrailing := pem.Decode(renewed.BundlePEM())
			if !bytes.Equal(oldTrailing, newTrailing) {
				t.Fatal("renewal changed staged roots")
			}
		})
	}
}

func TestLeafExpiryFollowsSigningChain(t *testing.T) {
	now := time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name         string
		rootLifetime time.Duration
		midLifetime  time.Duration
		wantLifetime time.Duration
	}{
		{"root expires first", 10 * time.Minute, time.Hour, 9 * time.Minute},
		{"intermediate expires first", time.Hour, 5 * time.Minute, 4 * time.Minute},
		{"unrelated root expires first", time.Hour, time.Hour, 15 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootPEM, rootKey := testCAKeyPair(
				t,
				now.Add(-time.Hour),
				now.Add(tc.rootLifetime),
				true,
				true,
				x509.KeyUsageCertSign,
			)
			root, err := ParseSigningCA(rootPEM, rootKey, now)
			if err != nil {
				t.Fatal(err)
			}
			mid := testChildCA(t, root, "intermediate", now, tc.midLifetime)
			active := testChildCA(t, mid, "signing CA", now, 2*time.Hour)
			// The unrelated root has the same subject as the real root. Matching
			// names alone must not constrain the signing chain's lifetime.
			unrelated, _ := testCAKeyPair(
				t,
				now.Add(-time.Hour),
				now.Add(2*time.Minute),
				true,
				true,
				x509.KeyUsageCertSign,
			)
			bundle := append(active.CertificatePEM(), unrelated...)
			bundle = append(bundle, rootPEM...)
			bundle = append(bundle, mid.CertificatePEM()...)
			ca, err := ParseSigningCABundle(bundle, active.PrivateKeyPEM(), now)
			if err != nil {
				t.Fatal(err)
			}
			options := LeafOptions{
				CurrentTime:        now,
				Lifetime:           15 * time.Minute,
				IssuerExpiryMargin: time.Minute,
				MinimumLifetime:    time.Minute,
				Server:             true,
			}
			leaf, err := ca.Sign(context.Background(), active.privateKey.Public(), options)
			if err != nil {
				t.Fatal(err)
			}
			if want := now.Add(tc.wantLifetime); !leaf.NotAfter.Equal(want) {
				t.Fatalf("leaf expiry = %s, want %s", leaf.NotAfter, want)
			}
			roots := x509.NewCertPool()
			roots.AddCert(root.certificate)
			intermediates := x509.NewCertPool()
			intermediates.AddCert(mid.certificate)
			intermediates.AddCert(active.certificate)
			if _, err := leaf.Certificate.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				CurrentTime:   leaf.NotAfter.Add(-time.Second),
			}); err != nil {
				t.Fatalf("leaf chain is invalid before leaf expiry: %v", err)
			}
			// Reuse the loaded snapshot after its ancestors enter the renewal
			// window and expire; a Secret update must not be necessary to stop signing.
			deadline := now.Add(min(tc.rootLifetime, tc.midLifetime))
			for _, at := range []time.Time{deadline.Add(-2 * time.Minute), deadline.Add(time.Second)} {
				options.CurrentTime = at
				if _, err := ca.Sign(context.Background(), active.privateKey.Public(), options); err == nil {
					t.Fatalf("signing succeeded too close to/after chain expiry at %s", at)
				}
			}
		})
	}
}

func TestRenewSelfSignedCARejectsIntermediate(t *testing.T) {
	now := time.Now()
	rootPEM, rootKey := testCAKeyPair(t, now.Add(-time.Hour), now.Add(time.Hour), true, true, x509.KeyUsageCertSign)
	root, err := ParseSigningCA(rootPEM, rootKey, now)
	if err != nil {
		t.Fatal(err)
	}
	intermediate := testChildCA(t, root, "intermediate", now, time.Hour)
	if _, err := RenewSelfSignedCA(intermediate, time.Hour, now); err == nil {
		t.Fatal("renewal converted an intermediate into a self-signed root")
	}
}

func testChildCA(t *testing.T, parent SigningCA, name string, now time.Time, lifetime time.Duration) SigningCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent.certificate, key.Public(), parent.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseSigningCA(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), now)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}
