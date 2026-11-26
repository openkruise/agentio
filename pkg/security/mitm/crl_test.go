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

package mitm

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestCRLRenewalUsesSignedList(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := pki.NewSelfSignedCA("issuer", 72*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	id := ca.CRLKeyID()
	file := id + ".crl"
	urlPath := "/crl/" + file
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "system", Name: crlConfigMapName}}
	client := kube.NewFakeClient(cm)
	maps := krt.NewMutableCollection(nil, []*corev1.ConfigMap{cm})
	signer := newInstalledMITMSigner(t, ca, "issuer", time.Minute)
	p, err := newCRLPublisher(MITMSignerOptions{
		Mode: MITMSignModeSelfSign, Namespace: cm.Namespace, CRLOrigin: "http://pki.test",
		ConfigMaps: maps.AsCollection(),
	}, client)
	if err != nil {
		t.Fatal(err)
	}
	signer.crls = p
	download := func(path string, want int) []byte {
		t.Helper()
		rec := httptest.NewRecorder()
		signer.CRLHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want || (want == 200 && rec.Header().Get("Content-Type") != "application/pkix-crl") {
			t.Fatalf("GET %s: %d %v", path, rec.Code, rec.Header())
		}
		return rec.Body.Bytes()
	}
	store := func(cm *corev1.ConfigMap) {
		t.Helper()
		stored, err := client.Kube().CoreV1().ConfigMaps(cm.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		maps.Reset([]*corev1.ConfigMap{stored})
	}
	if err := p.reconcile(ctx, ca, now); err == nil {
		t.Fatal("renewed without a signed source")
	}
	if _, err := signer.SignDNS(ctx, "one.example", 15*time.Minute); err == nil {
		t.Fatal("issued a leaf before publication")
	}
	download(urlPath, http.StatusNotFound)

	revokedAt := now.Add(-time.Minute)
	seedExpiry := now.Add(5 * time.Minute)
	seed, err := ca.SignCRL(&x509.RevocationList{
		Number: big.NewInt(7), ThisUpdate: revokedAt, NextUpdate: seedExpiry,
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(42), RevocationTime: revokedAt, ReasonCode: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	seeded := cm.DeepCopy()
	seeded.BinaryData = map[string][]byte{file: seed}
	store(seeded)
	nearExpiry, err := signer.SignDNS(ctx, "one.example", 15*time.Minute)
	if err != nil || !nearExpiry.NotAfter.Equal(seedExpiry) {
		t.Fatalf(
			"certificate validity exceeds the current CRL window or issuance failed: expiry %v, err %v",
			nearExpiry.NotAfter,
			err,
		)
	}
	if err := p.reconcile(ctx, ca, now); err != nil {
		t.Fatal(err)
	}
	stored, err := client.Kube().CoreV1().ConfigMaps(cm.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	maps.Reset([]*corev1.ConfigMap{stored})
	regular, err := parseFullCRL(download(urlPath, http.StatusOK), id)
	if err != nil || ca.VerifyCRL(regular) != nil ||
		!regular.NextUpdate.Equal(now.Add(24*time.Hour)) || regular.Number.Cmp(big.NewInt(8)) != 0 ||
		len(regular.RevokedCertificateEntries) != 1 || len(stored.BinaryData) != 1 {
		t.Fatalf("expected one renewed 24-hour CRL carrying the revoked entry: %v", err)
	}
	entry := regular.RevokedCertificateEntries[0]
	if entry.SerialNumber.Cmp(big.NewInt(42)) != 0 || !entry.RevocationTime.Equal(revokedAt) || entry.ReasonCode != 1 {
		t.Fatalf("renewal changed revoked entry: %+v", entry)
	}
	if err := p.reconcile(ctx, ca, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	unchanged, err := client.Kube().CoreV1().ConfigMaps(cm.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if err != nil || !bytes.Equal(unchanged.BinaryData[file], regular.Raw) {
		t.Fatalf("renewed a CRL that was still current: %v", err)
	}
	issued, err := signer.SignDNS(ctx, "one.example", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued.CertificateChain)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != p.origin+urlPath ||
		len(leaf.OCSPServer) != 0 {
		t.Fatalf("unexpected status URLs: %v %v", leaf.CRLDistributionPoints, leaf.OCSPServer)
	}
	corrupt := stored.DeepCopy()
	der := corrupt.BinaryData[file]
	der[len(der)-1] ^= 1
	store(corrupt)
	if err := p.reconcile(ctx, ca, now); err == nil {
		t.Fatal("renewed a CRL with an invalid signature")
	}
	download(urlPath, http.StatusServiceUnavailable)
	download("/metrics", http.StatusNotFound)
}

func TestCRLDownloadAfterSigningKeyChange(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	publishedAt := now.Add(-time.Hour)
	previous, err := pki.NewSelfSignedCA("previous", 72*time.Hour, publishedAt)
	if err != nil {
		t.Fatal(err)
	}
	active, err := pki.NewSelfSignedCA("active", 72*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	id := previous.CRLKeyID()
	file := id + ".crl"
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "system", Name: crlConfigMapName}}
	maps := krt.NewMutableCollection(nil, []*corev1.ConfigMap{cm})
	signer := newInstalledMITMSigner(t, active, "active", time.Minute)
	signer.crls = &crlPublisher{namespace: cm.Namespace, maps: maps.AsCollection(), managed: true}

	for _, tc := range []struct {
		name   string
		expiry time.Time
		status int
	}{
		{"current", now.Add(5 * time.Minute), http.StatusOK},
		{"expired", now.Add(-time.Minute), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := previous.SignCRL(&x509.RevocationList{
				Number: big.NewInt(7), ThisUpdate: publishedAt, NextUpdate: tc.expiry,
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{SerialNumber: big.NewInt(42), RevocationTime: publishedAt},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			stored := cm.DeepCopy()
			stored.BinaryData = map[string][]byte{file: der}
			maps.Reset([]*corev1.ConfigMap{stored})
			rec := httptest.NewRecorder()
			signer.CRLHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/crl/"+file, nil))
			if rec.Code != tc.status || (tc.status == http.StatusOK && !bytes.Equal(rec.Body.Bytes(), der)) {
				t.Fatalf("GET old CA's file: HTTP %d, want %d", rec.Code, tc.status)
			}
			if _, err := signer.SignDNS(t.Context(), "one.example", 15*time.Minute); err == nil {
				t.Fatal("issued a new leaf without the new key's CRL")
			}
		})
	}
}

func TestCRLServiceAcrossCASecrets(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	before := newMITMSecret(t, "pki-old", "ca-v1", 24*time.Hour, now)
	after := newMITMSecret(t, "pki-new", "ca-v2", 24*time.Hour, now)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "custom-system", Name: crlConfigMapName},
		BinaryData: map[string][]byte{},
	}
	for _, secret := range []*corev1.Secret{before, after} {
		ca, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], now)
		if err != nil {
			t.Fatal(err)
		}
		der, err := ca.SignCRL(
			&x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)},
		)
		if err != nil {
			t.Fatal(err)
		}
		cm.BinaryData[ca.CRLKeyID()+".crl"] = der
	}
	client := kube.NewFakeClient(before, after, cm)
	maps := krt.NewInformer[*corev1.ConfigMap](client, krt.WithStop(ctx.Done()))
	go client.Run(ctx.Done())
	if !maps.WaitUntilSynced(ctx.Done()) {
		t.Fatal("CRL ConfigMap informer did not sync")
	}
	const origin = "http://pki.test"
	for _, secret := range []*corev1.Secret{before, after} {
		signer, err := NewMITMSigner(ctx, client, MITMSignerOptions{
			Mode: MITMSignModeSecret, Namespace: cm.Namespace, SecretNamespace: secret.Namespace,
			SecretName: secret.Name, ConfigMaps: maps, CRLOrigin: origin,
		})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Eventually(
			t,
			func() bool { return signer.State().Get() != nil },
			"load CA Secret from its own namespace",
		)
		issued, err := signer.SignDNS(ctx, "app.example", 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(issued.CertificateChain)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		points := leaf.CRLDistributionPoints
		if len(points) != 1 || points[0] != fmt.Sprintf("%s/crl/%x.crl", origin, leaf.AuthorityKeyId) {
			t.Fatalf("replica using %s issued a leaf with distribution points %v", secret.Name, points)
		}
		for file, der := range cm.BinaryData {
			rec := httptest.NewRecorder()
			signer.CRLHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/crl/"+file, nil))
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), der) {
				t.Fatalf("replica using %s failed to serve %s: HTTP %d", secret.Name, file, rec.Code)
			}
		}
	}
}
