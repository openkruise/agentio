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
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestMITMOCSPStapling(t *testing.T) {
	for _, tc := range []struct {
		name        string
		enabled     bool
		publication bool
	}{
		{"disabled", false, false},
		{"standalone", true, false},
		{"CRL without stapling", false, true},
		{"stapling with CRL", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			now := time.Now().UTC().Truncate(time.Second)
			secret := newMITMSecret(t, "pki", "issuer", 24*time.Hour, now)
			ca, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], now)
			if err != nil {
				t.Fatal(err)
			}
			crlExpiry := now.Add(5 * time.Minute)
			der, err := ca.SignCRL(&x509.RevocationList{
				Number:     big.NewInt(1),
				ThisUpdate: now,
				NextUpdate: crlExpiry,
			})
			if err != nil {
				t.Fatal(err)
			}
			file := ca.CRLKeyID() + ".crl"
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "system", Name: crlConfigMapName},
				BinaryData: map[string][]byte{file: der},
			}
			client := kube.NewFakeClient(secret, cm)
			maps := krt.NewInformer[*corev1.ConfigMap](client, krt.WithStop(ctx.Done()))
			go client.Run(ctx.Done())
			origin := ""
			if tc.publication {
				origin = "http://pki.test"
			}
			signer, err := NewMITMSigner(ctx, client, MITMSignerOptions{
				Mode:                MITMSignModeSecret,
				Namespace:           "system",
				SecretNamespace:     secret.Namespace,
				SecretName:          secret.Name,
				OCSPStaplingEnabled: tc.enabled,
				CRLOrigin:           origin,
				ConfigMaps:          maps,
				LeafExpiryMargin:    time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			issuer, err := NewOnDemandIssuer(
				ctx,
				DomainSignerSource{Signer: signer, State: signer.State()},
				&fakeGatewayAuthorizer{},
				OnDemandOptions{
					LeafLifetime: 10 * time.Minute,
					RenewBefore:  time.Minute,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			var issued SignedCertificate
			testutil.Eventually(t, func() bool {
				issued, err = issuer.Get(ctx, model.ClientScope{}, "app.example")
				return err == nil
			}, "issue a certificate with the selected staple mode")
			if !tc.enabled {
				if len(issued.OCSPStaple) != 0 {
					t.Fatal("disabled flag returned a staple")
				}
				if tc.publication && !issued.NotAfter.After(crlExpiry) {
					t.Fatal("disabled stapling changed external CRL lifetime semantics")
				}
				return
			}
			block, _ := pem.Decode(issued.CertificateChain)
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			response, err := ocsp.ParseResponseForCert(issued.OCSPStaple, leaf, ca.Certificate())
			if err != nil {
				t.Fatal(err)
			}
			if response.Status != ocsp.Good || !response.NextUpdate.Equal(leaf.NotAfter) ||
				!issued.UsableUntil.Before(response.NextUpdate) {
				t.Fatal("staple status or expiry is inconsistent with the leaf and SDS deadline")
			}
			if tc.publication && !leaf.NotAfter.Equal(crlExpiry) {
				t.Fatal("staple outlives its source CRL")
			}
			expected := append([]byte(nil), issued.OCSPStaple...)
			issued.OCSPStaple[0] ^= 0xff
			cached, err := issuer.Get(ctx, model.ClientScope{}, "app.example")
			if err != nil || !bytes.Equal(cached.OCSPStaple, expected) {
				t.Fatal("caller mutated the cached staple")
			}
			if !tc.publication {
				return
			}

			revision := cached.SignerRevision
			cms := client.Kube().CoreV1().ConfigMaps(cm.Namespace)
			unrelated := cm.DeepCopy()
			unrelated.BinaryData["unrelated.der"] = []byte("other issuer's response")
			if _, err := cms.Update(ctx, unrelated, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			testutil.Eventually(t, func() bool {
				observed := maps.GetKey(cm.Namespace + "/" + cm.Name)
				return observed != nil && len((*observed).BinaryData["unrelated.der"]) > 0
			}, "observe unrelated status update")
			if signer.State().Get().Revision != revision {
				t.Fatal("unrelated status invalidated leaf staples")
			}

			revoked := unrelated.DeepCopy()
			revoked.BinaryData[file], err = ca.SignCRL(&x509.RevocationList{
				Number:     big.NewInt(2),
				ThisUpdate: now,
				NextUpdate: crlExpiry,
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{SerialNumber: leaf.SerialNumber, RevocationTime: now},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cms.Update(ctx, revoked, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			var replacement SignedCertificate
			testutil.Eventually(t, func() bool {
				replacement, err = issuer.Get(ctx, model.ClientScope{}, "app.example")
				return err == nil && replacement.SignerRevision != revision
			}, "revocation invalidates the cached certificate and staple")
			block, _ = pem.Decode(replacement.CertificateChain)
			current, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if current.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				t.Fatal("revoked leaf was reused")
			}
			if _, err := ocsp.ParseResponseForCert(replacement.OCSPStaple, current, ca.Certificate()); err != nil {
				t.Fatal(err)
			}
			if signer.TrustBundles().Get().Revision != ca.Revision() {
				t.Fatal("CRL update changed public trust revision")
			}
		})
	}
}

func TestStaplingRenewsSubCAUsageWithExistingKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newMITMSecret(t, "pki", "parent", 2*subCALifetime, now)
	parent, err := pki.ParseSigningCABundle(root.Data[mitmCACertKey], root.Data[mitmCAKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	client := kube.NewFakeClient(root)
	signer := &MITMSigner{
		client:  client,
		options: MITMSignerOptions{Namespace: "system"},
		crls:    &crlPublisher{origin: "http://pki.test"},
	}
	if err := signer.reconcileSubCA(t.Context(), parent, now); err != nil {
		t.Fatal(err)
	}
	secrets := client.Kube().CoreV1().Secrets("system")
	secret, err := secrets.Get(t.Context(), subCASecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	legacy := *child.Certificate()
	legacy.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	keyBlock, _ := pem.Decode(root.Data[mitmCAKeyKey])
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &legacy, parent.Certificate(), legacy.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	secret.Data[mitmCACertKey] = pki.AppendCertificateChain(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		parent.BundlePEM(),
	)
	if _, err := secrets.Update(t.Context(), secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	signer.options.OCSPStaplingEnabled = true
	if err := signer.reconcileSubCA(t.Context(), parent, now); err != nil {
		t.Fatal(err)
	}
	updated, err := secrets.Get(t.Context(), subCASecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := pki.ParseSigningCABundle(updated.Data[mitmCACertKey], updated.Data[mitmCAKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret.Data[mitmCAKeyKey], updated.Data[mitmCAKeyKey]) || renewed.CRLKeyID() != child.CRLKeyID() ||
		renewed.Certificate().KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("OCSP usage upgrade changed key or failed to grant digitalSignature")
	}
	badUsage := *parent.Certificate()
	badUsage.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	der, err = x509.CreateCertificate(rand.Reader, &badUsage, &badUsage, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	badCA, err := pki.ParseSigningCABundle(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		root.Data[mitmCAKeyKey],
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	installed := newInstalledMITMSigner(t, badCA, "parent", time.Minute)
	installed.options.OCSPStaplingEnabled = true
	if _, err := installed.SignDNS(
		t.Context(),
		"no-usage.example",
		time.Minute,
	); err == nil ||
		!strings.Contains(err.Error(), "digitalSignature") {
		t.Fatal("signer accepted a CA without OCSP signing usage")
	}
}
