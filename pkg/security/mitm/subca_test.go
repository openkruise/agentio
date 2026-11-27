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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestManagedSubCA(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		origin  string
	}{
		{"disabled", false, ""},
		{"enabled without publication", true, ""},
		{"enabled with publication", true, "http://pki.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			now := time.Now()
			root := newMITMSecret(t, "parent-namespace", "parent-ca", 2*365*24*time.Hour, now)
			// The parent allows certificate signing without CRL signing.
			block, _ := pem.Decode(root.Data[mitmCACertKey])
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			block, _ = pem.Decode(root.Data[mitmCAKeyKey])
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			root.Data[mitmCACertKey] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			parent, err := pki.ParseSigningCABundle(root.Data[mitmCACertKey], root.Data[mitmCAKeyKey], now)
			if err != nil {
				t.Fatal(err)
			}
			client := kube.NewFakeClient(root)
			maps := krt.NewInformer[*corev1.ConfigMap](client, krt.WithStop(ctx.Done()))
			go client.Run(ctx.Done())
			options := MITMSignerOptions{
				Mode:             MITMSignModeSecret,
				Namespace:        "system",
				SecretNamespace:  root.Namespace,
				SecretName:       root.Name,
				SubCAEnabled:     tc.enabled,
				CRLOrigin:        tc.origin,
				ConfigMaps:       maps,
				LeafExpiryMargin: time.Minute,
			}
			signer, err := NewMITMSigner(ctx, client, options)
			if err != nil {
				t.Fatal(err)
			}
			var leaf SignedCertificate
			testutil.Eventually(t, func() bool {
				leaf, err = signer.SignDNS(ctx, "app.example", 15*time.Minute)
				return err == nil
			}, "issue using the configured CA mode")
			var certs []*x509.Certificate
			for remaining := leaf.CertificateChain; len(remaining) > 0; {
				b, tail := pem.Decode(remaining)
				if b == nil {
					t.Fatal("invalid issued chain")
				}
				parsed, err := x509.ParseCertificate(b.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				certs = append(certs, parsed)
				remaining = tail
			}
			want := 2
			if tc.enabled {
				want = 3
			}
			if len(certs) != want {
				t.Fatalf("chain contains %d certs, want %d", len(certs), want)
			}
			roots := x509.NewCertPool()
			roots.AddCert(parent.Certificate())
			intermediates := x509.NewCertPool()
			for _, c := range certs[1:] {
				intermediates.AddCert(c)
			}
			if _, err := certs[0].Verify(
				x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "app.example"},
			); err != nil {
				t.Fatal(err)
			}
			secrets := client.Kube().CoreV1().Secrets("system")
			if !tc.enabled {
				if _, err := secrets.Get(ctx, subCASecretName, metav1.GetOptions{}); err == nil {
					t.Fatal("disabled flag created a Sub CA")
				}
				return
			}
			sub := certs[1]
			if sub.KeyUsage&x509.KeyUsageCRLSign == 0 || !sub.MaxPathLenZero {
				t.Fatal("missing Sub CA CRL usage or path length")
			}
			stored, err := secrets.Get(ctx, subCASecretName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(stored.Data[mitmCAKeyKey], root.Data[mitmCAKeyKey]) {
				t.Fatal("Sub CA reused parent private key")
			}
			replica, err := NewMITMSigner(ctx, client, options)
			if err != nil {
				t.Fatal(err)
			}
			testutil.Eventually(
				t,
				func() bool { return replica.State().Get() != nil },
				"second replica loads shared Sub CA",
			)
			if replica.currentRevision() != signer.currentRevision() {
				t.Fatal("replicas use different Sub CAs")
			}
			if tc.origin == "" {
				if signer.CRLHandler() != nil || len(sub.OCSPServer) != 0 || len(certs[0].CRLDistributionPoints) != 0 {
					t.Fatal("publication enabled without an origin")
				}
				return
			}
			handler := signer.CRLHandler()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest("GET", certs[0].CRLDistributionPoints[0], nil))
			list, err := x509.ParseRevocationList(rec.Body.Bytes())
			if err != nil || rec.Code != 200 {
				t.Fatalf("CRL download: HTTP %d, %v", rec.Code, err)
			}
			if err := list.CheckSignatureFrom(sub); err != nil {
				t.Fatal(err)
			}
			for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
				request, err := ocsp.CreateRequest(sub, parent.Certificate(), &ocsp.RequestOptions{Hash: hash})
				if err != nil {
					t.Fatal(err)
				}
				for _, method := range []string{"GET", "POST"} {
					path := sub.OCSPServer[0]
					if method == "GET" {
						path += "/" + url.PathEscape(base64.StdEncoding.EncodeToString(request))
					}
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, httptest.NewRequest(method, path, bytes.NewReader(request)))
					response, err := ocsp.ParseResponseForCert(rec.Body.Bytes(), sub, parent.Certificate())
					if rec.Code != 200 || err != nil || response.Status != ocsp.Good {
						t.Fatalf("OCSP %s: %v", method, err)
					}
				}
				unknown := *sub
				unknown.SerialNumber = big.NewInt(424242)
				body, err := ocsp.CreateRequest(&unknown, parent.Certificate(), &ocsp.RequestOptions{Hash: hash})
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, sub.OCSPServer[0], bytes.NewReader(body)))
				if !bytes.Equal(rec.Body.Bytes(), ocsp.UnauthorizedErrorResponse) {
					t.Fatal("OCSP authorized an unknown certificate")
				}
			}
			after, err := client.Kube().CoreV1().Secrets(root.Namespace).Get(ctx, root.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after.Data[mitmCACertKey], root.Data[mitmCACertKey]) ||
				!bytes.Equal(after.Data[mitmCAKeyKey], root.Data[mitmCAKeyKey]) {
				t.Fatal("Sub CA mode modified the parent Secret")
			}
			// An explicit revoked Sub CA status must stop issuance and renewal.
			requestDER, err := ocsp.CreateRequest(sub, parent.Certificate(), nil)
			if err != nil {
				t.Fatal(err)
			}
			request, err := ocsp.ParseRequest(requestDER)
			if err != nil {
				t.Fatal(err)
			}
			status, err := ocsp.CreateResponse(parent.Certificate(), parent.Certificate(), ocsp.Response{
				Status:       ocsp.Revoked,
				SerialNumber: sub.SerialNumber,
				RevokedAt:    now.Add(-time.Minute),
				ThisUpdate:   now.Add(-time.Minute),
				NextUpdate:   now.Add(time.Hour),
			}, key)
			if err != nil {
				t.Fatal(err)
			}
			cms := client.Kube().CoreV1().ConfigMaps("system")
			cm, err := cms.Get(ctx, crlConfigMapName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			cm.BinaryData[ocspKey(request)] = status
			if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			testutil.Eventually(t, func() bool {
				_, err := signer.SignDNS(ctx, "revoked.example", 15*time.Minute)
				return err != nil
			}, "revoked Sub CA stops signing")
			if err := signer.reconcileSubCA(ctx, parent, now); err == nil {
				t.Fatal("renewed a revoked Sub CA status")
			}
		})
	}
}

func TestSubCARenewalPreservesPublishedRevocations(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	parent, err := pki.NewSelfSignedCA("parent", 2*subCALifetime, now)
	if err != nil {
		t.Fatal(err)
	}
	client := kube.NewFakeClient()
	signer := &MITMSigner{
		client:  client,
		options: MITMSignerOptions{Namespace: "system"},
		crls:    &crlPublisher{origin: "http://pki.test"},
	}
	if err := signer.reconcileSubCA(ctx, parent, now); err != nil {
		t.Fatal(err)
	}
	api := client.Kube().CoreV1().Secrets("system")
	secret, err := api.Get(ctx, subCASecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	cms := client.Kube().CoreV1().ConfigMaps("system")
	cm, err := cms.Get(ctx, crlConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	oldResponses := len(cm.BinaryData)
	file := ca.CRLKeyID() + ".crl"
	cm.BinaryData[file], err = ca.SignCRL(&x509.RevocationList{
		Number:                    big.NewInt(10),
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlLifetime),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(42), RevocationTime: now}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	renewalAt := now.Add(subCALifetime - subCARenewBefore + time.Hour)
	if err := signer.reconcileSubCA(ctx, parent, renewalAt); err != nil {
		t.Fatal(err)
	}
	renewed, err := api.Get(ctx, subCASecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	next, err := pki.ParseSigningCABundle(renewed.Data[mitmCACertKey], renewed.Data[mitmCAKeyKey], renewalAt)
	if err != nil {
		t.Fatal(err)
	}
	if next.CRLKeyID() != ca.CRLKeyID() || !next.NotAfter().After(ca.NotAfter()) ||
		next.Certificate().SerialNumber.Cmp(ca.Certificate().SerialNumber) == 0 {
		t.Fatal("renewal did not retain the signing key and replace the certificate")
	}
	committed, err := cms.Get(ctx, crlConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed.BinaryData[file], cm.BinaryData[file]) || len(committed.BinaryData) <= oldResponses {
		t.Fatal("renewal lost the revocation list or the old OCSP responses")
	}
	delete(committed.BinaryData, file)
	if _, err := cms.Update(ctx, committed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := signer.reconcileSubCA(ctx, parent, renewalAt); err == nil {
		t.Fatal("recreated a missing historical CRL as an empty list")
	}
}
