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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// IssueSubCA uses the parent's key to sign a CA with an independent key.
// Renewal keeps the Sub CA key so its published CRL still covers older leaves.
func (ca SigningCA) IssueSubCA(
	previous *SigningCA,
	ocspURL string,
	lifetime time.Duration,
	now time.Time,
) (SigningCA, error) {
	if ca.certificate.MaxPathLenZero {
		return SigningCA{}, fmt.Errorf("parent CA path length forbids a Sub CA")
	}
	keyPEM := []byte(nil)
	var key crypto.Signer
	if previous != nil {
		key, keyPEM = previous.privateKey, previous.PrivateKeyPEM()
	} else {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return SigningCA{}, err
		}
		key = generated
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return SigningCA{}, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	serial, err := randomSerial()
	if err != nil {
		return SigningCA{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Agentio MITM Sub CA"},
		NotBefore: now.Add(-ClockSkew), NotAfter: minTime(now.Add(lifetime), ca.chainNotAfter),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if ocspURL != "" {
		template.OCSPServer = []string{ocspURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, key.Public(), ca.privateKey)
	if err != nil {
		return SigningCA{}, err
	}
	bundle := AppendCertificateChain(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.BundlePEM())
	return ParseSigningCABundle(bundle, keyPEM, now)
}

// SignOCSP signs the status of a certificate directly issued by this parent.
func (ca SigningCA) SignOCSP(child *x509.Certificate, hash crypto.Hash, now time.Time) ([]byte, error) {
	if err := child.CheckSignatureFrom(ca.certificate); err != nil {
		return nil, err
	}
	return ocsp.CreateResponse(ca.certificate, ca.certificate, ocsp.Response{
		Status: ocsp.Good, SerialNumber: child.SerialNumber, IssuerHash: hash,
		ThisUpdate: now.Add(-ClockSkew), NextUpdate: minTime(now.Add(24*time.Hour), ca.chainNotAfter),
	}, ca.privateKey)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
