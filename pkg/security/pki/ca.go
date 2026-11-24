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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	defaultRSAKeySize = 2048
	// ClockSkew is the allowance for backdating certificates and CRLs.
	ClockSkew = time.Minute
)

var asciiWhitespace = " \t\r\n\v\f"

// SigningCA is an immutable snapshot of a validated signing certificate,
// matching private key, and the original certificate bundle distributed with
// issued leaves.
type SigningCA struct {
	certificate    *x509.Certificate
	privateKey     crypto.Signer
	certificatePEM []byte
	privateKeyPEM  []byte
	bundlePEM      []byte
	revision       string
	chainNotAfter  time.Time
}

func (ca SigningCA) Available() bool {
	return ca.certificate != nil && ca.privateKey != nil
}

func (ca SigningCA) NotAfter() time.Time {
	if ca.certificate == nil {
		return time.Time{}
	}
	return ca.certificate.NotAfter
}

// Revision identifies the ordered certificate bundle semantically, independent
// of PEM formatting. It changes when either the active CA or a trailing CA
// changes, so consumers never reuse a leaf with an obsolete chain.
func (ca SigningCA) Revision() string {
	return ca.revision
}

func (ca SigningCA) Equal(other SigningCA) bool {
	if ca.certificate == nil || other.certificate == nil {
		return ca.certificate == other.certificate
	}
	return ca.certificate.Equal(other.certificate) && bytes.Equal(ca.bundlePEM, other.bundlePEM)
}

func (ca SigningCA) CertificatePEM() []byte {
	return append([]byte(nil), ca.certificatePEM...)
}

func (ca SigningCA) CRLKeyID() string {
	return hex.EncodeToString(ca.certificate.SubjectKeyId)
}

func (ca SigningCA) VerifyCRL(list *x509.RevocationList) error {
	if !bytes.Equal(list.RawIssuer, ca.certificate.RawSubject) ||
		!bytes.Equal(list.AuthorityKeyId, ca.certificate.SubjectKeyId) {
		return fmt.Errorf("CRL issuer does not match the signing CA")
	}
	return list.CheckSignatureFrom(ca.certificate)
}

func (ca SigningCA) SignCRL(list *x509.RevocationList) ([]byte, error) {
	return x509.CreateRevocationList(rand.Reader, list, ca.certificate, ca.privateKey)
}

func (ca SigningCA) PrivateKeyPEM() []byte {
	return append([]byte(nil), ca.privateKeyPEM...)
}

func (ca SigningCA) BundlePEM() []byte {
	return append([]byte(nil), ca.bundlePEM...)
}

// ParseSigningCA parses exactly one PEM-encoded signing certificate.
func ParseSigningCA(certPEM, keyPEM []byte, now time.Time) (SigningCA, error) {
	return parseSigningCA(certPEM, keyPEM, now, false, false)
}

// ParseSigningCABundle parses a signing certificate followed by zero or more
// CA certificates. The first certificate must match keyPEM; the complete
// bundle is preserved for delivery with issued leaves.
func ParseSigningCABundle(bundlePEM, keyPEM []byte, now time.Time) (SigningCA, error) {
	return parseSigningCA(bundlePEM, keyPEM, now, true, false)
}

// ParseSelfSignedCAForRenewal permits an expired active root only for SELF_SIGN
// maintenance. Key matching, self-signature, NotBefore and any trailing CAs are
// still validated. Normal signer loading must use ParseSigningCA[Bundle].
func ParseSelfSignedCAForRenewal(certPEM, keyPEM []byte, now time.Time, allowBundle bool) (SigningCA, error) {
	return parseSigningCA(certPEM, keyPEM, now, allowBundle, true)
}

func parseSigningCA(certPEM, keyPEM []byte, now time.Time, allowBundle, renewal bool) (SigningCA, error) {
	certificates, err := parseCACertificates(certPEM, now, renewal)
	if err != nil {
		return SigningCA{}, err
	}
	if !allowBundle && len(certificates) != 1 {
		return SigningCA{}, fmt.Errorf("CA certificate has trailing data")
	}
	if renewal && !isSelfSigned(certificates[0]) {
		return SigningCA{}, fmt.Errorf("active CA certificate is not self-signed")
	}

	keyBlock, err := DecodeSinglePEMBlock(keyPEM, "CA private key")
	if err != nil {
		return SigningCA{}, err
	}
	privateKey, err := parsePrivateKey(keyBlock)
	if err != nil {
		return SigningCA{}, err
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return SigningCA{}, fmt.Errorf("CA private key type %T does not implement crypto.Signer", privateKey)
	}
	if err := validateMatchingKey(certificates[0], signer); err != nil {
		return SigningCA{}, err
	}

	digest := sha256.New()
	for _, certificate := range certificates {
		digest.Write(certificate.Raw)
	}
	return SigningCA{
		certificate:    certificates[0],
		privateKey:     signer,
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificates[0].Raw}),
		privateKeyPEM:  append([]byte(nil), keyPEM...),
		bundlePEM:      append([]byte(nil), certPEM...),
		revision:       hex.EncodeToString(digest.Sum(nil)),
		chainNotAfter:  signingChainExpiry(certificates),
	}, nil
}

// signingChainExpiry follows verified issuer links, regardless of bundle order.
// Unrelated staged roots do not shorten the active chain's lifetime. If the
// bundle offers alternative issuer certificates, cap at the earliest expiry so
// the leaf remains bounded by every supplied path a client might select.
func signingChainExpiry(certificates []*x509.Certificate) time.Time {
	expires := certificates[0].NotAfter
	chain := []*x509.Certificate{certificates[0]}
	seen := map[*x509.Certificate]bool{certificates[0]: true}
	for len(chain) > 0 {
		certificate := chain[0]
		chain = chain[1:]
		if certificate.NotAfter.Before(expires) {
			expires = certificate.NotAfter
		}
		if isSelfSigned(certificate) {
			continue
		}
		for _, parent := range certificates {
			if !seen[parent] && bytes.Equal(certificate.RawIssuer, parent.RawSubject) &&
				certificate.CheckSignatureFrom(parent) == nil {
				seen[parent] = true
				chain = append(chain, parent)
			}
		}
	}
	return expires
}

func isSelfSigned(certificate *x509.Certificate) bool {
	return bytes.Equal(certificate.RawIssuer, certificate.RawSubject) &&
		certificate.CheckSignatureFrom(certificate) == nil
}

func parseCACertificates(value []byte, now time.Time, renewal bool) ([]*x509.Certificate, error) {
	remaining := bytes.Trim(value, asciiWhitespace)
	if len(remaining) == 0 {
		return nil, fmt.Errorf("CA certificate is empty")
	}
	var certificates []*x509.Certificate
	for index := 1; len(remaining) > 0; index++ {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, fmt.Errorf("CA certificate has invalid PEM data at certificate %d", index)
		}
		consumed := remaining[:len(remaining)-len(rest)]
		beginMarker := []byte("-----BEGIN " + block.Type + "-----")
		if !bytes.HasPrefix(consumed, beginMarker) || bytes.Count(consumed, []byte("-----BEGIN ")) != 1 {
			return nil, fmt.Errorf("CA certificate has invalid PEM data at certificate %d", index)
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("CA certificate PEM block %d has type %q", index, block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA certificate %d: %w", index, err)
		}
		if err := validateCACertificate(
			certificate,
			now,
			fmt.Sprintf("CA certificate %d", index),
			renewal && index == 1,
		); err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		remaining = bytes.Trim(rest, asciiWhitespace)
	}
	return certificates, nil
}

func validateCACertificate(certificate *x509.Certificate, now time.Time, name string, allowExpired bool) error {
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		return fmt.Errorf("%s does not have valid CA basic constraints", name)
	}
	if certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%s does not allow certificate signing key usage", name)
	}
	if now.Before(certificate.NotBefore) {
		return fmt.Errorf("%s is not valid before %s", name, certificate.NotBefore.UTC().Format(time.RFC3339))
	}
	if !allowExpired && now.After(certificate.NotAfter) {
		return fmt.Errorf("%s expired at %s", name, certificate.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func validateMatchingKey(certificate *x509.Certificate, signer crypto.Signer) error {
	certificatePublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal CA certificate public key: %w", err)
	}
	signerPublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshal CA private key public key: %w", err)
	}
	if !bytes.Equal(certificatePublicKey, signerPublicKey) {
		return fmt.Errorf("CA private key does not match certificate public key")
	}
	return nil
}

// DecodeSinglePEMBlock decodes exactly one PEM block from value, rejecting
// leading or trailing data; name labels the input in errors.
func DecodeSinglePEMBlock(value []byte, name string) (*pem.Block, error) {
	value = bytes.Trim(value, asciiWhitespace)
	block, trailing := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM encoded", name)
	}
	if len(trailing) != 0 {
		return nil, fmt.Errorf("%s has trailing data", name)
	}
	beginMarker := []byte("-----BEGIN " + block.Type + "-----")
	if !bytes.HasPrefix(value, beginMarker) || bytes.Count(value, beginMarker) != 1 {
		return nil, fmt.Errorf("%s has leading data", name)
	}
	return block, nil
}

func parsePrivateKey(block *pem.Block) (any, error) {
	var (
		privateKey any
		err        error
	)
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported CA private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	return privateKey, nil
}

// NewSelfSignedCA and RenewSelfSignedCA implement the control plane's supported
// RSA CA path with strict input validation.
func NewSelfSignedCA(commonName string, lifetime time.Duration, now time.Time) (SigningCA, error) {
	if lifetime <= 0 {
		return SigningCA{}, fmt.Errorf("CA lifetime must be positive")
	}
	key, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	if err != nil {
		return SigningCA{}, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return SigningCA{}, fmt.Errorf("generate CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-ClockSkew),
		NotAfter:              now.Add(lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return SigningCA{}, fmt.Errorf("self-sign CA: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return ParseSigningCA(certPEM, keyPEM, now)
}

func RenewSelfSignedCA(ca SigningCA, lifetime time.Duration, now time.Time) (SigningCA, error) {
	if !ca.Available() {
		return SigningCA{}, fmt.Errorf("signing CA is not available")
	}
	if !isSelfSigned(ca.certificate) {
		return SigningCA{}, fmt.Errorf("active CA certificate is not self-signed")
	}
	if lifetime <= 0 {
		return SigningCA{}, fmt.Errorf("CA lifetime must be positive")
	}
	serial, err := randomSerial()
	if err != nil {
		return SigningCA{}, fmt.Errorf("generate CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               ca.certificate.Subject,
		NotBefore:             now.Add(-ClockSkew),
		NotAfter:              now.Add(lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              ca.certificate.KeyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, ca.privateKey.Public(), ca.privateKey)
	if err != nil {
		return SigningCA{}, fmt.Errorf("re-sign root CA: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// Replace only the active certificate. A MITM bundle may carry additional
	// operator-supplied CA certificates after it; those remain in their original
	// order across SELF_SIGN renewal. A strict workload CA has no trailing blocks.
	_, trailing := pem.Decode(bytes.TrimLeft(ca.bundlePEM, asciiWhitespace))
	bundlePEM := append(certPEM, trailing...)
	if len(bytes.TrimSpace(trailing)) == 0 {
		return ParseSigningCA(bundlePEM, ca.privateKeyPEM, now)
	}
	return ParseSigningCABundle(bundlePEM, ca.privateKeyPEM, now)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// ValidateTrustBundle validates the self-signed root-only bundle stored in the
// workload CA Secret.
func ValidateTrustBundle(bundle []byte, active SigningCA, now time.Time) error {
	if !active.Available() {
		return fmt.Errorf("active signing certificate is required")
	}
	remaining := bytes.Trim(bundle, asciiWhitespace)
	if len(remaining) == 0 {
		return fmt.Errorf("trust bundle is empty")
	}
	containsActive := false
	for index := 1; len(remaining) > 0; index++ {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return fmt.Errorf("trust bundle has invalid PEM data at certificate %d", index)
		}
		consumed := remaining[:len(remaining)-len(rest)]
		beginMarker := []byte("-----BEGIN " + block.Type + "-----")
		if !bytes.HasPrefix(consumed, beginMarker) || bytes.Count(consumed, []byte("-----BEGIN ")) != 1 {
			return fmt.Errorf("trust bundle has invalid PEM data at certificate %d", index)
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("trust bundle PEM block has type %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse trust bundle certificate %d: %w", index, err)
		}
		if err := validateCACertificate(
			certificate,
			now,
			fmt.Sprintf("trust bundle certificate %d", index),
			false,
		); err != nil {
			return err
		}
		if !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) || certificate.CheckSignatureFrom(certificate) != nil {
			return fmt.Errorf("trust bundle certificate %d is not self-signed", index)
		}
		if certificate.Equal(active.certificate) {
			containsActive = true
		}
		remaining = bytes.Trim(rest, asciiWhitespace)
	}
	if !containsActive {
		return fmt.Errorf("trust bundle does not contain active signing certificate")
	}
	return nil
}
