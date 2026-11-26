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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/ptr"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/security/pki"
)

const (
	subCASecretName  = "agentio-mitm-sub-ca"
	subCALifetime    = 365 * 24 * time.Hour
	subCARenewBefore = 30 * 24 * time.Hour
)

func (s *MITMSigner) subCAOCSPURLs() []string {
	if s.crls == nil {
		return nil
	}
	return []string{s.crls.origin + "/ocsp"}
}

func (s *MITMSigner) parseSubCA(secret *corev1.Secret, parent pki.SigningCA, now time.Time) (pki.SigningCA, error) {
	ca, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], now)
	if err != nil {
		return pki.SigningCA{}, err
	}
	cert := ca.Certificate()
	if err := cert.CheckSignatureFrom(parent.Certificate()); err != nil {
		return pki.SigningCA{}, err
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 || !cert.MaxPathLenZero ||
		!slices.Equal(cert.OCSPServer, s.subCAOCSPURLs()) {
		return pki.SigningCA{}, fmt.Errorf("Sub CA has unexpected constraints, key usage or OCSP origin")
	}
	if !bytes.Equal(ca.BundlePEM(), pki.AppendCertificateChain(ca.CertificatePEM(), parent.BundlePEM())) {
		return pki.SigningCA{}, fmt.Errorf("Sub CA bundle differs from the configured parent chain")
	}
	return ca, nil
}

func (s *MITMSigner) subCACollection(ctx context.Context) krt.Singleton[caState] {
	client := kclient.NewFiltered[*corev1.Secret](s.client, kclient.Filter{
		Namespace: s.options.Namespace, FieldSelector: "metadata.name=" + subCASecretName,
	})
	secrets := krt.WrapClient(client, s.options.KrtOptions.WithName("MITM_Sub_CA_Secret")...)
	client.Start(ctx.Done())
	return krt.NewSingleton(func(hctx krt.HandlerContext) *caState {
		parent := krt.FetchOne(hctx, s.parentCA.AsCollection())
		child := ptr.Flatten(krt.FetchOne(hctx, secrets, krt.FilterKey(s.options.Namespace+"/"+subCASecretName)))
		if parent == nil || child == nil {
			return nil
		}
		ca, err := s.parseSubCA(child, parent.ca, time.Now())
		if err != nil {
			log.Error("load MITM Sub CA", "error", err)
			return nil
		}
		return &caState{ca: ca, secretUID: child.UID}
	}, s.options.KrtOptions.WithName("MITM_Sub_CA")...)
}

func (s *MITMSigner) runSubCAMaintenance(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var lastError string
	for {
		if parent := s.parentCA.Get(); parent != nil {
			err := s.reconcileSubCA(ctx, parent.ca, time.Now().UTC().Truncate(time.Second))
			switch {
			case err == nil:
				lastError = ""
			case !apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) && ctx.Err() == nil && err.Error() != lastError:
				log.Error("maintain MITM Sub CA", "error", err)
				lastError = err.Error()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *MITMSigner) reconcileSubCA(ctx context.Context, parent pki.SigningCA, now time.Time) error {
	api := s.client.Kube().CoreV1().Secrets(s.options.Namespace)
	secret, err := api.Get(ctx, subCASecretName, metav1.GetOptions{})
	creating := apierrors.IsNotFound(err)
	if err != nil && !creating {
		return err
	}
	var ca pki.SigningCA
	var previous *pki.SigningCA
	renew := creating
	if !creating {
		block, _ := pem.Decode(secret.Data[mitmCACertKey])
		if block == nil {
			return fmt.Errorf("managed Sub CA certificate is not PEM encoded")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		// Expired managed CAs can be renewed after downtime using the same key.
		parseAt := now
		if !now.Before(cert.NotAfter) {
			parseAt = cert.NotBefore.Add(pki.ClockSkew)
		}
		ca, err = pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], parseAt)
		if err != nil {
			return err
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign == 0 || !cert.MaxPathLenZero {
			return fmt.Errorf("managed Sub CA has unexpected constraints or key usage")
		}
		if cert.CheckSignatureFrom(parent.Certificate()) == nil {
			previous = &ca
		}
		_, matchErr := s.parseSubCA(secret, parent, now)
		renew = matchErr != nil ||
			(ca.NotAfter().Sub(now) <= subCARenewBefore && ca.NotAfter().Before(parent.ChainNotAfter()))
	}
	if renew {
		ocspURL := ""
		if urls := s.subCAOCSPURLs(); len(urls) != 0 {
			ocspURL = urls[0]
		}
		ca, err = parent.IssueSubCA(previous, ocspURL, subCALifetime, now)
		if err != nil {
			return err
		}
	}
	if err := s.publishSubCAStatus(ctx, parent, ca, previous == nil, now); err != nil {
		return err
	}
	if !renew {
		return nil
	}
	if creating {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: s.options.Namespace, Name: subCASecretName},
			Type:       corev1.SecretTypeOpaque,
		}
	}
	secret.Data = map[string][]byte{mitmCACertKey: ca.BundlePEM(), mitmCAKeyKey: ca.PrivateKeyPEM()}
	if creating {
		_, err = api.Create(ctx, secret, metav1.CreateOptions{})
	} else {
		_, err = api.Update(ctx, secret, metav1.UpdateOptions{})
	}
	return err
}

func ocspKey(request *ocsp.Request) string {
	return fmt.Sprintf(
		"ocsp-%d-%x-%x-%x.der",
		request.HashAlgorithm,
		request.IssuerNameHash,
		request.IssuerKeyHash,
		request.SerialNumber,
	)
}

func (s *MITMSigner) publishSubCAStatus(
	ctx context.Context,
	parent, ca pki.SigningCA,
	bootstrap bool,
	now time.Time,
) error {
	api := s.client.Kube().CoreV1().ConfigMaps(s.options.Namespace)
	cm, err := api.Get(ctx, crlConfigMapName, metav1.GetOptions{})
	creating := apierrors.IsNotFound(err)
	if creating {
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: s.options.Namespace, Name: crlConfigMapName}}
	} else if err != nil {
		return err
	}
	if cm.BinaryData == nil {
		cm.BinaryData = map[string][]byte{}
	}
	changed := false
	if len(cm.BinaryData[ca.CRLKeyID()+".crl"]) == 0 {
		if !bootstrap {
			return fmt.Errorf("managed Sub CA lost its published CRL")
		}
		der, err := ca.SignCRL(&x509.RevocationList{
			Number: big.NewInt(
				1,
			), ThisUpdate: now.Add(-pki.ClockSkew), NextUpdate: minTime(now.Add(crlLifetime), ca.NotAfter()),
		})
		if err != nil {
			return err
		}
		cm.BinaryData[ca.CRLKeyID()+".crl"] = der
		changed = true
	}
	cert, issuer := ca.Certificate(), parent.Certificate()
	var hashes []crypto.Hash
	if len(cert.OCSPServer) != 0 {
		hashes = []crypto.Hash{crypto.SHA1, crypto.SHA256}
	}
	for _, hash := range hashes {
		der, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: hash})
		if err != nil {
			return err
		}
		request, err := ocsp.ParseRequest(der)
		if err != nil {
			return err
		}
		key := ocspKey(request)
		response, err := ocsp.ParseResponse(cm.BinaryData[key], issuer)
		if err == nil && response.Status == ocsp.Revoked {
			return fmt.Errorf("managed Sub CA is revoked")
		}
		if err == nil && response.NextUpdate.Sub(now) > 8*time.Hour {
			continue
		}
		cm.BinaryData[key], err = parent.SignOCSP(cert, hash, now)
		if err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	if creating {
		_, err = api.Create(ctx, cm, metav1.CreateOptions{})
	} else {
		_, err = api.Update(ctx, cm, metav1.UpdateOptions{})
	}
	return err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *MITMSigner) subCAStatusExpiry(ca pki.SigningCA, now time.Time) (time.Time, error) {
	parent := s.parentCA.Get()
	if parent == nil {
		return time.Time{}, fmt.Errorf("parent CA is unavailable")
	}
	der, err := ocsp.CreateRequest(ca.Certificate(), parent.ca.Certificate(), nil)
	if err != nil {
		return time.Time{}, err
	}
	request, err := ocsp.ParseRequest(der)
	if err != nil {
		return time.Time{}, err
	}
	cm, err := s.crls.configMap()
	if err != nil {
		return time.Time{}, err
	}
	response, err := ocsp.ParseResponseForCert(
		cm.BinaryData[ocspKey(request)],
		ca.Certificate(),
		parent.ca.Certificate(),
	)
	if err != nil {
		return time.Time{}, err
	}
	if response.Status != ocsp.Good || now.Before(response.ThisUpdate) || !now.Before(response.NextUpdate) {
		return time.Time{}, fmt.Errorf("Sub CA has no current good OCSP response")
	}
	return response.NextUpdate, nil
}

func (s *MITMSigner) downloadOCSP(w http.ResponseWriter, r *http.Request) {
	var der []byte
	var err error
	if r.Method == http.MethodGet {
		der, err = base64.StdEncoding.DecodeString(r.PathValue("request"))
	} else {
		der, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	}
	if err != nil {
		http.Error(w, "invalid OCSP request", http.StatusBadRequest)
		return
	}
	request, err := ocsp.ParseRequest(der)
	if err != nil {
		http.Error(w, "invalid OCSP request", http.StatusBadRequest)
		return
	}
	cm, err := s.crls.configMap()
	if err != nil {
		http.Error(w, "OCSP publisher unavailable", http.StatusServiceUnavailable)
		return
	}
	body := cm.BinaryData[ocspKey(request)]
	response, err := ocsp.ParseResponse(body, nil)
	now := time.Now()
	if err != nil || now.Before(response.ThisUpdate) || !now.Before(response.NextUpdate) {
		body = ocsp.UnauthorizedErrorResponse
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "public, max-age=60")
	if _, err := w.Write(body); err != nil {
		log.Debug("write MITM OCSP response", "error", err)
	}
}
