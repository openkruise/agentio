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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/security/pki"
)

const (
	crlLifetime      = 24 * time.Hour
	crlConfigMapName = "agentio-mitm-ca-crls"

	oidCRLNumber                = "2.5.29.20"
	oidReasonCode               = "2.5.29.21"
	oidDeltaCRLIndicator        = "2.5.29.27"
	oidIssuingDistributionPoint = "2.5.29.28"
	oidCertificateIssuer        = "2.5.29.29"
	oidAuthorityKeyIdentifier   = "2.5.29.35"
)

type crlPublisher struct {
	origin    string
	namespace string
	maps      krt.Collection[*corev1.ConfigMap]
	client    kube.Client
	managed   bool
	stapling  bool
}

func newCRLPublisher(o MITMSignerOptions, client kube.Client) (*crlPublisher, error) {
	u, err := url.Parse(o.CRLOrigin)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil ||
		(u.EscapedPath() != "" && u.EscapedPath() != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("MITM CRL origin must be an absolute HTTP origin, got %q", o.CRLOrigin)
	}
	if o.ConfigMaps == nil {
		return nil, fmt.Errorf("MITM CRL publisher requires a ConfigMap collection")
	}
	return &crlPublisher{
		origin:    "http://" + u.Host,
		namespace: o.Namespace,
		maps:      o.ConfigMaps,
		client:    client,
		managed:   o.Mode == MITMSignModeSelfSign || o.SubCAEnabled,
		stapling:  o.OCSPStaplingEnabled,
	}, nil
}

func (p *crlPublisher) configMap() (*corev1.ConfigMap, error) {
	cm := p.maps.GetKey(p.namespace + "/" + crlConfigMapName)
	if cm == nil {
		return nil, fmt.Errorf("CRL ConfigMap %s/%s is unavailable", p.namespace, crlConfigMapName)
	}
	return *cm, nil
}

// parseFullCRL accepts one direct, complete list per issuer.
func parseFullCRL(der []byte, id string) (*x509.RevocationList, error) {
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	if len(list.Raw) != len(der) || id == "" || hex.EncodeToString(list.AuthorityKeyId) != id || list.Number == nil ||
		list.Number.Sign() < 0 || !list.NextUpdate.After(list.ThisUpdate) {
		return nil, fmt.Errorf("invalid CRL issuer, number or update times")
	}
	for _, ext := range list.Extensions {
		if id := ext.Id.String(); ext.Critical || id == oidDeltaCRLIndicator || id == oidIssuingDistributionPoint {
			return nil, fmt.Errorf("unsupported CRL extension %s", ext.Id)
		}
	}
	for _, entry := range list.RevokedCertificateEntries {
		for _, ext := range entry.Extensions {
			if ext.Critical || ext.Id.String() == oidCertificateIssuer {
				return nil, fmt.Errorf("unsupported CRL entry extension %s", ext.Id)
			}
		}
	}
	return list, nil
}

func freshCRL(list *x509.RevocationList, now time.Time) bool {
	return !now.Before(list.ThisUpdate) && now.Before(list.NextUpdate)
}

func publishedCRL(cm *corev1.ConfigMap, id string) (*x509.RevocationList, error) {
	der := cm.BinaryData[id+".crl"]
	if len(der) == 0 {
		return nil, fmt.Errorf("issuer %s has no signed CRL in binaryData", id)
	}
	return parseFullCRL(der, id)
}

func (p *crlPublisher) issuanceHorizon(ca pki.SigningCA, now time.Time) (time.Time, error) {
	cm, err := p.configMap()
	if err != nil {
		return time.Time{}, err
	}
	id := ca.CRLKeyID()
	list, err := publishedCRL(cm, id)
	if err != nil {
		return time.Time{}, err
	}
	if !freshCRL(list, now) {
		return time.Time{}, fmt.Errorf("issuer %s has no current CRL", id)
	}
	if err := ca.VerifyCRL(list); err != nil {
		return time.Time{}, err
	}
	if !p.managed && !p.stapling {
		// The external authority continues publishing through the lifetime of its leaves.
		return ca.NotAfter(), nil
	}
	return list.NextUpdate, nil
}

// CRLHandler serves signed revocation status, or returns nil when publication is disabled.
func (s *MITMSigner) CRLHandler() http.Handler {
	if s.crls == nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /crl/{file}", s.downloadCRL)
	if s.options.SubCAEnabled {
		mux.HandleFunc("GET /ocsp/{request...}", s.downloadOCSP)
		mux.HandleFunc("POST /ocsp", s.downloadOCSP)
	}
	return mux
}

func (s *MITMSigner) downloadCRL(w http.ResponseWriter, r *http.Request) {
	cm, err := s.crls.configMap()
	if err != nil {
		http.Error(w, "CRL publisher unavailable", http.StatusServiceUnavailable)
		return
	}
	file := r.PathValue("file")
	id, ok := strings.CutSuffix(file, ".crl")
	if !ok || len(cm.BinaryData[file]) == 0 {
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	list, err := publishedCRL(cm, id)
	active := s.caSingleton.Get()
	if err == nil && active != nil && active.ca.CRLKeyID() == id {
		err = active.ca.VerifyCRL(list)
	}
	if err != nil || !freshCRL(list, now) {
		http.Error(w, "CRL unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", min(60, int(list.NextUpdate.Sub(now).Seconds()))))
	http.ServeContent(w, r, file, time.Time{}, bytes.NewReader(list.Raw))
}

func (p *crlPublisher) run(ctx context.Context, ca krt.Singleton[caState]) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var lastError string
	for {
		now := time.Now().UTC().Truncate(time.Second)
		active := ca.Get()
		if active != nil {
			err := p.reconcile(ctx, active.ca, now)
			if err == nil {
				lastError = ""
			} else if !apierrors.IsConflict(err) && err.Error() != lastError && ctx.Err() == nil {
				log.Error("publish MITM CRL", "error", err)
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

func (p *crlPublisher) reconcile(ctx context.Context, ca pki.SigningCA, now time.Time) error {
	cm, err := p.configMap()
	if err != nil {
		return err
	}
	id := ca.CRLKeyID()
	if id == "" {
		return fmt.Errorf("MITM CA needs a subject key identifier for CRL publication")
	}
	old, err := publishedCRL(cm, id)
	if err != nil {
		return err
	}
	if err := ca.VerifyCRL(old); err != nil {
		return err
	}
	if now.Before(old.ThisUpdate) {
		return fmt.Errorf("published CRL has a future thisUpdate")
	}
	if !now.Before(ca.NotAfter()) {
		return fmt.Errorf("MITM CRL issuer expired")
	}
	if old.NextUpdate.Sub(now) > crlLifetime/3 || old.NextUpdate.Equal(ca.NotAfter()) {
		return nil
	}
	next := now.Add(crlLifetime)
	if ca.NotAfter().Before(next) {
		next = ca.NotAfter()
	}
	thisUpdate := now.Add(-pki.ClockSkew)
	if old.ThisUpdate.After(thisUpdate) {
		thisUpdate = old.ThisUpdate
	}
	entries := make([]x509.RevocationListEntry, 0, len(old.RevokedCertificateEntries))
	for _, entry := range old.RevokedCertificateEntries {
		for _, ext := range entry.Extensions {
			// Go encodes this extension from the parsed ReasonCode field.
			if ext.Id.String() != oidReasonCode {
				entry.ExtraExtensions = append(entry.ExtraExtensions, ext)
			}
		}
		entries = append(entries, entry)
	}
	var extensions []pkix.Extension
	for _, ext := range old.Extensions {
		// Go writes authorityKeyIdentifier and CRLNumber when signing.
		if id := ext.Id.String(); id != oidAuthorityKeyIdentifier && id != oidCRLNumber {
			extensions = append(extensions, ext)
		}
	}
	template := &x509.RevocationList{
		Number:                    new(big.Int).Add(old.Number, big.NewInt(1)),
		ThisUpdate:                thisUpdate,
		NextUpdate:                next,
		RevokedCertificateEntries: entries,
		ExtraExtensions:           extensions,
	}
	der, err := ca.SignCRL(template)
	if err != nil {
		return err
	}
	updated := cm.DeepCopy()
	updated.BinaryData[id+".crl"] = der
	// Only the committed object from the watch cache is visible to HTTP and SignDNS.
	_, err = p.client.Kube().CoreV1().ConfigMaps(p.namespace).Update(ctx, updated, metav1.UpdateOptions{})
	return err
}
