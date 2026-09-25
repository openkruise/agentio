// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package extensionprovider

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"

	corev1 "k8s.io/api/core/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
)

type material struct {
	cert  *tls.Certificate
	roots *x509.CertPool
}

func (m material) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.cert == nil {
		return nil, fmt.Errorf("no client certificate")
	}
	return m.cert, nil
}
func (m material) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if m.cert == nil {
		return &tls.Certificate{}, nil
	}
	return m.cert, nil
}
func (m material) RootCAs() (*x509.CertPool, error) { return m.roots, nil }

// TLSMaterial is one resolved snapshot, shared by fingerprinting and TLS
// construction. Read errors are data so failures and recoveries trigger updates.
type TLSMaterial struct {
	CA               []byte
	Certificate      []byte
	PrivateKey       []byte
	CAError          string
	CertificateError string
}

func resolveTLSMaterial(
	cfg *configv1.ClientTLS,
	namespace string,
	secret func(string) *corev1.Secret,
	configMap func(string) *corev1.ConfigMap,
	readFile func(string) ([]byte, string),
) TLSMaterial {
	m := TLSMaterial{}
	readSecret := func(ns, name string) (*corev1.Secret, string) {
		key := resourceKey(namespace, ns, name)
		sec := secret(key)
		if sec == nil {
			return nil, fmt.Sprintf("Secret %q unavailable", key)
		}
		return sec, ""
	}
	if ref := cfg.GetCaSecretRef(); ref != nil {
		sec, err := readSecret(ref.Namespace, ref.Name)
		m.CAError = err
		if sec != nil {
			m.CA = sec.Data["ca.crt"]
			if len(m.CA) == 0 {
				m.CAError = fmt.Sprintf("Secret %q requires non-empty ca.crt",
					resourceKey(namespace, ref.Namespace, ref.Name))
			}
		}
	} else if ref := cfg.GetCaConfigMapRef(); ref != nil {
		key := resourceKey(namespace, ref.Namespace, ref.Name)
		cm := configMap(key)
		if cm == nil {
			m.CAError = fmt.Sprintf("ConfigMap %q unavailable", key)
		} else {
			m.CA = []byte(cm.Data["ca.crt"])
			if len(m.CA) == 0 {
				m.CAError = fmt.Sprintf("ConfigMap %q requires non-empty ca.crt", key)
			}
		}
	} else if cfg.GetCaCertificateFile() != "" {
		m.CA, m.CAError = readFile(cfg.GetCaCertificateFile())
	}
	if ref := cfg.GetClientCertificateSecretRef(); ref != nil {
		sec, err := readSecret(ref.Namespace, ref.Name)
		m.CertificateError = err
		if sec != nil {
			m.Certificate = sec.Data[corev1.TLSCertKey]
			m.PrivateKey = sec.Data[corev1.TLSPrivateKeyKey]
			if len(m.Certificate) == 0 || len(m.PrivateKey) == 0 {
				m.CertificateError = fmt.Sprintf("Secret %q requires non-empty tls.crt and tls.key",
					resourceKey(namespace, ref.Namespace, ref.Name))
			}
		}
	} else if files := cfg.GetClientCertificateFiles(); files != nil {
		m.Certificate, m.CertificateError = readFile(files.CertificateFile)
		key, err := readFile(files.PrivateKeyFile)
		m.PrivateKey = key
		if err != "" {
			m.CertificateError = err
		}
	}
	return m
}

func clientTLS(endpoint string, cfg *configv1.ClientTLS, raw TLSMaterial) (*tls.Config, error) {
	m := material{}
	if cfg.GetCaSource() != nil {
		pool := x509.NewCertPool()
		switch {
		case raw.CAError != "":
			if !cfg.GetOptional() {
				return nil, fmt.Errorf("CA material: %s", raw.CAError)
			}
		case !pool.AppendCertsFromPEM(raw.CA):
			if !cfg.GetOptional() {
				return nil, fmt.Errorf("CA material has no valid certificates")
			}
		default:
			m.roots = pool
		}
	}
	if cfg.GetClientCertificateSource() != nil {
		cert, err := tls.X509KeyPair(raw.Certificate, raw.PrivateKey)
		switch {
		case raw.CertificateError != "":
			if !cfg.GetOptional() {
				return nil, fmt.Errorf("client certificate: %s", raw.CertificateError)
			}
		case err != nil:
			if !cfg.GetOptional() {
				return nil, fmt.Errorf("client certificate is invalid: %w", err)
			}
		default:
			m.cert = &cert
		}
	}
	if cfg.GetInsecureSkipVerify() {
		return &tls.Config{
			MinVersion:           tls.VersionTLS12,
			ServerName:           cfg.GetServerName(),
			InsecureSkipVerify:   true, //nolint:gosec // Explicit provider configuration.
			GetClientCertificate: m.GetClientCertificate,
		}, nil
	}
	if len(cfg.GetPeerSpiffeIds()) != 0 {
		list, err := certs.NewSPIFFEAllowList(cfg.PeerSpiffeIds...)
		if err != nil {
			return nil, err
		}
		return certs.ClientTLSConfig(m, certs.WithPeerVerifier(list.VerifyPeer))
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid provider URL: %w", err)
	}
	name := cfg.GetServerName()
	if name == "" {
		name = u.Hostname()
	}
	return certs.ClientTLSConfig(m, certs.WithServerName(name))
}
