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

package extensionprovider

import (
	"crypto/tls"
	"testing"

	corev1 "k8s.io/api/core/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
)

func TestClientCertificateSecretKeys(t *testing.T) {
	standardCert, standardKey := certstest.SelfSigned(t, 8101)
	legacyCert, legacyKey := certstest.SelfSigned(t, 8102)
	cfg := &configv1.ClientTLS{
		ClientCertificateSource: &configv1.ClientTLS_ClientCertificateSecretRef{
			ClientCertificateSecretRef: &configv1.TargetReference{Name: "client"},
		},
	}
	for _, tc := range []struct {
		name   string
		data   map[string][]byte
		serial int64
	}{
		{name: "standard", data: map[string][]byte{"tls.crt": standardCert, "tls.key": standardKey}, serial: 8101},
		{name: "legacy", data: map[string][]byte{"client.crt": legacyCert, "client.key": legacyKey}, serial: 8102},
		{name: "standard takes precedence",
			data: map[string][]byte{
				"tls.crt":    standardCert,
				"tls.key":    standardKey,
				"client.crt": legacyCert,
				"client.key": legacyKey,
			},
			serial: 8101},
		{name: "partial standard pair",
			data: map[string][]byte{
				"tls.crt":    standardCert,
				"client.crt": legacyCert,
				"client.key": legacyKey,
			}},
		{name: "standard key only",
			data: map[string][]byte{
				"tls.key":    standardKey,
				"client.crt": legacyCert,
				"client.key": legacyKey,
			}},
		{name: "empty standard pair",
			data: map[string][]byte{
				"tls.crt":    nil,
				"tls.key":    nil,
				"client.crt": legacyCert,
				"client.key": legacyKey,
			}},
		{name: "invalid standard pair",
			data: map[string][]byte{
				"tls.crt":    []byte("broken"),
				"tls.key":    standardKey,
				"client.crt": legacyCert,
				"client.key": legacyKey,
			}},
		{name: "partial legacy pair", data: map[string][]byte{"client.crt": legacyCert}},
		{name: "missing pair"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := resolveTLSMaterial(cfg, "system", func(key string) *corev1.Secret {
				if key != "system/client" {
					t.Fatalf("unexpected Secret: %s", key)
				}
				return &corev1.Secret{Data: tc.data}
			}, nil, nil)
			transport, err := clientTLS("https://credentials.example", cfg, raw)
			if tc.serial == 0 {
				if err == nil {
					t.Fatal("invalid certificate material was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cert, err := transport.GetClientCertificate(&tls.CertificateRequestInfo{})
			if err != nil {
				t.Fatal(err)
			}
			if cert.Leaf.SerialNumber.Int64() != tc.serial {
				t.Fatalf("certificate serial = %v, want %d", cert.Leaf.SerialNumber, tc.serial)
			}
		})
	}
}
