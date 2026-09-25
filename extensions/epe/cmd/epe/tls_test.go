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
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certsource"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
)

// writeSelfSignedPEM writes a throwaway self-signed cert/key (and the cert
// again as a CA bundle) into dir and returns the three paths. FromFiles reads
// the files eagerly, so they must exist before buildExtProcTLS runs.
func writeSelfSignedPEM(t *testing.T, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	certPEM, keyPEM := certstest.SelfSigned(t, 1)

	certPath = filepath.Join(dir, "cert-chain.pem")
	keyPath = filepath.Join(dir, "key.pem")
	caPath = filepath.Join(dir, "root-cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing CA bundle: %v", err)
	}
	return certPath, keyPath, caPath
}

func TestBuildExtProcTLS(t *testing.T) {
	certPath, keyPath, caPath := writeSelfSignedPEM(t, t.TempDir())

	garbageCA := filepath.Join(t.TempDir(), "garbage-ca.pem")
	if err := os.WriteFile(garbageCA, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("writing garbage CA bundle: %v", err)
	}

	tests := []struct {
		name             string
		source           string
		certPath         string
		keyPath          string
		caPath           string
		expectError      string
		expectSecure     bool
		expectClientCert bool
	}{
		{
			name:   "all empty means plaintext",
			source: "none",
		},
		{
			name:             "ca source enables required mTLS",
			source:           "ca",
			expectSecure:     true,
			expectClientCert: true,
		},
		{
			name:        "cert without key is rejected",
			certPath:    certPath,
			expectError: "must be set together",
		},
		{
			name:        "key without cert is rejected",
			keyPath:     keyPath,
			expectError: "must be set together",
		},
		{
			name:        "ca without cert and key is rejected",
			caPath:      caPath,
			expectError: "must be set together",
		},
		{
			name:        "missing certificate file is rejected",
			certPath:    filepath.Join(t.TempDir(), "missing.pem"),
			keyPath:     keyPath,
			expectError: "no such file",
		},
		{
			// An unreadable bundle now resolves to "use the system trust store"
			// rather than an error, so the startup probe asserts the resulting
			// pool instead of the error. The rejection itself is unchanged.
			name:        "missing CA bundle file is rejected at startup",
			certPath:    certPath,
			keyPath:     keyPath,
			caPath:      filepath.Join(t.TempDir(), "missing-ca.pem"),
			expectError: "no usable CA certificates",
		},
		{
			name:        "unparseable CA bundle is rejected at startup",
			certPath:    certPath,
			keyPath:     keyPath,
			caPath:      garbageCA,
			expectError: "no usable CA certificates",
		},
		{
			name:         "cert and key enable server TLS",
			certPath:     certPath,
			keyPath:      keyPath,
			expectSecure: true,
		},
		{
			name:             "ca additionally enables required mTLS",
			expectClientCert: true,
			certPath:         certPath,
			keyPath:          keyPath,
			caPath:           caPath,
			expectSecure:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := tt.source
			if source == "" {
				source = "file"
			}
			result, err := buildExtProcTLS(
				extProcTLSOptions{
					Source:   source,
					CertPath: tt.certPath,
					KeyPath:  tt.keyPath,
					CAPath:   tt.caPath,
					Workload: certsource.WorkloadOptions{
						Address:   "agentiod.agentio-system.svc:15012",
						TokenPath: filepath.Join(t.TempDir(), "token"),
						RootPath:  caPath,
						SPIFFEID:  "spiffe://cluster.local/ns/agentio-system/sa/agentio-epe",
					},
				},
				t.Context().Done(),
			)
			if tt.expectError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.expectError)
				}
				if !strings.Contains(err.Error(), tt.expectError) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.expectError)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildExtProcTLS: %v", err)
			}
			if result.Secure != tt.expectSecure {
				t.Errorf("Secure = %v, want %v", result.Secure, tt.expectSecure)
			}
			if !tt.expectSecure {
				if result.Provider != nil {
					t.Errorf("plaintext result must have a nil Provider, got %v", result.Provider)
				}
				return
			}
			if result.Provider == nil {
				t.Fatal("secure result must have a non-nil Provider")
			}
			if result.RequireClientCert != tt.expectClientCert {
				t.Errorf("RequireClientCert = %v, want %v", result.RequireClientCert, tt.expectClientCert)
			}
			if (result.Workload != nil) != (source == "ca") {
				t.Errorf("certificate renewal runnable present = %v for source %q", result.Workload != nil, source)
			}

		})
	}
}
