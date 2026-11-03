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

package gatewayagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCAUsesIndependentProjectedToken(t *testing.T) {
	c := testConfig(t)
	issuer := newTestCA(t)
	c.CAAddress = issuer.serve(t)
	c.RootCertFile = filepath.Join(t.TempDir(), "root.pem")
	c.CARootCertFile = c.RootCertFile
	if err := os.WriteFile(c.RootCertFile, issuer.root, 0o600); err != nil {
		t.Fatal(err)
	}
	adsToken := filepath.Join(t.TempDir(), "ads-token")
	c.TokenFile = adsToken
	if err := os.WriteFile(c.TokenFile, []byte("ads-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	caToken := filepath.Join(t.TempDir(), "ca-token")
	if err := os.WriteFile(caToken, []byte("ca-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTIO_CA_TOKEN_FILE", caToken)
	c.applyCredentialPaths()
	if _, _, err := requestWorkloadCertificate(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if got := <-issuer.tokens; got != "Bearer ca-token" {
		t.Fatalf("CA credential = %q; want independent CA token", got)
	}
	if c.TokenFile != adsToken {
		t.Fatal("CA configuration replaced the ADS credential")
	}
	if err := os.WriteFile(caToken, []byte("rotated-ca-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := requestWorkloadCertificate(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if got := <-issuer.tokens; got != "Bearer rotated-ca-token" {
		t.Fatalf("CA reused an old token: %q", got)
	}
}
