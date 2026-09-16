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
package options

import (
	"os"
	"path/filepath"
	"testing"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/jwt"
	"istio.io/istio/pkg/security"
)

func TestJWTPath(t *testing.T) {
	for _, policy := range []string{jwt.PolicyThirdParty, jwt.PolicyFirstParty} {
		for _, mode := range []string{"default", "override", "missing override", "disabled"} {
			t.Run(policy+"/"+mode, func(t *testing.T) {
				t.Chdir(t.TempDir())
				legacy := constants.ThirdPartyJwtPath
				if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(legacy, []byte("legacy-token"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("JWT_PATH", "")
				path, want := legacy, "legacy-token"
				switch mode {
				case "default":
					if err := os.Unsetenv("JWT_PATH"); err != nil {
						t.Fatal(err)
					}
				case "override":
					path = filepath.Join(t.TempDir(), "agentio-token")
					want = "agentio-token-value"
					if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
						t.Fatal(err)
					}
					t.Setenv("JWT_PATH", path)
				case "missing override":
					want = ""
					t.Setenv("JWT_PATH", filepath.Join(t.TempDir(), "missing"))
				}
				opts, err := SetupSecurityOptions(&meshconfig.ProxyConfig{}, &security.Options{}, policy, security.JWT, "")
				if err != nil {
					t.Fatal(err)
				}
				if mode == "disabled" {
					if opts.CredFetcher != nil {
						t.Fatal("empty JWT_PATH should disable token fetching")
					}
					return
				}
				if opts.CredFetcher == nil {
					t.Fatal("missing credential fetcher")
				}
				defer opts.CredFetcher.Stop()
				got, err := opts.CredFetcher.GetPlatformCredential()
				if err != nil || got != want {
					t.Fatalf("credential = %q, error = %v; want %q", got, err, want)
				}
				if mode == "override" {
					if err := os.WriteFile(path, []byte("rotated-token"), 0o600); err != nil {
						t.Fatal(err)
					}
					got, err := opts.CredFetcher.GetPlatformCredential()
					if err != nil || got != "rotated-token" {
						t.Fatalf("rotated credential = %q, error = %v", got, err)
					}
				}
			})
		}
	}
}
