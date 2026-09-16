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
package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	caserver "istio.io/istio/security/pkg/server/ca"
)

func TestRunCAWithJWTPath(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}); err != nil {
			t.Error(err)
		}
	}))
	defer provider.Close()
	payload, err := json.Marshal(map[string]any{"iss": provider.URL, "aud": []string{"istio-ca"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agentio-token")
	if err := os.WriteFile(path, []byte("e30."+base64.RawURLEncoding.EncodeToString(payload)+".signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOKEN_ISSUER", "")
	t.Setenv("AUDIENCE", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for _, tc := range []struct {
		name, path string
		want       int
	}{
		{"projected token", path, 1},
		{"missing token", filepath.Join(t.TempDir(), "missing"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JWT_PATH", tc.path)
			server := &Server{caServer: &caserver.Server{}}
			grpcServer := grpc.NewServer()
			defer grpcServer.Stop()
			server.RunCA(grpcServer)
			if got := len(server.caServer.Authenticators); got != tc.want {
				t.Fatalf("authenticators = %d, want %d", got, tc.want)
			}
		})
	}
}
