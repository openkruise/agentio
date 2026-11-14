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

package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpstreamPreservesIdentityHostAndSNI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://host-000001.load.test:8443/allow", nil)
	req.TLS = &tls.ConnectionState{ServerName: "host-000001.load.test"}
	req.Header.Set("X-Stability-Client", "7")
	w := httptest.NewRecorder()
	handler().ServeHTTP(w, req)
	var response struct {
		Host    string      `json:"host"`
		SNI     string      `json:"tls_sni"`
		Headers http.Header `json:"headers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || response.Host != req.Host || response.SNI != req.TLS.ServerName ||
		response.Headers.Get("X-Stability-Client") != "7" {
		t.Fatalf("identity mismatch: %+v", response)
	}
}

func TestUpstreamChecksTransferSizes(t *testing.T) {
	for _, n := range []int{1024, 8 << 20, 8<<20 + 1} {
		w := httptest.NewRecorder()
		handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", n))))
		want := 200
		if n > 8<<20 {
			want = 400
		}
		if w.Code != want {
			t.Fatalf("upload %d: %d", n, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/download", nil))
	b, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1<<20 || w.Header().Get("Content-Length") != "1048576" {
		t.Fatal("incorrect download length", len(b))
	}
}
