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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A permissive or echoing origin would make the data-path test pass without
// proving private credential injection, or would leak that credential itself.
func TestOAuth2FixtureCredentialBoundary(t *testing.T) {
	f := newOAuth2Fixture()
	for _, token := range []string{"", "unused", f.token} {
		req := httptest.NewRequest(http.MethodGet, "/resource", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.resourceHandler().ServeHTTP(w, req)
		want := http.StatusForbidden
		if token == f.token {
			want = http.StatusOK
		}
		if w.Code != want || strings.Contains(w.Body.String(), f.token) {
			t.Fatalf("origin status=%d body=%s", w.Code, w.Body)
		}
	}
	w := httptest.NewRecorder()
	f.resourceHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/token", nil))
	if w.Code != http.StatusTeapot {
		t.Fatalf("bypassed OAuth endpoint returned %d", w.Code)
	}
	w = httptest.NewRecorder()
	f.controlHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/observations", nil))
	var observed struct {
		OriginCalls   int
		RejectedCalls int
		BypassCalls   int
	}
	if err := json.Unmarshal(w.Body.Bytes(), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.OriginCalls != 3 || observed.RejectedCalls != 2 || observed.BypassCalls != 1 ||
		strings.Contains(w.Body.String(), f.token) {
		t.Fatalf("observations: %s", w.Body)
	}
}
