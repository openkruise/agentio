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
	"testing"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func TestTrafficPolicyFallbackHasExplicitPeers(t *testing.T) {
	var object map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := json.NewDecoder(req.Body).Decode(&object); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(object); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := dynamic.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	r := runner{dynamic: client}
	r.Prefix = "test"
	if err := r.trafficPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	rules := object["spec"].(map[string]any)["egress"].(map[string]any)["rules"].([]any)
	fallback := rules[len(rules)-1].(map[string]any)
	peers := fallback["to"].([]any)
	if fallback["action"] != "allow" || len(peers) != 2 ||
		peers[0].(map[string]any)["cidr"] != "0.0.0.0/0" || peers[1].(map[string]any)["cidr"] != "::/0" {
		t.Fatalf("fallback must match both address families: %v", fallback)
	}
}
