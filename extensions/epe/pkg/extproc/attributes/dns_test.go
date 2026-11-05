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

// Package httpreq holds the neutral request tuple shared by the filter
// framework and the policy model. It is a leaf: importing it pulls in no
// policy API, no protos, nothing but the standard library — which is what
// lets the engine's dependency closure stay free of agents-api.
package attributes

import (
	"reflect"
	"strings"
	"testing"
)

func TestExtractDNSCandidates(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{"list", `"api.example.com", "cdn.example.com";seen=?1`, []string{"api.example.com", "cdn.example.com"}},
		{"empty", "", nil}, {"token", `api.example.com`, nil}, {"mixed", `"api.example.com", 3`, nil},
		{"inner", `("api.example.com")`, nil}, {"empty item", `""`, nil}, {"json", `["api.example.com"]`, nil},
		{"oversize", `"` + strings.Repeat("a", 8192) + `"`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := makeAttrs(t, map[string]any{FilterStateDestinationDNSCandidates: tc.raw})
			headers := makeHTTPHeaders(map[string]string{":method": "GET", ":authority": "original.example", "x-agentio-destination-dns-candidates": `"spoof.example"`})
			_, req := Extract(t.Context(), headers, attrs)
			if !reflect.DeepEqual(req.DNSCandidates, tc.want) || req.Host != "original.example" {
				t.Fatalf("request=%+v, want=%v", req, tc.want)
			}
		})
	}
	_, req := Extract(t.Context(), makeHTTPHeaders(map[string]string{"x-agentio-destination-dns-candidates": `"spoof.example"`}), nil)
	if len(req.DNSCandidates) != 0 {
		t.Fatal("application header became DNS evidence")
	}
}
