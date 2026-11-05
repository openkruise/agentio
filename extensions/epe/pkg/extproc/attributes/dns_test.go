// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

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
