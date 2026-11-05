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
package attributes

import (
	"context"
	"net/netip"

	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func TestParseHTTPRequest(t *testing.T) {
	h1 := map[string]string{":authority": "api.openai.com", ":path": "/v1/chat", ":method": "POST"}
	info1 := parseHTTPRequest(context.Background(), h1)
	if info1.Host != "api.openai.com" {
		t.Errorf("expected host 'api.openai.com', got %q", info1.Host)
	}
	if info1.Path != "/v1/chat" {
		t.Errorf("expected path '/v1/chat', got %q", info1.Path)
	}
	if info1.Method != "POST" {
		t.Errorf("expected method 'POST', got %q", info1.Method)
	}

	h2 := map[string]string{"host": "example.com", ":path": "/api"}
	info2 := parseHTTPRequest(context.Background(), h2)
	if info2.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", info2.Host)
	}
}

// TestSplitHostPort exercises the (host, port) extractor, including IPv6.
func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int32
	}{
		{"", "", 0},
		{"example.com", "example.com", 0},
		{"example.com:8080", "example.com", 8080},
		{"example.com:0", "example.com", 0},
		{"example.com:99999", "example.com", 0},
		{"example.com:abc", "example.com", 0},
		{"127.0.0.1:443", "127.0.0.1", 443},
		{"[::1]:8080", "::1", 8080},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"[::1]", "::1", 0},
		{"[unclosed", "[unclosed", 0},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			gotHost, gotPort := splitHostPort(tc.in)
			if gotHost != tc.wantHost || gotPort != tc.wantPort {
				t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)",
					tc.in, gotHost, gotPort, tc.wantHost, tc.wantPort)
			}
		})
	}
}

// TestSplitPathAndQuery covers the path/query splitter.
func TestSplitPathAndQuery(t *testing.T) {
	tests := []struct {
		in, wantPath, wantQuery string
	}{
		{"", "", ""},
		{"/foo", "/foo", ""},
		{"/foo?x=1", "/foo", "x=1"},
		{"/foo?x=1&y=2", "/foo", "x=1&y=2"},
		{"/foo?", "/foo", ""},
		{"?onlyquery", "", "onlyquery"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			p, q := splitPathAndQuery(tc.in)
			if p != tc.wantPath || q != tc.wantQuery {
				t.Errorf("splitPathAndQuery(%q) = (%q,%q), want (%q,%q)",
					tc.in, p, q, tc.wantPath, tc.wantQuery)
			}
		})
	}
}

// TestParseHTTPRequest_SplitsHostAndPath verifies the front-door parser splits
// ":authority" into Host+Port and ":path" into Path+Query.
func TestParseHTTPRequest_SplitsHostAndPath(t *testing.T) {
	info := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "api.example.com:8443",
		":path":      "/v1/chat?x=1&y=2",
		":method":    "POST",
	})
	if info.Host != "api.example.com" {
		t.Errorf("expected host=api.example.com, got %q", info.Host)
	}
	if info.Port != 8443 {
		t.Errorf("expected port=8443, got %d", info.Port)
	}
	if info.Path != "/v1/chat" {
		t.Errorf("path should NOT include query, got %q", info.Path)
	}
	if info.Query.Get("x") != "1" || info.Query.Get("y") != "2" {
		t.Errorf("expected x=1 y=2, got %v", info.Query)
	}

	// Falls back to "host" header when :authority is absent.
	info2 := parseHTTPRequest(context.Background(), map[string]string{
		"host":    "fallback.example.com:1234",
		":path":   "/p",
		":method": "GET",
	})
	if info2.Host != "fallback.example.com" || info2.Port != 1234 {
		t.Errorf("expected host=fallback.example.com:1234, got %q:%d", info2.Host, info2.Port)
	}
	if info2.Query != nil {
		t.Errorf("expected nil query for path with no '?', got %v", info2.Query)
	}

	// Empty headers map yields zero HTTPRequest (with non-nil Headers map).
	info3 := parseHTTPRequest(context.Background(), map[string]string{})
	if info3.Host != "" || info3.Path != "" || info3.Method != "" || info3.Port != 0 {
		t.Errorf("expected empty info, got %+v", info3)
	}
}

// TestParseHTTPRequest_MalformedQuery verifies that an unparsable query
// string does not panic; the DEBUG log branch is exercised but the returned
// Query may be empty or partial.
func TestParseHTTPRequest_MalformedQuery(t *testing.T) {
	info := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "api.example.com",
		":path":      "/v1/chat?%zz",
		":method":    "GET",
	})
	if info.Path != "/v1/chat" {
		t.Errorf("expected path '/v1/chat', got %q", info.Path)
	}
}

// TestParseHTTPRequest_ExtractsScheme verifies that the :scheme pseudo-header
// is propagated to HTTPRequest.Scheme.
func TestParseHTTPRequest_ExtractsScheme(t *testing.T) {
	info := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "api.example.com",
		":path":      "/v1/chat",
		":method":    "GET",
		":scheme":    "https",
	})
	if info.Scheme != "https" {
		t.Errorf("expected Scheme 'https', got %q", info.Scheme)
	}

	info2 := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "api.example.com",
		":path":      "/v1/chat",
		":method":    "GET",
	})
	if info2.Scheme != "" {
		t.Errorf("expected empty Scheme when :scheme absent, got %q", info2.Scheme)
	}
}

// TestParseHTTPRequest_InfersPortFromScheme verifies that an authority
// without an explicit port falls back to the scheme's default (80/443).
func TestParseHTTPRequest_InfersPortFromScheme(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		scheme    string
		wantPort  int32
	}{
		{"http scheme infers 80", "api.example.com", "http", 80},
		{"HTTPS scheme infers 443 (case-insensitive)", "api.example.com", "HTTPS", 443},
		{"explicit port overrides http inference", "api.example.com:8080", "http", 8080},
		{"explicit port overrides https inference", "api.example.com:9443", "https", 9443},
		{"unknown scheme leaves Port=0", "api.example.com", "ftp", 0},
		{"missing scheme leaves Port=0", "api.example.com", "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := map[string]string{
				":authority": tc.authority,
				":path":      "/",
				":method":    "GET",
			}
			if tc.scheme != "" {
				h[":scheme"] = tc.scheme
			}
			info := parseHTTPRequest(context.Background(), h)
			if info.Port != tc.wantPort {
				t.Errorf("got Port=%d, want %d", info.Port, tc.wantPort)
			}
		})
	}
}

func TestParseHTTPRequest_CONNECTWithoutExplicitPortDoesNotInferProxySchemePort(t *testing.T) {
	info := parseHTTPRequest(context.Background(), map[string]string{
		":authority": "target.example.com",
		":method":    "CONNECT",
		":scheme":    "https",
	})
	if info.Port != 0 {
		t.Fatalf("CONNECT port = %d, want 0 when target authority omits it", info.Port)
	}
}

// TestInferPortFromScheme exercises the helper directly.
func TestInferPortFromScheme(t *testing.T) {
	tests := map[string]int32{
		"http":  80,
		"HTTP":  80,
		"https": 443,
		"Https": 443,
		"ftp":   0,
		"":      0,
	}
	for in, want := range tests {
		if got := inferPortFromScheme(in); got != want {
			t.Errorf("inferPortFromScheme(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestRequestAfterMutationsKeepsOriginalMatchingInput(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ops          []filter.HeaderOp
		host         string
		port         int32
		keepOriginal bool
	}{
		{name: "token only", ops: filter.SetHeader("authorization", "token").HeaderOps, host: "example.com", port: 80, keepOriginal: true},
		{name: "same authority", ops: filter.SetHeader(":authority", "example.com:80").HeaderOps, host: "example.com", port: 80, keepOriginal: true},
		{name: "scheme changes inferred port", ops: filter.SetHeader(":scheme", "https").HeaderOps, host: "example.com", port: 443},
		{name: "IPv6 authority", ops: filter.SetHeader("Host", "[2001:db8::1]:8443").HeaderOps, host: "2001:db8::1", port: 8443},
		{name: "CONNECT needs explicit port", ops: filter.SetHeader(":method", "CONNECT").HeaderOps, host: "example.com", port: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{":authority": "example.com", ":scheme": "http", ":method": "GET"}
			original := parseHTTPRequest(t.Context(), headers)
			original.OriginalDestination = netip.MustParseAddrPort("192.0.2.1:80")
			got := RequestAfterMutations(t.Context(), original, tc.ops)
			if got.Host != tc.host || got.Port != tc.port || got.OriginalDestination.IsValid() != tc.keepOriginal {
				t.Fatalf("effective request=%+v", got)
			}
			if original.Host != "example.com" || original.Port != 80 || headers[":authority"] != "example.com" ||
				headers[":scheme"] != "http" ||
				headers[":method"] != "GET" {
				t.Fatalf("original request changed: %+v", original)
			}
		})
	}
}
