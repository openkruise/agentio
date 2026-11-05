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
package filter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSandboxTokenJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want SandboxToken
	}{
		{
			name: "all fields",
			in:   `{"requestId":"r1","accessToken":"a1","sandboxClientId":"c1"}`,
			want: SandboxToken{RequestID: "r1", AccessToken: "a1", SandboxClientID: "c1"},
		},
		{
			name: "empty object",
			in:   `{}`,
			want: SandboxToken{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got SandboxToken
			if err := json.Unmarshal([]byte(tc.in), &got); err != nil {
				t.Fatalf("json.Unmarshal(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("SandboxToken: want %+v, got %+v", tc.want, got)
			}
		})
	}
}

func TestParseSandboxToken(t *testing.T) {
	tokenJSON := `{"requestId":"r1","accessToken":"tok","sandboxClientId":"c1"}`
	parsed := &SandboxToken{RequestID: "r1", AccessToken: "tok", SandboxClientID: "c1"}

	tests := []struct {
		name string
		raw  string
		want *SandboxToken
	}{
		{
			name: "valid base64 token parsed",
			raw:  base64.StdEncoding.EncodeToString([]byte(tokenJSON)),
			want: parsed,
		},
		{
			name: "raw JSON fallback when not base64",
			raw:  tokenJSON,
			want: parsed,
		},
		{
			name: "garbage neither base64 nor JSON returns nil",
			raw:  "!!!not-base64-and-not-json!!!",
			want: nil,
		},
		{
			name: "base64 of non-JSON returns nil",
			raw:  base64.StdEncoding.EncodeToString([]byte("not json at all")),
			want: nil,
		},
		{
			name: "empty raw value returns nil",
			raw:  "",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := NewSandboxToken(tc.raw)
			got := token.Parse(context.Background())
			if token != nil && token.raw != "" {
				t.Fatal("raw token retained after parse")
			}
			if again := token.Parse(context.Background()); again != got {
				t.Fatal("second access did not reuse parse result")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Parse() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSandboxTokenSharedAcrossStreamViews(t *testing.T) {
	original := Stream{
		RequestContext: RequestContext{
			Caller: CallerContext{Token: NewSandboxToken(`{"accessToken":"opaque","sandboxClientId":"c1"}`)},
		},
	}
	view := original
	parsed := view.Caller.Token.Parse(t.Context())
	if parsed == nil || parsed.AccessToken != "opaque" {
		t.Fatal("token was not parsed")
	}
	if original.Caller.Token.raw != "" {
		t.Fatal("view did not share lazy parse state")
	}
	if got := original.Caller.Token.Parse(t.Context()); got != parsed {
		t.Fatal("request views did not reuse token")
	}
}

func TestParseSandboxMetadataToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want *SandboxToken
	}{
		{
			name: "ztunnel Structured Fields encoding",
			raw:  `agent-identity.access-token="a,b;c% d=+/\"\\", agent-identity.sandbox-client-id="client+/=", runtime.name="test,runtime"`,
			want: &SandboxToken{AccessToken: "a,b;c% d=+/\"\\", SandboxClientID: "client+/="},
		},
		{
			name: "percent sequences remain literal and unknown values and parameters are ignored",
			raw:  `agent-identity.access-token="a%2Cb%ZZ";version=@0, runtime.count=42, agent-identity.sandbox-client-id="client"`,
			want: &SandboxToken{AccessToken: "a%2Cb%ZZ", SandboxClientID: "client"},
		},
		{
			name: "duplicate Dictionary keys use the last value",
			raw:  `agent-identity.access-token="first", agent-identity.access-token="last", agent-identity.sandbox-client-id="client"`,
			want: &SandboxToken{AccessToken: "last", SandboxClientID: "client"},
		},
		{name: "empty"},
		{name: "missing identity", raw: `runtime.name="test"`},
		{name: "missing client", raw: `agent-identity.access-token="token"`},
		{name: "missing token", raw: `agent-identity.sandbox-client-id="client"`},
		{name: "empty token", raw: `agent-identity.access-token="", agent-identity.sandbox-client-id="client"`},
		{name: "wrong type", raw: `agent-identity.access-token=token, agent-identity.sandbox-client-id="client"`},
		{name: "inner list", raw: `agent-identity.access-token=("token"), agent-identity.sandbox-client-id="client"`},
		{name: "malformed entry", raw: `token, agent-identity.sandbox-client-id="client"`},
		{name: "invalid escape", raw: `agent-identity.access-token="token\n", agent-identity.sandbox-client-id="client"`},
		{name: "legacy KV is not accepted", raw: "agent-identity.access-token=token,agent-identity.sandbox-client-id=client"},
		{name: "JSON is not accepted", raw: `{"agent-identity.access-token":"token","agent-identity.sandbox-client-id":"client"}`},
		{name: "non ASCII", raw: `agent-identity.access-token="中", agent-identity.sandbox-client-id="client"`},
		{name: "oversized", raw: strings.Repeat("x", 8193)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := NewSandboxMetadataToken(tc.raw)
			got := token.Parse(t.Context())
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Parse() = %+v, want %+v", got, tc.want)
			}
			if again := token.Parse(t.Context()); again != got {
				t.Fatal("second access did not reuse parse result")
			}
			if token != nil && token.raw != "" {
				t.Fatal("raw metadata retained after parse")
			}
		})
	}
}

func TestSandboxTokenPredecoded(t *testing.T) {
	token := &SandboxToken{AccessToken: "opaque", SandboxClientID: "c1"}
	if token.Parse(t.Context()) != token {
		t.Fatal("pre-decoded token was not preserved")
	}
}
