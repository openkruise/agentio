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
package httpcallout

import (
	"reflect"
	"strings"
	"testing"
)

func TestConfigEffectiveAppliesDefaultsAndNormalizesAllowlist(t *testing.T) {
	original := Config{
		Provider: "scanner",
		Request: &PhaseConfig{
			Headers: HeadersConfig{
				Mode:      HeaderModeAllowlist,
				Allowlist: []string{"X-Tenant", "x-tenant", "X-Trace-ID"},
			},
			Body: true,
		},
		Response: &PhaseConfig{
			Headers: HeadersConfig{
				Mode:      HeaderModeAllowlist,
				Allowlist: []string{"X-Upstream", "x-upstream", "X-Trace-ID"},
			},
		},
	}

	got, err := original.Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if got.MaxBodyBytes != 1<<20 {
		t.Errorf("MaxBodyBytes = %d, want %d", got.MaxBodyBytes, 1<<20)
	}
	wantRequest := PhaseConfig{
		Headers: HeadersConfig{
			Mode:      HeaderModeAllowlist,
			Allowlist: []string{"x-tenant", "x-trace-id"},
		},
		Body: true,
	}
	if !reflect.DeepEqual(*got.Request, wantRequest) {
		t.Errorf("Request = %#v, want %#v", *got.Request, wantRequest)
	}
	wantResponse := PhaseConfig{
		Headers: HeadersConfig{
			Mode:      HeaderModeAllowlist,
			Allowlist: []string{"x-upstream", "x-trace-id"},
		},
	}
	if !reflect.DeepEqual(*got.Response, wantResponse) {
		t.Errorf("Response = %#v, want %#v", *got.Response, wantResponse)
	}
}

// TestConfigEffectiveReturnsADeepCopy is the aliasing bite. With pointer phase
// fields a shallow struct copy would hand the filter the caller's PhaseConfig,
// so a later edit to the config the operator built would reach into a running
// filter and break the "owned copy safe to retain" promise.
func TestConfigEffectiveReturnsADeepCopy(t *testing.T) {
	in := Config{
		Provider: "scanner",
		Request: &PhaseConfig{
			Headers: HeadersConfig{Mode: HeaderModeAllowlist, Allowlist: []string{"X-Tenant"}},
			Body:    true,
		},
		Response: &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeDenylist, Denylist: []string{"Authorization"}}},
	}

	got, err := in.Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if got.Request == in.Request {
		t.Error("Effective returned the caller's request PhaseConfig pointer")
	}
	if got.Response == in.Response {
		t.Error("Effective returned the caller's response PhaseConfig pointer")
	}

	// Mutate everything reachable through the input after the call. Nothing the
	// filter now holds may move.
	in.Request.Body = false
	in.Request.Headers.Mode = HeaderModeNone
	in.Request.Headers.Allowlist[0] = "x-hijacked"
	in.Response.Headers.Mode = HeaderModeNone
	in.Response.Headers.Denylist[0] = "x-hijacked"

	if !got.Request.Body {
		t.Error("mutating the caller's Request.Body changed the effective copy")
	}
	if got.Request.Headers.Mode != HeaderModeAllowlist {
		t.Errorf("request header mode = %q, want it unaffected by the caller's edit", got.Request.Headers.Mode)
	}
	wantAllowlist := []string{"x-tenant"}
	if !reflect.DeepEqual(got.Request.Headers.Allowlist, wantAllowlist) {
		t.Errorf("request allowlist = %v, want %v: the slice is shared with the caller", got.Request.Headers.Allowlist, wantAllowlist)
	}
	if got.Response.Headers.Mode != HeaderModeDenylist {
		t.Errorf("response header mode = %q, want it unaffected by the caller's edit", got.Response.Headers.Mode)
	}
	wantDenylist := []string{"authorization"}
	if !reflect.DeepEqual(got.Response.Headers.Denylist, wantDenylist) {
		t.Errorf("response denylist = %v, want %v: the slice is shared with the caller", got.Response.Headers.Denylist, wantDenylist)
	}
}

// TestConfigEffectiveDefaultsBothDirectionsToNone pins that disclosure is opt-in
// in both directions: response headers carry upstream-minted credentials such as
// set-cookie, so they are no more forwardable by default than request headers.
func TestConfigEffectiveDefaultsBothDirectionsToNone(t *testing.T) {
	got, err := (Config{
		Provider: "scanner",
		Request:  &PhaseConfig{},
		Response: &PhaseConfig{},
	}).Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if got.Request.Headers.Mode != HeaderModeNone {
		t.Errorf("request header mode = %q, want %q", got.Request.Headers.Mode, HeaderModeNone)
	}
	if len(got.Request.Headers.Allowlist) != 0 {
		t.Errorf("request header allowlist = %v, want empty", got.Request.Headers.Allowlist)
	}
	if len(got.Request.Headers.Denylist) != 0 {
		t.Errorf("request header denylist = %v, want empty", got.Request.Headers.Denylist)
	}
	if got.Request.Body {
		t.Error("an empty PhaseConfig collected a body, want body collection opt-in")
	}
	if got.Response.Headers.Mode != HeaderModeNone {
		t.Errorf("response header mode = %q, want %q", got.Response.Headers.Mode, HeaderModeNone)
	}
	if len(got.Response.Headers.Allowlist) != 0 {
		t.Errorf("response header allowlist = %v, want empty", got.Response.Headers.Allowlist)
	}
	if len(got.Response.Headers.Denylist) != 0 {
		t.Errorf("response header denylist = %v, want empty", got.Response.Headers.Denylist)
	}
	if got.Response.Body {
		t.Error("an empty PhaseConfig collected a body, want body collection opt-in")
	}
}

// TestConfigEffectiveAcceptsEitherPhaseAlone pins that presence is enablement:
// the disabled direction stays nil rather than becoming a defaulted phase.
func TestConfigEffectiveAcceptsEitherPhaseAlone(t *testing.T) {
	t.Run("request only", func(t *testing.T) {
		got, err := (Config{
			Provider: "scanner",
			Request:  &PhaseConfig{},
		}).Effective()
		if err != nil {
			t.Fatalf("Effective: %v", err)
		}
		if got.Request == nil {
			t.Fatal("the enabled request phase was dropped")
		}
		if got.Response != nil {
			t.Errorf("Response = %#v, want nil for a disabled phase", got.Response)
		}
	})

	t.Run("response only", func(t *testing.T) {
		got, err := (Config{
			Provider: "scanner",
			Response: &PhaseConfig{},
		}).Effective()
		if err != nil {
			t.Fatalf("Effective: %v", err)
		}
		if got.Response == nil {
			t.Fatal("the enabled response phase was dropped")
		}
		if got.Request != nil {
			t.Errorf("Request = %#v, want nil for a disabled phase", got.Request)
		}
	})
}

func TestConfigEffectivePreservesExplicitOverrides(t *testing.T) {
	got, err := (Config{
		Provider:     "scanner",
		Response:     &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeAll}, Body: true},
		MaxBodyBytes: 8 << 20,
		FailOpen:     true,
	}).Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if got.MaxBodyBytes != 8<<20 || !got.FailOpen {
		t.Errorf("explicit settings were not preserved: %+v", got)
	}
	if !got.Response.Body {
		t.Error("Response.Body was not preserved")
	}
}

func TestConfigEffectiveRejectsInvalidConfiguration(t *testing.T) {
	valid := Config{Provider: "scanner", Request: &PhaseConfig{}}
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:    "no phase",
			mutate:  func(c *Config) { c.Request = nil },
			wantErr: "phase",
		},
		{
			name:    "empty provider",
			mutate:  func(c *Config) { c.Provider = "" },
			wantErr: "provider",
		},
		{
			name:    "negative body limit",
			mutate:  func(c *Config) { c.MaxBodyBytes = -1 },
			wantErr: "body",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			if _, err := cfg.Effective(); err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Fatalf("Effective error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestConfigEffectiveRejectsInvalidHeaderConfigInBothDirections runs one table
// against both directions: the modes are identical in semantics, so a rule that
// holds for the request side and not the response side would be a bug rather
// than a design.
func TestConfigEffectiveRejectsInvalidHeaderConfigInBothDirections(t *testing.T) {
	directions := []struct {
		name  string
		field func(*Config) *HeadersConfig
	}{
		{
			name:  "request",
			field: func(c *Config) *HeadersConfig { return &c.Request.Headers },
		},
		{
			name:  "response",
			field: func(c *Config) *HeadersConfig { return &c.Response.Headers },
		},
	}
	tests := []struct {
		name    string
		mutate  func(*HeadersConfig)
		wantErr string
	}{
		{
			name:    "unknown mode",
			mutate:  func(h *HeadersConfig) { h.Mode = HeaderMode("unknown") },
			wantErr: "header mode",
		},
		{
			name:    "empty allowlist",
			mutate:  func(h *HeadersConfig) { h.Mode = HeaderModeAllowlist },
			wantErr: "allowlist",
		},
		{
			name:    "empty denylist",
			mutate:  func(h *HeadersConfig) { h.Mode = HeaderModeDenylist },
			wantErr: "denylist",
		},
		{
			name: "invalid allowlist name",
			mutate: func(h *HeadersConfig) {
				h.Mode = HeaderModeAllowlist
				h.Allowlist = []string{"bad header"}
			},
			wantErr: "header name",
		},
		{
			name: "invalid denylist name",
			mutate: func(h *HeadersConfig) {
				h.Mode = HeaderModeDenylist
				h.Denylist = []string{"bad header"}
			},
			wantErr: "header name",
		},
		{
			name: "allowlist entries in none mode",
			mutate: func(h *HeadersConfig) {
				h.Mode = HeaderModeNone
				h.Allowlist = []string{"x-tenant"}
			},
			wantErr: "allowlist",
		},
		{
			name: "allowlist entries in all mode",
			mutate: func(h *HeadersConfig) {
				h.Mode = HeaderModeAll
				h.Allowlist = []string{"x-tenant"}
			},
			wantErr: "allowlist",
		},
		{
			name: "denylist entries in none mode",
			mutate: func(h *HeadersConfig) {
				h.Mode = HeaderModeNone
				h.Denylist = []string{"x-tenant"}
			},
			wantErr: "denylist",
		},
		{
			name: "denylist entries in all mode",
			mutate: func(h *HeadersConfig) {
				h.Mode = HeaderModeAll
				h.Denylist = []string{"x-tenant"}
			},
			wantErr: "denylist",
		},
		{
			// The two fields exist so that a one-word mode edit cannot silently
			// invert "only these" into "all but these". These two cases are that
			// guarantee: a list under the mode that does not own it is an error.
			name: "allowlist under denylist mode",
			mutate: func(h *HeadersConfig) {
				h.Mode = HeaderModeDenylist
				h.Denylist = []string{"authorization"}
				h.Allowlist = []string{"x-tenant"}
			},
			wantErr: "allowlist",
		},
		{
			name: "denylist under allowlist mode",
			mutate: func(h *HeadersConfig) {
				h.Mode = HeaderModeAllowlist
				h.Allowlist = []string{"x-tenant"}
				h.Denylist = []string{"authorization"}
			},
			wantErr: "denylist",
		},
	}

	for _, direction := range directions {
		t.Run(direction.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					cfg := Config{
						Provider: "scanner",
						Request:  &PhaseConfig{},
						Response: &PhaseConfig{},
					}
					tc.mutate(direction.field(&cfg))
					_, err := cfg.Effective()
					if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
						t.Fatalf("Effective error = %v, want one containing %q", err, tc.wantErr)
					}
					// The message must name the direction, or an operator with
					// both fields set cannot tell which one is wrong.
					if !strings.Contains(strings.ToLower(err.Error()), direction.name) {
						t.Errorf("error = %q, want it to name the %s direction", err.Error(), direction.name)
					}
				})
			}
		})
	}
}

// TestConfigEffectiveAcceptsCredentialsInEitherList pins the reversal. A name
// written in a reviewed CRD is a decision, not an accident: a callout that
// inspects or transforms credentials needs to see them, and rejecting the name
// made a legitimate setup inexpressible.
func TestConfigEffectiveAcceptsCredentialsInEitherList(t *testing.T) {
	credentials := []string{
		"authorization", "proxy-authorization", "cookie",
		"set-cookie", "www-authenticate", "proxy-authenticate",
	}

	for _, mode := range []HeaderMode{HeaderModeAllowlist, HeaderModeDenylist} {
		t.Run(string(mode), func(t *testing.T) {
			headers := HeadersConfig{Mode: mode}
			if mode == HeaderModeAllowlist {
				headers.Allowlist = credentials
			} else {
				headers.Denylist = credentials
			}
			got, err := (Config{
				Provider: "scanner",
				Request:  &PhaseConfig{Headers: headers},
				Response: &PhaseConfig{Headers: headers},
			}).Effective()
			if err != nil {
				t.Fatalf("Effective rejected %v under %q: %v", credentials, mode, err)
			}
			for _, direction := range []struct {
				name  string
				phase *PhaseConfig
			}{{"request", got.Request}, {"response", got.Response}} {
				list := direction.phase.Headers.Allowlist
				if mode == HeaderModeDenylist {
					list = direction.phase.Headers.Denylist
				}
				if !reflect.DeepEqual(list, credentials) {
					t.Errorf("%s %s = %v, want %v", direction.name, mode, list, credentials)
				}
			}
		})
	}
}

// TestConfigEffectiveNormalizesTheDenylist mirrors the allowlist normalization:
// whichever list the mode owns is lower-cased and deduplicated, so a match at
// forwarding time never depends on the casing an operator happened to write.
func TestConfigEffectiveNormalizesTheDenylist(t *testing.T) {
	got, err := (Config{
		Provider: "scanner",
		Request: &PhaseConfig{Headers: HeadersConfig{
			Mode:     HeaderModeDenylist,
			Denylist: []string{"Authorization", "authorization", "Cookie"},
		}},
		Response: &PhaseConfig{Headers: HeadersConfig{
			Mode:     HeaderModeDenylist,
			Denylist: []string{"Set-Cookie", "set-cookie"},
		}},
	}).Effective()
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	wantRequest := []string{"authorization", "cookie"}
	if !reflect.DeepEqual(got.Request.Headers.Denylist, wantRequest) {
		t.Errorf("request denylist = %v, want %v", got.Request.Headers.Denylist, wantRequest)
	}
	if len(got.Request.Headers.Allowlist) != 0 {
		t.Errorf("request allowlist = %v, want empty under denylist mode", got.Request.Headers.Allowlist)
	}
	wantResponse := []string{"set-cookie"}
	if !reflect.DeepEqual(got.Response.Headers.Denylist, wantResponse) {
		t.Errorf("response denylist = %v, want %v", got.Response.Headers.Denylist, wantResponse)
	}
}
