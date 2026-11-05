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

// GetToken / GetSTSCredential behavior against a fake credential provider.
// This is an external test package on purpose: it shares the fake in
// credentialtest, which imports credential — an internal test package would
// form a test import cycle. Tests that poke unexported client internals
// (URL resolution, mTLS transport construction) stay in client_test.go.
package credential_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential/credentialtest"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential/tokencache"
)

func TestGetTokenWithExtraMetadata_SendsMetadata(t *testing.T) {
	p := credentialtest.NewAPIKeyProvider(t, "k1")
	metadata := map[string]any{
		"tenant": "tenant-a",
		"scopes": []any{"read", "write"},
	}
	if _, err := p.Client().GetTokenWithExtraMetadata(context.Background(), "access", "client", "provider", metadata); err != nil {
		t.Fatalf("GetTokenWithExtraMetadata: %v", err)
	}

	raw, _ := p.LastRequestBody.Load().([]byte)
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if !reflect.DeepEqual(got["extraMetadata"], metadata) {
		t.Fatalf("extraMetadata = %#v, want %#v", got["extraMetadata"], metadata)
	}
}

func TestGetTokenWithExtraMetadata_PartitionsCache(t *testing.T) {
	p := credentialtest.NewAPIKeyProvider(t, "k1")
	c := p.ClientWithCache(tokencache.NewCache(time.Minute, 10), nil)

	for _, metadata := range []map[string]any{
		{"tenant": "tenant-a"},
		{"tenant": "tenant-b"},
		{"tenant": "tenant-a"},
	} {
		if _, err := c.GetTokenWithExtraMetadata(context.Background(), "access", "client", "provider", metadata); err != nil {
			t.Fatalf("GetTokenWithExtraMetadata: %v", err)
		}
	}
	if got := p.Calls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2 distinct metadata cache entries", got)
	}
}

// TestGetToken_CacheExpiresInSeconds asserts the provider's declared lifetime
// governs the cache entry, and that absent/null/non-positive falls back to the
// cache's own TTL. Measured by whether a second GetToken reaches the provider,
// since the TTL is not observable from outside the cache.
func TestGetToken_CacheExpiresInSeconds(t *testing.T) {
	const cacheTTL = time.Hour

	for _, tc := range []struct {
		name    string
		field   string        // rendered verbatim into the response JSON
		wantTTL time.Duration // lifetime the entry should end up with
	}{
		{name: "shorter than the fallback", field: `,"cacheExpiresInSeconds":600`, wantTTL: 600 * time.Second},
		{name: "longer than the fallback", field: `,"cacheExpiresInSeconds":10800`, wantTTL: 3 * time.Hour},
		{name: "absent", field: ``, wantTTL: cacheTTL},
		{name: "null", field: `,"cacheExpiresInSeconds":null`, wantTTL: cacheTTL},
		{name: "zero", field: `,"cacheExpiresInSeconds":0`, wantTTL: cacheTTL},
		{name: "negative", field: `,"cacheExpiresInSeconds":-5`, wantTTL: cacheTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := credentialtest.NewRawProvider(t, `{"requestId":"r","apiKey":"k1"`+tc.field+`}`)
			cache := tokencache.NewCache(cacheTTL, 10)
			now := time.Unix(1000, 0)
			cache.SetClock(func() time.Time { return now })
			c := p.ClientWithCache(cache, nil)

			// A malformed lifetime must not fail the credential itself.
			tok, err := c.GetToken(context.Background(), "access", "client", "provider")
			if err != nil {
				t.Fatalf("GetToken: %v", err)
			}
			if tok != "k1" {
				t.Fatalf("token = %q, want k1", tok)
			}

			// Just short of the expected lifetime: still cached.
			now = now.Add(tc.wantTTL - time.Second)
			if _, err := c.GetToken(context.Background(), "access", "client", "provider"); err != nil {
				t.Fatalf("GetToken before expiry: %v", err)
			}
			if got := p.Calls.Load(); got != 1 {
				t.Fatalf("provider calls = %d before %v elapsed, want 1 (entry expired early)", got, tc.wantTTL)
			}

			// Just past it: refetched.
			now = now.Add(2 * time.Second)
			if _, err := c.GetToken(context.Background(), "access", "client", "provider"); err != nil {
				t.Fatalf("GetToken after expiry: %v", err)
			}
			if got := p.Calls.Load(); got != 2 {
				t.Fatalf("provider calls = %d after %v elapsed, want 2 (entry outlived its TTL)", got, tc.wantTTL)
			}
		})
	}
}

// TestGetToken_CacheExpiresInSecondsNonNumeric documents that a quoted or
// fractional value fails the whole response unmarshal, so the apiKey becomes
// unreachable rather than the lifetime falling back.
func TestGetToken_CacheExpiresInSecondsNonNumeric(t *testing.T) {
	for _, field := range []string{`"600"`, `600.5`, `"abc"`} {
		p := credentialtest.NewRawProvider(t, `{"requestId":"r","apiKey":"k1","cacheExpiresInSeconds":`+field+`}`)
		_, err := p.Client().GetToken(context.Background(), "access", "client", "provider")
		if err == nil {
			t.Errorf("cacheExpiresInSeconds=%s: expected the whole lookup to fail, got a usable token", field)
		}
	}
}

// --- GetToken ---------------------------------------------------------------

func TestGetToken_Success(t *testing.T) {
	p := credentialtest.NewAPIKeyProvider(t, "k1")
	c := p.Client()

	tok, err := c.GetToken(context.Background(), "access", "client", "provider")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if tok != "k1" {
		t.Errorf("expected k1, got %q", tok)
	}
	got, _ := p.LastRequestBody.Load().([]byte)
	if !bytes.Contains(got, []byte(`"resourceId":"client"`)) ||
		!bytes.Contains(got, []byte(`"credentialProviderName":"provider"`)) {
		t.Errorf("unexpected request body: %s", got)
	}
}

// TestGetToken_Errors covers the response-handling failure modes: a non-OK
// HTTP status, an unparseable body, and an empty apiKey in a valid response.
func TestGetToken_Errors(t *testing.T) {
	tests := []struct {
		name   string
		client func(t *testing.T) *credential.Client
	}{
		{
			name: "non-OK status",
			client: func(t *testing.T) *credential.Client {
				return credentialtest.NewErrorProvider(t, http.StatusForbidden, `denied`).Client()
			},
		},
		{
			name: "bad JSON body",
			client: func(t *testing.T) *credential.Client {
				return credentialtest.NewErrorProvider(t, http.StatusOK, `not json`).Client()
			},
		},
		{
			name: "empty apiKey",
			client: func(t *testing.T) *credential.Client {
				return credentialtest.NewAPIKeyProvider(t, "").Client()
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.client(t).GetToken(context.Background(), "access", "client", "provider"); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

// TestGetToken_CacheHit verifies the cache short-circuits the HTTP call.
func TestGetToken_CacheHit(t *testing.T) {
	p := credentialtest.NewAPIKeyProvider(t, "fresh")
	c := p.ClientWithCache(tokencache.NewCache(time.Minute, 10), nil)

	for i := 0; i < 3; i++ {
		tok, err := c.GetToken(context.Background(), "a", "b", "p")
		if err != nil || tok != "fresh" {
			t.Fatalf("iter %d: tok=%q err=%v", i, tok, err)
		}
	}
	if called := p.Calls.Load(); called != 1 {
		t.Errorf("expected upstream to be called once, got %d", called)
	}
}

// TestGetToken_NetworkError covers the "request send failed" branch by
// pointing at a server we've already shut down.
func TestGetToken_NetworkError(t *testing.T) {
	p := credentialtest.NewAPIKeyProvider(t, "unreachable")
	p.Server.Close() // URL stays readable; the client just cannot connect
	c := p.Client()

	if _, err := c.GetToken(context.Background(), "a", "b", "c"); err == nil {
		t.Fatal("expected network error")
	}
}

// --- GetSTSCredential -------------------------------------------------------

// stsClient wires a fake STS provider to a client with a fresh STS cache.
func stsClient(p *credentialtest.FakeProvider) *credential.Client {
	return p.ClientWithCache(nil, tokencache.NewSTSCache(100))
}

func TestGetSTSCredential_CacheHit(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	p := credentialtest.NewSTSProvider(t, "ak", "sk", "st", exp)
	c := stsClient(p)

	for i := 0; i < 3; i++ {
		cred, err := c.GetSTSCredential(context.Background(), "access", "client", "provider")
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if cred.AccessKeyID != "ak" || cred.AccessKeySecret != "sk" || cred.SecurityToken != "st" {
			t.Fatalf("iter %d: unexpected cred: %+v", i, cred)
		}
	}
	if called := p.Calls.Load(); called != 1 {
		t.Errorf("expected upstream to be called once, got %d", called)
	}
}

// TestGetSTSCredential_HitMatchesMiss asserts a cache hit returns the same value
// as the miss that populated it.
func TestGetSTSCredential_HitMatchesMiss(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	p := credentialtest.NewSTSProvider(t, "ak", "sk", "st", exp)
	c := stsClient(p)

	miss, err := c.GetSTSCredential(context.Background(), "access", "client", "provider")
	if err != nil {
		t.Fatalf("miss: %v", err)
	}
	hit, err := c.GetSTSCredential(context.Background(), "access", "client", "provider")
	if err != nil {
		t.Fatalf("hit: %v", err)
	}
	if p.Calls.Load() != 1 {
		t.Fatalf("expected the second call to hit the cache, got %d upstream calls", p.Calls.Load())
	}
	if miss != hit {
		t.Errorf("miss = %+v, hit = %+v", miss, hit)
	}
}

func TestGetSTSCredentialWithExtraMetadata_PartitionsCache(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	p := credentialtest.NewSTSProvider(t, "ak", "sk", "st", exp)
	c := stsClient(p)

	for _, metadata := range []map[string]any{
		{"tenant": "tenant-a"},
		{"tenant": "tenant-b"},
		{"tenant": "tenant-a"},
	} {
		if _, err := c.GetSTSCredentialWithExtraMetadata(context.Background(), "access", "client", "provider", metadata); err != nil {
			t.Fatalf("GetSTSCredentialWithExtraMetadata: %v", err)
		}
	}
	if got := p.Calls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2 distinct metadata cache entries", got)
	}
}

// TestGetSTSCredential_NotCached verifies every request reaches the provider
// whenever the response cannot be cached: the expiration falls inside the
// safety margin, the response carries no expiration, or no STS cache is
// configured on the client.
func TestGetSTSCredential_NotCached(t *testing.T) {
	tests := []struct {
		name string
		// expiration returns the expiration string served by the fake provider;
		// evaluated per subtest so "now"-relative timestamps stay fresh.
		expiration func() string
		withCache  bool
		calls      int
	}{
		{
			// Expiration is 1 second from now; with the default 5min margin,
			// the effective expiry is already in the past, so caching is skipped.
			name:       "expiration within margin",
			expiration: func() string { return time.Now().Add(1 * time.Second).UTC().Format(time.RFC3339) },
			withCache:  true,
			calls:      3,
		},
		{
			name:       "no expiration in response",
			expiration: func() string { return "" },
			withCache:  true,
			calls:      2,
		},
		{
			name:       "no STS cache configured",
			expiration: func() string { return time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339) },
			withCache:  false,
			calls:      2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := credentialtest.NewSTSProvider(t, "ak", "sk", "st", tc.expiration())
			c := p.Client() // no STS cache
			if tc.withCache {
				c = stsClient(p)
			}

			for i := 0; i < tc.calls; i++ {
				if _, err := c.GetSTSCredential(context.Background(), "access", "client", "provider"); err != nil {
					t.Fatalf("iter %d: %v", i, err)
				}
			}
			if called := p.Calls.Load(); called != int64(tc.calls) {
				t.Errorf("expected upstream to be called %d times (no caching), got %d", tc.calls, called)
			}
		})
	}
}

func TestGetSTSCredential_IncompleteResponse(t *testing.T) {
	p := credentialtest.NewSTSProvider(t, "ak", "", "st", "")
	c := stsClient(p)

	_, err := c.GetSTSCredential(context.Background(), "access", "client", "provider")
	if err == nil {
		t.Fatal("expected error for incomplete STS credential")
	}
}
