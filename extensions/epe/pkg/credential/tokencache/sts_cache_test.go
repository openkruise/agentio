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
package tokencache

import (
	"sync"
	"testing"
	"time"
)

func stsEntry(ak, sk, token string) STSCacheEntry {
	return STSCacheEntry{
		AccessKeyID:     ak,
		AccessKeySecret: sk,
		SecurityToken:   token,
	}
}

func TestSTSCache_BasicSetGet(t *testing.T) {
	c := NewSTSCache(100)
	entry := stsEntry("ak1", "sk1", "token1")
	c.SetWithExpiration(
		Key{ProviderName: "provider-a", ResourceID: "resource-1"},
		entry,
		time.Now().Add(1*time.Hour),
		0,
	)

	got, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"})
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.AccessKeyID != "ak1" || got.AccessKeySecret != "sk1" || got.SecurityToken != "token1" {
		t.Errorf("unexpected entry: %+v", got)
	}
}

func TestSTSCache_Miss(t *testing.T) {
	c := NewSTSCache(100)

	got, ok := c.Get(Key{ProviderName: "provider-a", ResourceID: "resource-1"})
	if ok {
		t.Fatalf("expected cache miss, got %+v", got)
	}
}

func TestSTSCache_Expiration(t *testing.T) {
	c := NewSTSCache(100)
	c.expirationMargin = 0
	now := time.Unix(1000, 0)
	c.SetClock(func() time.Time { return now })

	entry := stsEntry("ak1", "sk1", "token1")
	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r1"}, entry, now.Add(50*time.Millisecond), 0)

	got, ok := c.Get(Key{ProviderName: "p", ResourceID: "r1"})
	if !ok || got.AccessKeyID != "ak1" {
		t.Fatalf("expected immediate hit, got %+v, %v", got, ok)
	}

	now = now.Add(100 * time.Millisecond)

	got, ok = c.Get(Key{ProviderName: "p", ResourceID: "r1"})
	if ok {
		t.Fatalf("expected expired entry, got %+v", got)
	}
}

// TestSTSCache_ExpirationMargin verifies the safety margin: an entry whose
// effective expiry (expiration - margin) is already in the past is skipped,
// while one with enough remaining lifetime is cached.
func TestSTSCache_ExpirationMargin(t *testing.T) {
	tests := []struct {
		name       string
		margin     time.Duration
		expiresIn  time.Duration
		wantCached bool
	}{
		{
			// Token expires in 5 minutes, but margin is 10 minutes, so effective
			// expiry is 5min - 10min = -5min (already past). Should not be cached.
			name:       "margin exceeds lifetime",
			margin:     10 * time.Minute,
			expiresIn:  5 * time.Minute,
			wantCached: false,
		},
		{
			// Token expires in 1 hour. Effective expiry = 55min from now. Should cache.
			name:       "lifetime exceeds margin",
			margin:     5 * time.Minute,
			expiresIn:  1 * time.Hour,
			wantCached: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewSTSCache(100)
			c.expirationMargin = tc.margin

			entry := stsEntry("ak1", "sk1", "token1")
			c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r1"}, entry, time.Now().Add(tc.expiresIn), 0)

			got, ok := c.Get(Key{ProviderName: "p", ResourceID: "r1"})
			if ok != tc.wantCached {
				t.Fatalf("cached = %v, want %v", ok, tc.wantCached)
			}
			if tc.wantCached {
				if got.AccessKeyID != "ak1" {
					t.Errorf("expected ak1, got %s", got.AccessKeyID)
				}
			} else if c.Len() != 0 {
				t.Errorf("expected len 0, got %d", c.Len())
			}
		})
	}
}

func TestSTSCache_Delete(t *testing.T) {
	c := NewSTSCache(100)
	entry := stsEntry("ak1", "sk1", "token1")
	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r1"}, entry, time.Now().Add(1*time.Hour), 0)

	c.Delete(Key{ProviderName: "p", ResourceID: "r1"})

	_, ok := c.Get(Key{ProviderName: "p", ResourceID: "r1"})
	if ok {
		t.Fatal("expected cache miss after delete")
	}
}

func TestSTSCache_DeleteNonExistent(t *testing.T) {
	c := NewSTSCache(100)
	c.Delete(Key{ProviderName: "nonexistent", ResourceID: "nonexistent"}) // should not panic
}

func TestSTSCache_LRUEviction(t *testing.T) {
	c := NewSTSCache(3)
	c.expirationMargin = 0
	exp := time.Now().Add(1 * time.Hour)

	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r1"}, stsEntry("ak1", "sk1", "t1"), exp, 0)
	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r2"}, stsEntry("ak2", "sk2", "t2"), exp, 0)
	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r3"}, stsEntry("ak3", "sk3", "t3"), exp, 0)
	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r4"}, stsEntry("ak4", "sk4", "t4"), exp, 0)

	_, ok := c.Get(Key{ProviderName: "p", ResourceID: "r1"})
	if ok {
		t.Fatal("expected r1 to be evicted")
	}

	got, ok := c.Get(Key{ProviderName: "p", ResourceID: "r2"})
	if !ok || got.AccessKeyID != "ak2" {
		t.Errorf("expected r2=ak2, got %+v, %v", got, ok)
	}
}

func TestSTSCache_UpdateExisting(t *testing.T) {
	c := NewSTSCache(100)
	c.expirationMargin = 0
	exp := time.Now().Add(1 * time.Hour)

	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r1"}, stsEntry("ak-old", "sk-old", "t-old"), exp, 0)
	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r1"}, stsEntry("ak-new", "sk-new", "t-new"), exp, 0)

	got, ok := c.Get(Key{ProviderName: "p", ResourceID: "r1"})
	if !ok || got.AccessKeyID != "ak-new" {
		t.Errorf("expected ak-new, got %+v, %v", got, ok)
	}
	if c.Len() != 1 {
		t.Errorf("expected len 1, got %d", c.Len())
	}
}

func TestSTSCache_Len(t *testing.T) {
	c := NewSTSCache(100)
	c.expirationMargin = 0
	exp := time.Now().Add(1 * time.Hour)

	if c.Len() != 0 {
		t.Errorf("expected 0, got %d", c.Len())
	}

	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r1"}, stsEntry("ak1", "sk1", "t1"), exp, 0)
	c.SetWithExpiration(Key{ProviderName: "p", ResourceID: "r2"}, stsEntry("ak2", "sk2", "t2"), exp, 0)

	if c.Len() != 2 {
		t.Errorf("expected 2, got %d", c.Len())
	}
}

func TestSTSCache_DifferentProviders(t *testing.T) {
	c := NewSTSCache(100)
	c.expirationMargin = 0
	exp := time.Now().Add(1 * time.Hour)

	c.SetWithExpiration(Key{ProviderName: "provider-a", ResourceID: "r1"}, stsEntry("ak-a", "sk-a", "t-a"), exp, 0)
	c.SetWithExpiration(Key{ProviderName: "provider-b", ResourceID: "r1"}, stsEntry("ak-b", "sk-b", "t-b"), exp, 0)

	gotA, okA := c.Get(Key{ProviderName: "provider-a", ResourceID: "r1"})
	gotB, okB := c.Get(Key{ProviderName: "provider-b", ResourceID: "r1"})

	if !okA || gotA.AccessKeyID != "ak-a" {
		t.Errorf("provider-a: expected ak-a, got %+v, %v", gotA, okA)
	}
	if !okB || gotB.AccessKeyID != "ak-b" {
		t.Errorf("provider-b: expected ak-b, got %+v, %v", gotB, okB)
	}
}

func TestSTSCache_ConcurrentAccess(t *testing.T) {
	c := NewSTSCache(1000)
	c.expirationMargin = 0
	entry := stsEntry("ak", "sk", "token")
	exp := time.Now().Add(1 * time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c.SetWithExpiration(Key{ProviderName: "provider", ResourceID: "resource"}, entry, exp, 0)
		}()
		go func() {
			defer wg.Done()
			c.Get(Key{ProviderName: "provider", ResourceID: "resource"})
		}()
	}
	wg.Wait()

	got, ok := c.Get(Key{ProviderName: "provider", ResourceID: "resource"})
	if !ok || got.AccessKeyID != "ak" {
		t.Errorf("expected ak after concurrent ops, got %+v, %v", got, ok)
	}
}

// TestSTSCache_DefaultExpirationMargin verifies NewSTSCache falls back to the
// default expiration margin regardless of a non-positive max size.
func TestSTSCache_DefaultExpirationMargin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		maxSize int
	}{
		{name: "zero max size", maxSize: 0},
		{name: "negative max size", maxSize: -5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewSTSCache(tc.maxSize)
			if c.expirationMargin != defaultExpirationMargin {
				t.Errorf("expected default expiration margin %v, got %v", defaultExpirationMargin, c.expirationMargin)
			}
		})
	}
}
