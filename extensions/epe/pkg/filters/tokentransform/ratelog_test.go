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
package tokentransform

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestLimiterAllow drives the limiter through ordered Allow calls with a fake
// clock; each case is an independent limiter and a sequence of steps.
func TestLimiterAllow(t *testing.T) {
	type step struct {
		name    string
		key     string
		advance time.Duration
		want    bool
	}
	tests := []struct {
		name  string
		ttl   time.Duration
		steps []step
	}{
		{
			name: "basic allow, suppress, and TTL reset",
			ttl:  time.Minute,
			steps: []step{
				{name: "first call must allow", key: "a", want: true},
				{name: "immediate second call must be suppressed", key: "a", want: false},
				{name: "different key must allow", key: "b", want: true},
				{name: "call after TTL must allow again", key: "a", advance: 61 * time.Second, want: true},
			},
		},
		{
			name: "independent keys tracked separately",
			ttl:  time.Minute,
			steps: []step{
				{name: "first key alpha", key: "alpha", want: true},
				{name: "first key beta", key: "beta", want: true},
				{name: "first key gamma", key: "gamma", want: true},
				{name: "repeat alpha suppressed", key: "alpha", want: false},
				{name: "repeat beta suppressed", key: "beta", want: false},
				{name: "first key delta", key: "delta", want: true},
			},
		},
		{
			name: "expiration boundary",
			ttl:  5 * time.Second,
			steps: []step{
				{name: "first call allowed", key: "x", want: true},
				{name: "before TTL suppressed", key: "x", advance: 4 * time.Second, want: false},
				{name: "exactly at TTL boundary suppressed", key: "x", want: false},
				{name: "after TTL allowed again", key: "x", advance: 2 * time.Second, want: true},
				{name: "immediately after re-allow suppressed", key: "x", want: false},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(0, 0)
			l := NewLimiter(tc.ttl, func() time.Time { return now })
			for _, s := range tc.steps {
				now = now.Add(s.advance)
				if got := l.Allow(s.key); got != s.want {
					t.Fatalf("%s: Allow(%q) = %v, want %v", s.name, s.key, got, s.want)
				}
			}
		})
	}
}

func TestNewLimiter_NilClock(t *testing.T) {
	// Passing nil clock should default to time.Now; the limiter must still function.
	l := NewLimiter(time.Second, nil)
	if !l.Allow("key") {
		t.Fatalf("first call with nil clock must be allowed")
	}
	if l.Allow("key") {
		t.Errorf("immediate repeat with nil clock must be suppressed")
	}
}

func TestAllow_PurgeExpiredEntries(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(time.Second, func() time.Time { return now })

	// Insert gcThreshold+1 unique keys so the purge path triggers.
	for i := 0; i <= gcThreshold; i++ {
		key := fmt.Sprintf("k%d", i)
		if !l.Allow(key) {
			t.Fatalf("initial insert of %s must be allowed", key)
		}
	}

	// Advance time past TTL so all entries are expired, then insert one more
	// key to trigger purge again.
	now = now.Add(2 * time.Second)

	// After purge, a previously-seen key is allowed again (entry was purged).
	if !l.Allow("k0") {
		t.Errorf("k0 should be allowed after expiration and purge")
	}

	if l.Allow("k0") {
		t.Errorf("k0 should be suppressed immediately after re-allow")
	}
}

func TestAllow_ConcurrentAccess(t *testing.T) {
	now := time.Unix(0, 0)
	var mu sync.Mutex
	l := NewLimiter(time.Hour, func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})

	const goroutines = 50
	const keysPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for k := 0; k < keysPerGoroutine; k++ {
				key := fmt.Sprintf("g%d-k%d", g, k)
				l.Allow(key)
			}
		}()
	}
	wg.Wait()

	// If there were a race, the race detector would have flagged it.
	if !l.Allow("post-concurrent") {
		t.Errorf("limiter must work after concurrent usage")
	}
	if l.Allow("post-concurrent") {
		t.Errorf("repeat key must still be suppressed")
	}
}
