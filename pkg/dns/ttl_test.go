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

package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

type ttlLookupFunc func(context.Context, string) (LookupResult, error)

func (f ttlLookupFunc) Lookup(ctx context.Context, host string, _ Family) (LookupResult, error) {
	return f(ctx, host)
}

func TestCacheUsesAnswerTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, 2 * time.Second, 90 * time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			calls := 0
			r := NewClient(ttlLookupFunc(func(context.Context, string) (LookupResult, error) {
				calls++
				return LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: ttl}, nil
			}), 0)
			now := time.Unix(1000, 0)
			r.cache.now = func() time.Time { return now }
			resolve := func() {
				t.Helper()
				if _, err := r.Resolve(context.Background(), "api.example", IPv4Only); err != nil {
					t.Fatal(err)
				}
			}
			resolve()
			if ttl > 0 {
				now = now.Add(ttl - time.Nanosecond)
				resolve()
				if calls != 1 {
					t.Fatalf("expired early: calls=%d", calls)
				}
				now = now.Add(time.Nanosecond)
			}
			resolve()
			if calls != 2 {
				t.Fatalf("TTL not honored: calls=%d", calls)
			}
		})
	}
}
