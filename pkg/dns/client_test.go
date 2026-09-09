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
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestFamiliesAndOwnedResults(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	calls := 0
	r := NewClient(ttlLookupFunc(func(context.Context, string) (LookupResult, error) {
		calls++
		return LookupResult{Addresses: []netip.Addr{v4, v6, v4}, TTL: time.Minute}, nil
	}), 0)
	now := time.Unix(1000, 0)
	r.cache.now = func() time.Time { return now }
	for _, test := range []struct {
		family Family
		want   []netip.Addr
	}{
		{IPv4Only, []netip.Addr{v4}},
		{IPv6Only, []netip.Addr{v6}},
		{DualStack, []netip.Addr{v4, v6}},
	} {
		first, err := r.Resolve(context.Background(), "API.example.", test.family)
		if err != nil || !reflect.DeepEqual(first.Addresses, test.want) {
			t.Fatalf("result=%+v, err=%v", first, err)
		}
		expires := first.ExpiresAt
		first.Addresses[0] = netip.Addr{} // Miss results must not alias stored data.
		now = now.Add(time.Second)
		second, err := r.Resolve(context.Background(), "api.example", test.family)
		if err != nil || !reflect.DeepEqual(second.Addresses, test.want) {
			t.Fatalf("cache result=%+v, err=%v", second, err)
		}
		if second.ExpiresAt != expires {
			t.Fatal("cache hit extended expiration")
		}
		second.Addresses[0] = netip.Addr{} // Hit results must also be independent.
		third, err := r.Resolve(context.Background(), "api.example", test.family)
		if err != nil || !reflect.DeepEqual(third.Addresses, test.want) {
			t.Fatalf("cache result=%+v, err=%v", third, err)
		}
	}
	if calls != 3 {
		t.Fatalf("address families did not use independent keys: calls=%d", calls)
	}
}

func TestCustomRecordFamilyAndInvalidation(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	calls := 0
	r := NewClient(ttlLookupFunc(func(context.Context, string) (LookupResult, error) {
		calls++
		return LookupResult{Addresses: []netip.Addr{v4, v6}, TTL: time.Minute}, nil
	}), 0)
	for _, family := range []Family{IPv4Only, IPv6Only, DualStack} {
		if _, err := r.Resolve(context.Background(), "api.example", family); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.SetRecord("api.example", []netip.Addr{v4}); err != nil {
		t.Fatal(err)
	}
	if r.cache.dns.Len() != 0 {
		t.Fatal("not all families invalidated")
	}
	if _, err := r.Resolve(context.Background(), "api.example", IPv6Only); !errors.Is(err, ErrNoAddresses) {
		t.Fatalf("error=%v", err)
	}
	if calls != 3 {
		t.Fatal("missing custom address family fell back to DNS")
	}
	if err := r.SetRecord("api.example", []netip.Addr{v6, v4}); err != nil {
		t.Fatal(err)
	}
	result, err := r.Resolve(context.Background(), "api.example", DualStack)
	if err != nil || result.Source != SourceCustom || !result.ExpiresAt.IsZero() || !reflect.DeepEqual(result.Addresses, []netip.Addr{v6, v4}) {
		t.Fatalf("custom result=%+v, err=%v", result, err)
	}
	result.Addresses[0] = netip.Addr{}
	result, err = r.Resolve(context.Background(), "api.example", IPv6Only)
	if err != nil || len(result.Addresses) != 1 || result.Addresses[0] != v6 {
		t.Fatalf("record mutated: %+v, %v", result, err)
	}
	if err := r.DeleteRecord("api.example"); err != nil {
		t.Fatal(err)
	}
	for _, family := range []Family{IPv4Only, IPv6Only, DualStack} {
		if _, err := r.Resolve(context.Background(), "api.example", family); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 6 {
		t.Fatalf("stale DNS answers survived custom records: calls=%d", calls)
	}
}

func TestExpiredAnswerIsNotServedOnFailure(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	want := errors.New("DNS unavailable")
	r := NewClient(ttlLookupFunc(func(context.Context, string) (LookupResult, error) {
		calls++
		if calls > 1 {
			return LookupResult{}, want
		}
		return LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: time.Second}, nil
	}), 0)
	r.cache.now = func() time.Time { return now }
	if _, err := r.Resolve(context.Background(), "api.example", IPv4Only); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	result, err := r.Resolve(context.Background(), "api.example", IPv4Only)
	if !errors.Is(err, want) || len(result.Addresses) != 0 {
		t.Fatalf("stale result=%+v, err=%v", result, err)
	}
}

func TestClientValidationAndCancellation(t *testing.T) {
	r := NewClient(ttlLookupFunc(func(context.Context, string) (LookupResult, error) {
		t.Fatal("invalid request reached lookup")
		return LookupResult{}, nil
	}), 0)
	for _, host := range []string{"", "api.example:80", "*.example", "user@api.example", "192.0.2.1", "::1", "api..example", " api.example", "api.example/path"} {
		if _, err := r.Resolve(context.Background(), host, IPv4Only); !errors.Is(err, ErrInvalidHost) {
			t.Fatalf("host=%q, err=%v", host, err)
		}
	}
	if _, err := r.Resolve(context.Background(), "api.example", Family(255)); !errors.Is(err, ErrInvalidFamily) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Resolve(ctx, "api.example", IPv4Only); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestLookupTimeCountsAgainstTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	r := NewClient(ttlLookupFunc(func(context.Context, string) (LookupResult, error) {
		now = now.Add(2 * time.Second)
		return LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: time.Second}, nil
	}), 0)
	r.cache.now = func() time.Time { return now }
	if _, err := r.Resolve(context.Background(), "api.example", IPv4Only); err != nil {
		t.Fatal(err)
	}
	if r.cache.dns.Len() != 0 {
		t.Fatal("slow lookup extended cache lifetime")
	}
}
