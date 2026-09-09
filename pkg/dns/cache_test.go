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

package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestCacheExpiryAndLRU(t *testing.T) {
	calls := map[string]int{}
	r := NewClient(lookupFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		calls[host]++
		return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
	}), 0, WithCache(2))
	now := time.Unix(1000, 0)
	r.cache.now = func() time.Time { return now }
	resolve := func(host string) {
		t.Helper()
		if _, err := r.Resolve(context.Background(), host, IPv4Only); err != nil {
			t.Fatal(err)
		}
	}
	resolve("A.example.")
	resolve("b.example")
	resolve("a.example") // Promote A.
	resolve("c.example") // Evict B.
	resolve("a.example")
	if calls["a.example"] != 1 {
		t.Fatal(calls)
	}
	resolve("b.example")
	if calls["b.example"] != 2 {
		t.Fatal(calls)
	}
	now = now.Add(time.Minute) // Exactly at expiry is a miss.
	resolve("b.example")
	if calls["b.example"] != 3 {
		t.Fatal(calls)
	}
}

func TestCustomRecords(t *testing.T) {
	dnsIP := netip.MustParseAddr("203.0.113.1")
	customIP := netip.MustParseAddr("192.0.2.1")
	calls := 0
	r := NewClient(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{dnsIP}, nil
	}), 0, WithCache(1))
	check := func(host string, want netip.Addr) {
		t.Helper()
		got, err := r.Resolve(context.Background(), host, IPv4Only)
		if err != nil || len(got.Addresses) != 1 || got.Addresses[0] != want {
			t.Fatalf("got %v, %v; want %v", got, err, want)
		}
	}
	check("a.example", dnsIP)
	addresses := []netip.Addr{customIP}
	if err := r.SetRecord("A.example.", addresses); err != nil {
		t.Fatal(err)
	}
	addresses[0] = dnsIP // Caller mutation cannot change the record.
	check("a.example", customIP)
	check("b.example", dnsIP)
	r.cache.now = func() time.Time { return time.Now().Add(time.Hour) }
	check("a.example", customIP) // Neither eviction nor expiry affects records.
	for _, invalid := range []struct {
		host string
		ips  []netip.Addr
	}{
		{"a.example", nil},
		{"a.example", []netip.Addr{customIP, netip.Addr{}}},
		{"a.example:80", []netip.Addr{customIP}},
		{"*.example", []netip.Addr{customIP}},
		{"192.0.2.1", []netip.Addr{customIP}},
	} {
		if err := r.SetRecord(invalid.host, invalid.ips); err == nil {
			t.Fatalf("accepted %v", invalid)
		}
	}
	check("a.example", customIP) // Failed updates are atomic.
	if err := r.DeleteRecord("A.example."); err != nil {
		t.Fatal(err)
	}
	check("a.example", dnsIP)
	if calls != 3 {
		t.Fatalf("DNS calls = %d", calls)
	}
}

func TestCacheDisabledAndErrors(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		calls := 0
		r := NewClient(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			calls++
			if !disabled {
				return nil, errors.New("DNS failure")
			}
			return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
		}), 0)
		if disabled {
			r = NewClient(r.lookup, 0, WithCache(0))
		}
		for range 2 {
			_, _ = r.Resolve(context.Background(), "a.example", IPv4Only)
		}
		if calls != 2 {
			t.Fatalf("disabled=%v: calls=%d", disabled, calls)
		}
	}
}

func TestRecordUpdateDuringLookup(t *testing.T) {
	for _, remove := range []bool{false, true} {
		started, release := make(chan struct{}), make(chan struct{})
		dnsIP, customIP := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("192.0.2.1")
		r := NewClient(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			close(started)
			<-release
			return []netip.Addr{dnsIP}, nil
		}), time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := r.Resolve(context.Background(), "a.example", IPv4Only)
			want := customIP
			if remove {
				want = dnsIP
			}
			if err != nil || len(ip.Addresses) != 1 || ip.Addresses[0] != want {
				t.Errorf("got %v, %v; want %v", ip, err, want)
			}
		}()
		<-started
		if err := r.SetRecord("a.example", []netip.Addr{customIP}); err != nil {
			t.Fatal(err)
		}
		if remove {
			if err := r.DeleteRecord("a.example"); err != nil {
				t.Fatal(err)
			}
		}
		close(release)
		wg.Wait()
		if r.cache.dns.Len() != 0 {
			t.Fatal("old lookup repopulated invalidated cache")
		}
	}
}

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f lookupFunc) Lookup(ctx context.Context, host string, family Family) (LookupResult, error) {
	network := "ip"
	if family == IPv4Only {
		network = "ip4"
	}
	if family == IPv6Only {
		network = "ip6"
	}
	addresses, err := f(ctx, network, host)
	return LookupResult{Addresses: addresses, TTL: time.Minute}, err
}
