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

package controller

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"

	"github.com/openkruise/agentio/pkg/dns"
)

func TestResolverRefreshesWithoutBlockingCompile(t *testing.T) {
	ctx := t.Context()
	var calls atomic.Int32
	resolver, err := New(ctx, Options{RefreshInterval: 20 * time.Millisecond, LookupTimeout: time.Second, MaxConcurrent: 2},
		func(context.Context, string) (dns.LookupResult, error) {
			calls.Add(1)
			return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.Resolve(krt.TestingDummyContext{}, "API.EXAMPLE.COM."); got != nil {
		t.Fatalf("cold resolve blocked or returned data: %v", got)
	}
	deadline := time.Now().Add(time.Second)
	for resolver.Results().GetKey("api.example.com") == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if resolver.Results().GetKey("api.example.com") == nil {
		t.Fatal("DNS result was not published to the collection")
	}
	got := resolver.Resolve(krt.TestingDummyContext{}, "api.example.com")
	if len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Fatalf("cached result = %v", got)
	}
	if calls.Load() == 0 {
		t.Fatal("lookup was not called")
	}
}

func TestResolverEvictsUnreferencedColdResultAtRefreshDeadline(t *testing.T) {
	host := "transient.example.com"
	address := netip.MustParseAddr("203.0.113.10")
	item := &entry{
		hostname:  host,
		addresses: []netip.Addr{address},
		next:      time.Now().Add(-time.Second),
		published: true,
		index:     -1,
	}
	resolver := &Resolver{
		entries: map[string]*entry{host: item},
		results: krt.NewStaticCollection[Result](nil, []Result{{
			Hostname:  host,
			Addresses: []netip.Addr{address},
		}}),
		jobs: make(chan string, 1),
	}
	resolver.scheduleLocked(item)

	resolver.dispatchDue()

	resolver.mu.RLock()
	_, retained := resolver.entries[host]
	resolver.mu.RUnlock()
	if retained {
		t.Fatal("unreferenced cold DNS entry remained resident after its TTL")
	}
	if got := resolver.Results().GetKey(host); got != nil {
		t.Fatalf("unreferenced cold DNS result remained published after its TTL: %+v", got)
	}
}

func TestResolverDropsUnreferencedColdEntryAfterLookupFailure(t *testing.T) {
	host := "unavailable.example.com"
	item := &entry{hostname: host, resolving: true, index: -1}
	resolver := &Resolver{
		ctx:     t.Context(),
		options: Options{RefreshInterval: time.Hour, LookupTimeout: time.Second},
		lookup: func(context.Context, string) (dns.LookupResult, error) {
			return dns.LookupResult{}, fmt.Errorf("DNS unavailable")
		},
		entries: map[string]*entry{host: item},
		results: krt.NewStaticCollection[Result](nil, nil),
		wake:    make(chan struct{}, 1),
	}

	resolver.refresh(host)

	resolver.mu.RLock()
	_, retained := resolver.entries[host]
	resolver.mu.RUnlock()
	if retained {
		t.Fatal("failed unreferenced cold DNS entry remained scheduled for retry")
	}
}

func TestRefreshDelayHonorsTTLWithStableJitter(t *testing.T) {
	first := refreshDelay("api.example.com", 30*time.Second, time.Minute)
	second := refreshDelay("api.example.com", 30*time.Second, time.Minute)
	if first != second {
		t.Fatalf("stable jitter changed for the same hostname: %v != %v", first, second)
	}
	if first < 25*time.Second || first >= 28*time.Second {
		t.Fatalf("30s TTL refresh delay = %v, want [25s, 28s)", first)
	}

	short := refreshDelay("short.example.com", time.Second, time.Minute)
	if short < 5*time.Second || short >= 6*time.Second {
		t.Fatalf("short TTL refresh delay = %v, want [5s, 6s)", short)
	}

	fallback := refreshDelay("fallback.example.com", 0, 40*time.Second)
	if fallback < 35*time.Second || fallback >= 38*time.Second {
		t.Fatalf("fallback refresh delay = %v, want [35s, 38s)", fallback)
	}
}

func TestProtocolLookupCombinesAAndAAAAUsingMinimumTTL(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(response mdns.ResponseWriter, request *mdns.Msg) {
		message := new(mdns.Msg)
		message.SetReply(request)
		name := request.Question[0].Name
		switch request.Question[0].Qtype {
		case mdns.TypeA:
			message.Answer = append(message.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 45},
				A:   net.ParseIP("192.0.2.10"),
			})
		case mdns.TypeAAAA:
			message.Answer = append(message.Answer, &mdns.AAAA{
				Hdr:  mdns.RR_Header{Name: name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 20},
				AAAA: net.ParseIP("2001:db8::10"),
			})
		}
		_ = response.WriteMsg(message)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	lookup := newProtocolLookup([]string{packet.LocalAddr().String()}, time.Second)
	result, err := lookup(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if result.TTL != 20*time.Second {
		t.Fatalf("TTL = %v, want 20s", result.TTL)
	}
	want := sets.New(
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::10"),
	)
	if len(result.Addresses) != len(want) {
		t.Fatalf("addresses = %v, want one A and one AAAA", result.Addresses)
	}
	for _, address := range result.Addresses {
		if !want.Contains(address) {
			t.Fatalf("unexpected address %s in %v", address, result.Addresses)
		}
	}
}

func TestProtocolLookupTreatsNXDOMAINAsAuthoritativeEmpty(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(response mdns.ResponseWriter, request *mdns.Msg) {
		message := new(mdns.Msg)
		message.SetRcode(request, mdns.RcodeNameError)
		message.Ns = append(message.Ns, &mdns.SOA{
			Hdr:     mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: 30},
			Ns:      "ns.example.com.",
			Mbox:    "hostmaster.example.com.",
			Minttl:  12,
			Refresh: 60,
			Retry:   60,
			Expire:  300,
		})
		_ = response.WriteMsg(message)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	lookup := newProtocolLookup([]string{packet.LocalAddr().String()}, time.Second)
	result, err := lookup(context.Background(), "gone.example.com")
	if err != nil {
		t.Fatalf("NXDOMAIN returned a transient error: %v", err)
	}
	if len(result.Addresses) != 0 {
		t.Fatalf("NXDOMAIN addresses = %v, want empty", result.Addresses)
	}
	if result.TTL != 12*time.Second {
		t.Fatalf("negative TTL = %v, want 12s", result.TTL)
	}
}

func TestResolverSchedulesFromAnswerTTLAndPreservesOnFailure(t *testing.T) {
	ctx := t.Context()
	var phase atomic.Int32
	resolver, err := New(ctx, Options{RefreshInterval: time.Hour, LookupTimeout: time.Second, MaxConcurrent: 1},
		func(context.Context, string) (dns.LookupResult, error) {
			if phase.Load() == 0 {
				return dns.LookupResult{
					Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.20")},
					TTL:       30 * time.Second,
				}, nil
			}
			return dns.LookupResult{}, fmt.Errorf("temporary DNS failure")
		})
	if err != nil {
		t.Fatal(err)
	}
	resolver.HandleAdd("api.example.com")
	eventuallyDNS(t, func() bool {
		result := resolver.Results().GetKey("api.example.com")
		return result != nil && len(result.Addresses) == 1
	}, "initial DNS result published")

	resolver.mu.RLock()
	next := resolver.entries["api.example.com"].next
	resolver.mu.RUnlock()
	delay := time.Until(next)
	if delay < 24*time.Second || delay >= 28*time.Second {
		t.Fatalf("next refresh delay = %v, want answer TTL based [24s, 28s)", delay)
	}

	phase.Store(1)
	resolver.refresh("api.example.com")
	result := resolver.Results().GetKey("api.example.com")
	if result == nil || len(result.Addresses) != 1 || result.Addresses[0].String() != "203.0.113.20" {
		t.Fatalf("temporary failure discarded last-known-good result: %+v", result)
	}
}

func TestNewUsesConfiguredDNSServers(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(response mdns.ResponseWriter, request *mdns.Msg) {
		message := new(mdns.Msg)
		message.SetReply(request)
		name := request.Question[0].Name
		if request.Question[0].Qtype == mdns.TypeA {
			message.Answer = append(message.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.30"),
			})
		}
		_ = response.WriteMsg(message)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	ctx := t.Context()
	resolver, err := New(ctx, Options{
		RefreshInterval: time.Hour,
		LookupTimeout:   time.Second,
		MaxConcurrent:   1,
		DNSServers:      []string{packet.LocalAddr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.Resolve(krt.TestingDummyContext{}, "api.example.com"); got != nil {
		t.Fatalf("cold resolve returned synchronously: %v", got)
	}
	eventuallyDNS(t, func() bool {
		result := resolver.Results().GetKey("api.example.com")
		return result != nil && len(result.Addresses) == 1 && result.Addresses[0].String() == "192.0.2.30"
	}, "configured DNS server result published")
}

func TestResolverWakesForAnswerTTLBeforeFallbackInterval(t *testing.T) {
	ctx := t.Context()
	var calls atomic.Int32
	resolver, err := New(ctx, Options{RefreshInterval: time.Hour, LookupTimeout: time.Second, MaxConcurrent: 1},
		func(context.Context, string) (dns.LookupResult, error) {
			call := calls.Add(1)
			return dns.LookupResult{
				Addresses: []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(call)})},
				TTL:       10 * time.Second,
			}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	resolver.HandleAdd("ttl.example.com")
	eventuallyDNS(t, func() bool {
		result := resolver.Results().GetKey("ttl.example.com")
		return result != nil && len(result.Addresses) == 1 && result.Addresses[0].String() == "192.0.2.1"
	}, "initial TTL result published")

	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		result := resolver.Results().GetKey("ttl.example.com")
		if result != nil && len(result.Addresses) == 1 && result.Addresses[0].String() == "192.0.2.2" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("TTL refresh did not run before fallback interval; calls=%d", calls.Load())
}
