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

package egressauthz

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/pkg/dns"
)

func run(t *testing.T, f authorizeFunc, host string, port int32) *filter.RouteMutation {
	t.Helper()
	target, reply, err := f(context.Background(), &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: host, Port: port}}})
	if err != nil {
		t.Fatal(err)
	}
	if reply != nil || target == nil {
		t.Fatalf("target=%v reply=%v", target, reply)
	}
	return &filter.RouteMutation{Upstream: target}
}

type lookupFunc func(context.Context, string, dns.Family) (dns.LookupResult, error)

func (f lookupFunc) Lookup(ctx context.Context, host string, family dns.Family) (dns.LookupResult, error) {
	return f(ctx, host, family)
}

func TestDNSUsesSharedCacheAndCustomRecords(t *testing.T) {
	calls := 0
	client := dns.NewClient(
		lookupFunc(func(_ context.Context, host string, family dns.Family) (dns.LookupResult, error) {
			calls++
			if host != "example.com" || family != dns.IPv4Only {
				t.Fatalf("lookup(%q, %v)", host, family)
			}
			return dns.LookupResult{
				Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
				TTL:       time.Minute,
			}, nil
		}),
		time.Second,
	)
	input := NewAggregate(client).Authorize
	for range 2 {
		got := run(t, input, "example.com", 8443)
		if !slices.Contains([]string{"192.0.2.1:8443", "192.0.2.2:8443"}, got.Upstream.Address.String()) ||
			got.ClearCache {
			t.Fatalf("unexpected route: %+v", got)
		}
	}
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls)
	}
	if err := client.SetRecord("example.com", []netip.Addr{netip.MustParseAddr("192.0.2.3")}); err != nil {
		t.Fatal(err)
	}
	if got := run(t, input, "example.com", 443); got.Upstream.Address.String() != "192.0.2.3:443" {
		t.Fatal("custom record did not override cached DNS")
	}
	if err := client.DeleteRecord("example.com"); err != nil {
		t.Fatal(err)
	}
	if got := run(
		t,
		input,
		"example.com",
		443,
	); !slices.Contains([]string{"192.0.2.1:443", "192.0.2.2:443"}, got.Upstream.Address.String()) ||
		calls != 2 {
		t.Fatal("removing custom record did not resume DNS")
	}
	got := run(t, NewAggregate(client).Authorize, "2001:db8::1", 443)
	if got.Upstream.Address.String() != "[2001:db8::1]:443" || got.ClearCache || calls != 2 {
		t.Fatal("literal IP route should skip DNS and preserve ClearCache=false")
	}
}

func TestInputFailuresDoNotProduceMutations(t *testing.T) {
	lookupErr := errors.New("lookup unavailable")
	client := dns.NewClient(lookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, lookupErr
	}), time.Second)
	for _, tc := range []struct {
		name  string
		input authorizeFunc
		host  string
		port  int32
		want  error
	}{
		{"lookup failure", NewAggregate(client).Authorize, "example.com", 443, lookupErr},
		{"missing client", NewAggregate(nil).Authorize, "example.com", 443, nil},
		{"invalid port", NewAggregate(client).Authorize, "example.com", 65536, nil},
		{"missing port", NewAggregate(client).Authorize, "example.com", 0, nil},
		{"scoped IP", NewAggregate(client).Authorize, "fe80::1%eth0", 443, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, _, err := tc.input(context.Background(), &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{
				Host:                tc.host,
				Port:                tc.port,
				OriginalDestination: netip.MustParseAddrPort("192.0.2.1:443"),
			}},
			})
			if err == nil || target != nil {
				t.Fatalf("target=%+v, err=%v", target, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuthorizationSelectsAndPinsAllowedCandidate(t *testing.T) {
	client := dns.NewClient(nil, time.Second)
	if err := client.SetRecord("example.com", []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
	}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Policies: []Policy{{Name: "test",
		Rules: []Rule{
			{Action: Deny, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}},
			{
				Action: Allow,
				CIDRs:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
				Ports:  []PortRange{{Start: 443}},
			},
		}}}}
	f := NewAggregate(client, cfg).Authorize
	if route := run(t, f, "example.com", 443); route.Upstream.Address.String() != "192.0.2.2:443" || route.ClearCache {
		t.Fatalf("unauthorized or changed target: %+v", route)
	}
	assertDenied(t, f, "example.com", 80)
	// A configured policy with no rules denies all destinations.
	empty := NewAggregate(client, Config{Policies: []Policy{{Name: "empty"}}}).Authorize
	assertDenied(t, empty, "example.com", 443)
	assertDenied(t, empty, "192.0.2.1", 443)
}

func assertDenied(t *testing.T, f authorizeFunc, host string, port int32) {
	t.Helper()
	target, reply, err := f(context.Background(), &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: host, Port: port}}})
	if err != nil || reply == nil || reply.Status != 403 || reply.Details != "epe_egress_denied" || target != nil {
		t.Fatalf("target=%v reply=%v err=%v", target, reply, err)
	}
}

type authorizeFunc func(context.Context, *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error)

func TestAuthorizationAuditDecision(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ips         []string
		original    string
		allowSecond bool
		wantAllowed bool
		want        string
	}{
		{name: "single deny", ips: []string{"192.0.2.1"}, want: filter.AuthorizationReasonPolicyDenied},
		{name: "no matching rule", ips: []string{"192.0.2.3"}, want: filter.AuthorizationReasonPolicyDenied},
		{name: "multiple denied", ips: []string{"192.0.2.1", "192.0.2.2"}, original: "192.0.2.99:80", want: filter.AuthorizationReasonPolicyDenied},
		{name: "allowed candidate", ips: []string{"192.0.2.1", "192.0.2.2"}, allowSecond: true, wantAllowed: true},
		{name: "denied original does not fall back", ips: []string{"192.0.2.1", "192.0.2.2"}, original: "192.0.2.1:80", allowSecond: true, want: filter.AuthorizationReasonPolicyDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := dns.NewClient(nil, time.Second)
			ips := make([]netip.Addr, 0, len(tc.ips))
			for _, ip := range tc.ips {
				ips = append(ips, netip.MustParseAddr(ip))
			}
			if err := client.SetRecord("example.com", ips); err != nil {
				t.Fatal(err)
			}
			action := Deny
			if tc.allowSecond {
				action = Allow
			}
			cfg := Config{
				Policies: []Policy{
					{
						Name:  "first",
						Rules: []Rule{{Action: Deny, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}}},
					},
					{
						Name:  "second",
						Rules: []Rule{{Action: action, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}}},
					},
				},
			}
			stream := &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: "example.com", Port: 80}}, StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()}}
			if tc.original != "" {
				stream.Request.OriginalDestination = netip.MustParseAddrPort(tc.original)
			}
			target, reply, err := NewAggregate(client, cfg).Authorize(t.Context(), stream)
			if err != nil {
				t.Fatal(err)
			}
			got := stream.Info.Authorization
			if got == nil || got.Reason != tc.want {
				t.Fatalf("audit: %+v", got)
			}
			if tc.wantAllowed {
				if reply != nil || got.Action != "allow" || got.Policy != "second" ||
					got.Destination != "192.0.2.2:80" {
					t.Fatalf("allow: %+v reply=%v", got, reply)
				}
			} else if tc.original == "192.0.2.1:80" {
				if target != nil || reply == nil || reply.Status != 403 || got.Action != "deny" ||
					got.Destination != tc.original || got.Policy != "first" ||
					got.RuleIndex == nil || *got.RuleIndex != 0 {
					t.Fatalf("original denial: target=%v reply=%v audit=%+v", target, reply, got)
				}
			} else if tc.name == "multiple denied" {
				if target != nil || reply == nil || reply.Status != 403 || got.Action != "deny" ||
					got.Policy != "" || got.RuleIndex != nil || got.Destination != "" {
					t.Fatalf("host denial: target=%v reply=%v audit=%+v", target, reply, got)
				}
			} else if tc.name == "no matching rule" && (got.Policy != "" || got.RuleIndex != nil) {
				t.Fatalf("invented match: %+v", got)
			}
		})
	}
}

func TestAuthorizationAuditResolutionFailure(t *testing.T) {
	client := dns.NewClient(lookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("DNS unavailable")
	}), time.Second)
	stream := &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: "example.com", Port: 80}}, StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()}}
	_, _, err := NewAggregate(client).Authorize(t.Context(), stream)
	if err == nil || stream.Info.Authorization.Action != "error" ||
		stream.Info.Authorization.Reason != filter.AuthorizationReasonResolutionFailed {
		t.Fatalf("error=%v audit=%+v", err, stream.Info.Authorization)
	}
}

func TestAggregateIPv4DNSAndDirectIPv6Destinations(t *testing.T) {
	for _, tc := range []struct {
		name     string
		host     string
		answers  []string
		upstream string
		denied   string
		want     string
		wantErr  error
	}{
		{name: "IPv4 DNS", host: "dual.example", answers: []string{"192.0.2.1"}, want: "192.0.2.1:443"},
		{name: "IPv6-only hostname has no address", host: "dual.example", answers: []string{"2001:db8::1"}, wantErr: dns.ErrNoAddresses},
		{name: "IPv6 answer is excluded", host: "dual.example", answers: []string{"2001:db8::1", "192.0.2.1"}, want: "192.0.2.1:443"},
		{name: "denied IPv4 cannot fall back to IPv6", host: "dual.example", answers: []string{"192.0.2.1", "2001:db8::1"}, denied: "0.0.0.0/0"},
		{name: "IPv4 literal skips DNS", host: "192.0.2.1", want: "192.0.2.1:443"},
		{name: "IPv6 literal skips DNS", host: "2001:db8::1", want: "[2001:db8::1]:443"},
		{name: "IPv6 literal is authorized", host: "::1", denied: "::1/128"},
		{name: "explicit IPv6 skips DNS", host: "unresolved.example", upstream: "[2001:db8::1]:8443", want: "[2001:db8::1]:8443"},
		{name: "explicit IPv6 is authorized", host: "unresolved.example", upstream: "[::1]:8443", denied: "::1/128"},
	} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/custom=%t", tc.name, custom), func(t *testing.T) {
				addresses := make([]netip.Addr, 0, len(tc.answers))
				for _, address := range tc.answers {
					addresses = append(addresses, netip.MustParseAddr(address))
				}
				lookups := 0
				client := dns.NewClient(
					lookupFunc(func(_ context.Context, host string, family dns.Family) (dns.LookupResult, error) {
						lookups++
						if host != tc.host || family != dns.IPv4Only {
							t.Fatalf("lookup(%q, %v), want (%q, IPv4Only)", host, family, tc.host)
						}
						return dns.LookupResult{Addresses: addresses}, nil
					}),
					0,
				)
				if custom && len(addresses) > 0 {
					if err := client.SetRecord(tc.host, addresses); err != nil {
						t.Fatal(err)
					}
				}
				cfg := Config{}
				if tc.denied != "" {
					cfg.DeniedCIDRs = []netip.Prefix{netip.MustParsePrefix(tc.denied)}
				}
				stream := &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: tc.host, Port: 443}}, StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()}}
				if tc.upstream != "" {
					address := netip.MustParseAddrPort(tc.upstream)
					stream.Upstream = &filter.UpstreamTarget{Address: &address}
				}
				target, reply, err := NewAggregate(client, cfg).Authorize(t.Context(), stream)
				switch {
				case tc.wantErr != nil:
					if !errors.Is(err, tc.wantErr) || target != nil || reply != nil ||
						stream.Info.Authorization.Reason != filter.AuthorizationReasonResolutionFailed {
						t.Fatalf("target=%v reply=%v err=%v, want %v", target, reply, err, tc.wantErr)
					}
				case tc.want == "":
					if err != nil || target != nil || reply == nil || reply.Status != 403 {
						t.Fatalf("target=%v reply=%v err=%v, want denial", target, reply, err)
					}
				default:
					if err != nil || reply != nil || target == nil || target.Address.String() != tc.want {
						t.Fatalf("target=%v reply=%v err=%v, want %s", target, reply, err, tc.want)
					}
				}
				wantLookups := 0
				if !custom && len(addresses) > 0 {
					wantLookups = 1
				}
				if lookups != wantLookups {
					t.Fatalf("DNS lookups=%d, want %d", lookups, wantLookups)
				}
			})
		}
	}
}

func TestAggregateRandomSelectionWithinPreferredFamily(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []string
		denied  []string
		want    []string
	}{
		{
			name:    "IPv4 preferred with interleaved families",
			answers: []string{"192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2", "192.0.2.3"},
			want:    []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		},
		{
			name:    "IPv6 answers do not change IPv4 selection",
			answers: []string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2", "2001:db8::3"},
			want:    []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			name:    "denied candidates excluded before selection",
			answers: []string{"192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2", "2001:db8::3"},
			denied:  []string{"192.0.2.1/32", "2001:db8::2/128"},
			want:    []string{"192.0.2.2"},
		},
		{
			name:    "later authorizer filters IPv4 candidates",
			answers: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"},
			denied:  []string{"192.0.2.1/32", "192.0.2.2/32"},
			want:    []string{"192.0.2.3", "192.0.2.4"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addresses := make([]netip.Addr, 0, len(tc.answers))
			for _, ip := range tc.answers {
				addresses = append(addresses, netip.MustParseAddr(ip))
			}
			lookups := 0
			client := dns.NewClient(lookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
				lookups++
				return dns.LookupResult{Addresses: addresses, TTL: time.Minute}, nil
			}), 0)
			authorizers := make([]Authorizer, 0, len(tc.denied))
			for _, cidr := range tc.denied {
				authorizers = append(authorizers, Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix(cidr)}})
			}
			a := NewAggregate(client, authorizers...)
			seen := make(map[string]bool)
			// Check every eligible IP is reachable without imposing an exact random
			// distribution. With at most three IPs, 128 draws make a miss negligible.
			for range 128 {
				target := run(t, a.Authorize, "multiple.example", 8443).Upstream
				ip := target.Address.Addr().String()
				if !slices.Contains(tc.want, ip) || target.Address.Port() != 8443 {
					t.Fatalf("selected %v outside eligible family/candidates %v", target.Address, tc.want)
				}
				seen[ip] = true
			}
			if len(seen) != len(tc.want) {
				t.Fatalf("selection stayed on a subset: got %v, want %v", seen, tc.want)
			}
			if lookups != 1 {
				t.Fatalf("DNS lookups=%d, want 1; selection must vary even with cached answers", lookups)
			}
		})
	}
}

func TestAggregateRandomSelectionPreservesFixedTargets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		host     string
		original string
		upstream string
		want     string
	}{
		{name: "IPv4 original", original: "192.0.2.2:443", want: "192.0.2.2:443"},
		{name: "IPv6 literal preserves original", host: "2001:db8::2", original: "[2001:db8::2]:443", want: "[2001:db8::2]:443"},
		{name: "explicit IPv4 overrides original", original: "192.0.2.2:443", upstream: "192.0.2.3:8443", want: "192.0.2.3:8443"},
		{name: "explicit IPv6 overrides original", original: "192.0.2.2:443", upstream: "[2001:db8::3]:8443", want: "[2001:db8::3]:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			client := dns.NewClient(lookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
				lookups++
				return dns.LookupResult{Addresses: []netip.Addr{
					netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
					netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
				},
					TTL: time.Minute,
				}, nil
			}), 0)
			a := NewAggregate(client, Config{})
			for range 128 {
				stream := &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{
					Host:                "multiple.example",
					Port:                443,
					OriginalDestination: netip.MustParseAddrPort(tc.original),
				}}, StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
				}
				if tc.host != "" {
					stream.Request.Host = tc.host
				}
				if tc.upstream != "" {
					address := netip.MustParseAddrPort(tc.upstream)
					stream.Upstream = &filter.UpstreamTarget{Address: &address}
				}
				target, reply, err := a.Authorize(t.Context(), stream)
				if err != nil || reply != nil || target == nil || target.Address.String() != tc.want {
					t.Fatalf("target=%v reply=%v err=%v, want %s", target, reply, err, tc.want)
				}
				if stream.Upstream != nil && target != stream.Upstream {
					t.Fatal("explicit upstream must be returned unchanged")
				}
				if stream.Info.Authorization.Destination != tc.want {
					t.Fatalf("audit=%+v", stream.Info.Authorization)
				}
			}
			wantLookups := 1
			if tc.upstream != "" || tc.host != "" {
				wantLookups = 0
			}
			if lookups != wantLookups {
				t.Fatalf("DNS lookups=%d, want %d", lookups, wantLookups)
			}
		})
	}
}

func TestSelectRandomCandidatePreservesFamily(t *testing.T) {
	v4a := netip.MustParseAddrPort("192.0.2.1:443")
	v4b := netip.MustParseAddrPort("192.0.2.2:443")
	v6a := netip.MustParseAddrPort("[2001:db8::1]:443")
	v6b := netip.MustParseAddrPort("[2001:db8::2]:443")
	for _, candidates := range [][]netip.AddrPort{
		{v4a, v6a, v4b, v6b},
		{v6a, v4a, v6b, v4b},
	} {
		seen := make(map[netip.AddrPort]bool)
		for range 128 {
			selected := selectRandomCandidate(candidates)
			if !slices.Contains(candidates, selected) || selected.Addr().Is4() != candidates[0].Addr().Is4() {
				t.Fatalf("selected %v outside preferred family of %v", selected, candidates)
			}
			seen[selected] = true
		}
		if len(seen) != 2 {
			t.Fatalf("selection stayed on one candidate: %v", seen)
		}
	}
}
