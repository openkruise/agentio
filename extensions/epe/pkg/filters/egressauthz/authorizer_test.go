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
	"net/netip"
	"slices"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/pkg/dns"
)

func TestGlobalDeniedCIDRs(t *testing.T) {
	global := Config{DeniedCIDRs: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
	}}
	allowAll := Config{}
	for _, tc := range []struct {
		name     string
		host     string
		ips      []netip.Addr
		upstream string
		original string
		want     string
	}{
		{name: "literal IPv4", host: "127.0.0.2"},
		{name: "literal IPv6", host: "::1"},
		{name: "mapped IPv4", host: "::ffff:127.0.0.1"},
		{name: "domain to loopback", host: "attacker.example", ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{name: "explicit route", host: "allowed.example", upstream: "127.0.0.1:15000"},
		{name: "mixed DNS", host: "mixed.example", ips: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, want: "192.0.2.1:15000"},
		{name: "denied original cannot fall back", host: "mixed.example", ips: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, original: "127.0.0.1:15000"},
		{name: "unmatched IPv4", host: "192.0.2.1", want: "192.0.2.1:15000"},
		{name: "unmatched IPv6", host: "2001:db8::1", want: "[2001:db8::1]:15000"},
	} {
		for _, extra := range []bool{false, true} {
			name := tc.name + "/static"
			authorizers := []Authorizer{NewStaticAuthorizer(global)}
			if extra {
				name = tc.name + "/additional-allow-all"
				authorizers = append(authorizers, NewStaticAuthorizer(allowAll))
			}
			t.Run(name, func(t *testing.T) {
				lookups := 0
				client := dns.NewClient(
					dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
						lookups++
						return dns.LookupResult{Addresses: tc.ips}, nil
					}),
					0,
				)
				stream := &filter.Stream{
					RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: tc.host, Port: 15000}},
					StreamRuntime:  filter.StreamRuntime{Info: filter.NewStreamInfo()},
				}
				if tc.upstream != "" {
					address := netip.MustParseAddrPort(tc.upstream)
					stream.Upstream = &filter.UpstreamTarget{Address: &address}
				}
				if tc.original != "" {
					stream.Request.OriginalDestination = netip.MustParseAddrPort(tc.original)
				}
				authorize := NewAggregate(client, authorizers...).Authorize
				target, reply, err := authorize(t.Context(), stream)
				if err != nil {
					t.Fatal(err)
				}
				if tc.want == "" {
					if target != nil || reply == nil || reply.Status != 403 {
						t.Fatalf("target=%v reply=%v", target, reply)
					}
					if stream.Info.Authorization.Policy != "EPEConfig/egressAuthorization" {
						t.Fatalf("audit=%+v", stream.Info.Authorization)
					}
				} else if reply != nil || target == nil || target.Address.String() != tc.want {
					t.Fatalf("target=%v reply=%v, want %s", target, reply, tc.want)
				}
				wantLookups := 0
				if tc.ips != nil {
					wantLookups = 1
				}
				if lookups != wantLookups {
					t.Fatalf("DNS lookups=%d, want %d", lookups, wantLookups)
				}
			})
		}
	}
}

func TestGlobalUpdateAndAdditionalRestrictions(t *testing.T) {
	denied := Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	global := NewStaticAuthorizer(denied)
	workload := Config{}
	client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{Addresses: []netip.Addr{
			netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1"),
		}}, nil
	}), 0)
	authorize := NewAggregate(
		client,
		global,
		authorizerFunc(
			func(ctx context.Context, stream *filter.Stream, candidates []netip.AddrPort) ([]netip.AddrPort, error) {
				// Publishing a new config cannot restore candidates already denied.
				global.Update(Config{})
				return workload.Authorize(ctx, stream, candidates)
			},
		),
	).Authorize
	request := func(host string) (*filter.UpstreamTarget, *filter.Reply, error) {
		return authorize(
			t.Context(),
			&filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: host, Port: 443}}},
		)
	}
	if target, reply, err := request("mixed.example"); err != nil || reply != nil || target == nil ||
		target.Address.String() != "192.0.2.1:443" {
		t.Fatalf("denied candidate restored: %v %v %v", target, reply, err)
	}
	if target, reply, err := request("127.0.0.1"); err != nil || reply != nil || target == nil ||
		target.Address.String() != "127.0.0.1:443" {
		t.Fatalf("update ignored: %v %v %v", target, reply, err)
	}
	global.Update(denied)
	workload.DeniedCIDRs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if target, reply, err := request("192.0.2.1"); err != nil || reply == nil || target != nil {
		t.Fatalf("workload restriction bypassed: %v %v %v", target, reply, err)
	}
}

type authorizerFunc func(context.Context, *filter.Stream, []netip.AddrPort) ([]netip.AddrPort, error)

func TestCandidatesSkipRequestPolicyAndFinalAuthorizationInvokesItOnce(t *testing.T) {
	private := netip.MustParseAddrPort("10.1.2.3:443")
	public := netip.MustParseAddrPort("203.0.113.8:443")
	loadErr := errors.New("policy unavailable")
	for _, outcome := range []string{"allow", "deny", "error", "common-deny"} {
		t.Run(outcome, func(t *testing.T) {
			cfg := Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
			if outcome == "common-deny" {
				cfg.DeniedCIDRs = append(cfg.DeniedCIDRs, netip.MustParsePrefix("0.0.0.0/0"))
			}
			client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
				return dns.LookupResult{Addresses: []netip.Addr{private.Addr(), public.Addr()}}, nil
			}), 0)
			calls := 0
			stream := &filter.Stream{
				RequestContext: filter.RequestContext{
					Request: httpreq.HTTPRequest{Host: "mixed.example", Port: 443},
					Policies: filter.PolicySnapshot{
						DestinationAuthorizer: authorizerFunc(
							func(_ context.Context, _ *filter.Stream, candidates []netip.AddrPort) ([]netip.AddrPort, error) {
								calls++
								if !slices.Equal(candidates, []netip.AddrPort{public}) {
									t.Fatalf("request policy candidates=%v, want only %v", candidates, public)
								}
								if outcome == "error" {
									return nil, loadErr
								}
								if outcome == "deny" {
									return nil, nil
								}
								return candidates, nil
							},
						),
					},
				},
				StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
			}
			a := NewAggregate(client, cfg)
			candidates, err := a.Candidates(t.Context(), stream)
			if err != nil || calls != 0 {
				t.Fatalf("candidates invoked request policy: calls=%d err=%v", calls, err)
			}
			if outcome != "common-deny" && !slices.Equal(candidates, []netip.AddrPort{public}) {
				t.Fatalf("common restrictions not applied: %v", candidates)
			}
			target, reply, err := a.Authorize(t.Context(), stream)
			wantCalls := 1
			if outcome == "common-deny" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("request policy calls=%d, want %d", calls, wantCalls)
			}
			switch outcome {
			case "allow":
				if err != nil || reply != nil || target == nil || *target.Address != public {
					t.Fatalf("target=%v reply=%v err=%v", target, reply, err)
				}
			case "deny", "common-deny":
				if err != nil || target != nil || reply == nil || reply.Status != 403 {
					t.Fatalf("target=%v reply=%v err=%v", target, reply, err)
				}
			case "error":
				if !errors.Is(err, loadErr) || target != nil || reply != nil ||
					stream.Info.Authorization.Reason != filter.AuthorizationReasonPolicyLoadFailed {
					t.Fatalf("target=%v reply=%v err=%v audit=%+v", target, reply, err, stream.Info.Authorization)
				}
			}
		})
	}
}

func (f authorizerFunc) Authorize(
	ctx context.Context,
	stream *filter.Stream,
	candidates []netip.AddrPort,
) ([]netip.AddrPort, error) {
	return f(ctx, stream, candidates)
}

func TestAggregateRequiresCommonCandidate(t *testing.T) {
	ips := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
	}
	for _, tc := range []struct {
		name            string
		allowed         [][]int
		want            []string
		candidateCounts []int
	}{
		{
			name:            "three authorizers share only the last candidate",
			allowed:         [][]int{{1, 2}, {0, 2}, {2}},
			want:            []string{"192.0.2.3:443"},
			candidateCounts: []int{3, 2, 1},
		},
		{
			name:            "individual allows do not imply a common allowed IP",
			allowed:         [][]int{{0}, {1}},
			candidateCounts: []int{3, 1},
		},
		{
			name: "empty aggregate still pins a destination",
			want: []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := make([]int, len(tc.allowed))
			authorizers := make([]Authorizer, 0, len(tc.allowed))
			for i, allowed := range tc.allowed {
				cfg := Config{}
				for j, ip := range ips {
					if !slices.Contains(allowed, j) {
						cfg.DeniedCIDRs = append(cfg.DeniedCIDRs, netip.PrefixFrom(ip, 32))
					}
				}
				authorizers = append(authorizers, authorizerFunc(
					func(ctx context.Context, stream *filter.Stream, candidates []netip.AddrPort) ([]netip.AddrPort, error) {
						calls[i]++
						if len(candidates) != tc.candidateCounts[i] {
							t.Fatalf("authorizer %d: candidates=%d, want %d", i, len(candidates), tc.candidateCounts[i])
						}
						return cfg.Authorize(ctx, stream, candidates)
					},
				))
			}
			lookups := 0
			client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
				lookups++
				return dns.LookupResult{Addresses: ips}, nil
			}), 0)
			stream := &filter.Stream{
				RequestContext: filter.RequestContext{
					Request: httpreq.HTTPRequest{Host: "multiple.example", Port: 443},
				},
				StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
			}
			target, reply, err := NewAggregate(client, authorizers...).Authorize(t.Context(), stream)
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.want) == 0 {
				if reply == nil || reply.Status != 403 || target != nil {
					t.Fatalf("target=%v reply=%v", target, reply)
				}
			} else if reply != nil || target == nil || !slices.Contains(tc.want, target.Address.String()) {
				t.Fatalf("target=%v reply=%v, want %v", target, reply, tc.want)
			}
			if lookups != 1 {
				t.Fatalf("DNS lookups=%d, want 1", lookups)
			}
			for i, count := range calls {
				if count != 1 {
					t.Fatalf("authorizer %d: calls=%d, want 1", i, count)
				}
			}
		})
	}
}

func TestAggregateStopsAfterDenialOrError(t *testing.T) {
	failure := errors.New("policy unavailable")
	for _, tc := range []struct {
		name    string
		first   Authorizer
		wantErr error
		reason  string
	}{
		{
			name:   "global denial skips workload policy loading",
			first:  NewStaticAuthorizer(Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}),
			reason: filter.AuthorizationReasonPolicyDenied,
		},
		{
			name: "authorizer error stops the chain",
			first: authorizerFunc(func(context.Context, *filter.Stream, []netip.AddrPort) ([]netip.AddrPort, error) {
				return nil, failure
			}),
			wantErr: failure,
			reason:  filter.AuthorizationReasonPolicyLoadFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAggregate(dns.NewClient(nil, 0), tc.first,
				authorizerFunc(func(context.Context, *filter.Stream, []netip.AddrPort) ([]netip.AddrPort, error) {
					t.Fatal("later authorizers must not run after a denial or error")
					return nil, nil
				}))
			stream := &filter.Stream{
				RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: "127.0.0.1", Port: 443}},
				StreamRuntime:  filter.StreamRuntime{Info: filter.NewStreamInfo()},
			}
			target, reply, err := a.Authorize(t.Context(), stream)
			if !errors.Is(err, tc.wantErr) || target != nil {
				t.Fatalf("target=%v reply=%v err=%v", target, reply, err)
			}
			if tc.wantErr == nil {
				if reply == nil || reply.Status != 403 {
					t.Fatalf("reply=%v, want denial", reply)
				}
			} else if reply != nil {
				t.Fatalf("reply=%v, want error only", reply)
			}
			if stream.Info.Authorization.Reason != tc.reason {
				t.Fatalf("audit=%+v", stream.Info.Authorization)
			}
		})
	}
}

func TestAggregateAuditsSelectedCandidate(t *testing.T) {
	client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{Addresses: []netip.Addr{
			netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
		}}, nil
	}), 0)
	cfg := authorizerFunc(
		func(_ context.Context, stream *filter.Stream, candidates []netip.AddrPort) ([]netip.AddrPort, error) {
			for i, target := range candidates {
				stream.Info.RecordAuthorizationMatch(target, "workload", i)
			}
			return candidates, nil
		},
	)
	for _, tc := range []struct {
		name   string
		next   Authorizer
		want   map[string]int
		policy string
	}{
		{
			name:   "no policy preserves selected candidate match",
			next:   Config{},
			want:   map[string]int{"192.0.2.1:443": 0, "192.0.2.2:443": 1},
			policy: "workload",
		},
		{
			name:   "later filter selects second candidate match",
			next:   Config{DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}},
			want:   map[string]int{"192.0.2.2:443": 1},
			policy: "workload",
		},
		{
			name: "later matching rule replaces earlier match",
			next: authorizerFunc(func(_ context.Context, stream *filter.Stream, candidates []netip.AddrPort) ([]netip.AddrPort, error) {
				for _, target := range candidates {
					stream.Info.RecordAuthorizationMatch(target, "later-policy", 0)
				}
				return candidates, nil
			}),
			want:   map[string]int{"192.0.2.1:443": 0, "192.0.2.2:443": 0},
			policy: "later-policy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[string]bool)
			for range 128 {
				stream := &filter.Stream{
					RequestContext: filter.RequestContext{
						Request: httpreq.HTTPRequest{Host: "multiple.example", Port: 443},
					},
					StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
				}
				target, reply, err := NewAggregate(client, cfg, tc.next).Authorize(t.Context(), stream)
				if err != nil || reply != nil || target == nil {
					t.Fatalf("target=%v reply=%v err=%v", target, reply, err)
				}
				rule, ok := tc.want[target.Address.String()]
				if !ok {
					t.Fatalf("unexpected target: %v", target.Address)
				}
				seen[target.Address.String()] = true
				audit := stream.Info.Authorization
				if audit.Destination != target.Address.String() || audit.Policy != tc.policy ||
					audit.RuleIndex == nil || *audit.RuleIndex != rule || audit.Action != "allow" {
					t.Fatalf("audit=%+v", audit)
				}
			}
			if len(seen) != len(tc.want) {
				t.Fatalf("selection did not cover allowed candidates: %v", seen)
			}
		})
	}
}
