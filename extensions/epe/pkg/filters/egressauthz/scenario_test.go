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

package egressauthz_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/pkg/dns"
)

// The caller owns publication; each request resolver loads exactly one Config
// and always mounts egressauthz, including when the policy list is empty.
// This is intentionally test-side wiring, not an update API in the filter.
func authHarness(t *testing.T, client *dns.Client, current *atomic.Pointer[egressauthz.Config]) *enginetest.Harness {
	t.Helper()
	regs, err := filter.Build(filter.Define(egressauthz.Descriptor(client),
		func(json.RawMessage) (egressauthz.Config, error) { return egressauthz.Config{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	return enginetest.New(t, enginetest.Options{
		Registrations: regs,
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			cfg := current.Load()
			if cfg == nil {
				return engine.Resolution{}, fmt.Errorf("egress policy snapshot is not ready")
			}
			return engine.Resolution{Units: []engine.Unit{{
				ID:   filter.UnitID{Scope: "default/egress", Name: "authorize"},
				Cfgs: []any{*cfg},
			}}}, nil
		},
	})
}

func authRequest(host string) *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", host, "/v1").Peer("default", "sandbox", nil)
}

func authRule(action egressauthz.Action, cidr string, port uint16) egressauthz.Rule {
	return egressauthz.Rule{
		Action: action,
		CIDRs:  []netip.Prefix{netip.MustParsePrefix(cidr)},
		Ports:  []egressauthz.PortRange{{Start: port}},
	}
}

func updateRules(t *testing.T, current *atomic.Pointer[egressauthz.Config], rules ...egressauthz.Rule) {
	t.Helper()
	publishPolicies(t, current, egressauthz.Policy{Name: "test", Rules: rules})
}

func publishPolicies(t *testing.T, current *atomic.Pointer[egressauthz.Config], policies ...egressauthz.Policy) {
	t.Helper()
	cfg := &egressauthz.Config{Policies: policies}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	current.Store(cfg)
}

func requireDenied(t *testing.T, v *enginetest.Verdict) {
	t.Helper()
	v.RequireBlocked(t, 403)
	v.RequireNoUpstream(t)
	if v.ImmediateDetails != "epe_egress_denied" {
		t.Fatalf("unexpected denial reason: %q", v.ImmediateDetails)
	}
}

type scenarioLookup func(context.Context, string, dns.Family) (dns.LookupResult, error)

func (f scenarioLookup) Lookup(ctx context.Context, host string, family dns.Family) (dns.LookupResult, error) {
	return f(ctx, host, family)
}

func TestScenario_EgressAuthzFirstMatchAndLiveReordering(t *testing.T) {
	calls := 0
	client := dns.NewClient(scenarioLookup(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		calls++
		return dns.LookupResult{
			Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			TTL:       time.Minute,
		}, nil
	}), time.Second)
	policy := &atomic.Pointer[egressauthz.Config]{}
	allow := authRule(egressauthz.Allow, "192.0.2.0/24", 443)
	deny := authRule(egressauthz.Deny, "192.0.2.1/32", 443)
	updateRules(t, policy, allow, deny)
	h := authHarness(t, client, policy)

	// The broad Allow wins because it comes first, even though a later Deny
	// matches the same destination more specifically.
	v := h.Run(t, authRequest("api.example.com:443"))
	response := v.RequireUpstream(t, "192.0.2.1:443")
	v.RequireOutcome(t, "mutated")
	if response.GetRequestHeaders().GetResponse().GetClearRouteCache() || len(v.RequestHeaderOps) != 0 {
		t.Fatal("authorization unexpectedly changed request headers or route cache")
	}

	// Same server, caller snapshot source and cached DNS answer; only rule order changes.
	updateRules(t, policy, deny, allow)
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))

	// A non-matching port must not inherit a previous request's authorization.
	updateRules(t, policy, allow, deny)
	requireDenied(t, h.Run(t, authRequest("api.example.com:80")))
	updateRules(t, policy)
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
	if calls != 1 {
		t.Fatalf("DNS calls=%d, want 1; policy changes must apply on cache hits", calls)
	}
}

func TestScenario_EgressAuthzPinsOnlyAuthorizedCustomAddress(t *testing.T) {
	client := dns.NewClient(scenarioLookup(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("unexpected DNS lookup")
	}), time.Second)
	setRecord := func(addresses ...string) {
		t.Helper()
		ips := make([]netip.Addr, len(addresses))
		for i, address := range addresses {
			ips[i] = netip.MustParseAddr(address)
		}
		if err := client.SetRecord("api.example.com", ips); err != nil {
			t.Fatal(err)
		}
	}
	policy := &atomic.Pointer[egressauthz.Config]{}
	updateRules(t, policy,
		authRule(egressauthz.Deny, "192.0.2.1/32", 443),
		authRule(egressauthz.Allow, "192.0.2.0/24", 443),
	)
	h := authHarness(t, client, policy)

	setRecord("192.0.2.1", "192.0.2.2")
	h.Run(t, authRequest("api.example.com:443")).RequireUpstream(t, "192.0.2.2:443")
	setRecord("192.0.2.3")
	h.Run(t, authRequest("api.example.com:443")).RequireUpstream(t, "192.0.2.3:443")
	setRecord("192.0.2.1", "203.0.113.1")
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
}

func TestScenario_EgressAuthzChecksLiteralCONNECTDestination(t *testing.T) {
	client := dns.NewClient(scenarioLookup(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("literal target must not query DNS")
	}), time.Second)
	policy := &atomic.Pointer[egressauthz.Config]{}
	updateRules(t, policy, authRule(egressauthz.Allow, "2001:db8::/32", 8443))
	h := authHarness(t, client, policy)
	request := func(port string) *enginetest.RequestBuilder {
		return enginetest.NewRequest("CONNECT", "[2001:db8::10]:"+port, "").
			Peer("default", "sandbox", nil)
	}
	h.Run(t, request("8443")).RequireUpstream(t, "[2001:db8::10]:8443")
	requireDenied(t, h.Run(t, request("443")))
}

func TestScenario_EgressAuthzReplacesCallerPolicySnapshots(t *testing.T) {
	client := dns.NewClient(scenarioLookup(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("unexpected DNS lookup")
	}), time.Second)
	if err := client.SetRecord("api.example.com", []netip.Addr{netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	skip := egressauthz.Policy{Name: "TrafficPolicy/team/unrelated", Rules: []egressauthz.Rule{
		authRule(egressauthz.Deny, "203.0.113.0/24", 443),
	}}
	team := egressauthz.Policy{Name: "TrafficPolicy/team/api", Rules: []egressauthz.Rule{
		authRule(egressauthz.Allow, "192.0.2.1/32", 443),
		authRule(egressauthz.Deny, "192.0.2.0/24", 443),
	}}
	global := egressauthz.Policy{Name: "GlobalTrafficPolicy/default", Rules: []egressauthz.Rule{
		authRule(egressauthz.Deny, "0.0.0.0/0", 443),
	}}
	current := &atomic.Pointer[egressauthz.Config]{}
	publishPolicies(t, current, skip, team, global)
	h := authHarness(t, client, current)
	h.Run(t, authRequest("api.example.com:443")).RequireUpstream(t, "192.0.2.1:443")

	denyTeam := egressauthz.Policy{Name: team.Name, Rules: team.Rules[1:]}
	publishPolicies(t, current, skip, denyTeam, global)
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
	publishPolicies(t, current, skip, team, global)
	h.Run(t, authRequest("api.example.com:443")).RequireUpstream(t, "192.0.2.1:443")

	// Removal and ordering are entirely caller-owned.
	publishPolicies(t, current, skip, global)
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
	publishPolicies(t, current, global, team)
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
	publishPolicies(t, current, team)
	h.Run(t, authRequest("api.example.com:443")).RequireUpstream(t, "192.0.2.1:443")
	publishPolicies(t, current)
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
}

func TestScenario_EgressAuthzFailuresNeverEmitTarget(t *testing.T) {
	client := dns.NewClient(scenarioLookup(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("DNS unavailable")
	}), time.Second)
	policy := &atomic.Pointer[egressauthz.Config]{}
	updateRules(t, policy, authRule(egressauthz.Allow, "0.0.0.0/0", 443))
	for _, tc := range []struct {
		name string
		cfg  egressauthz.Config
	}{
		{"DNS failure", *policy.Load()},
		{"invalid policy", egressauthz.Config{Policies: []egressauthz.Policy{{Name: ""}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := &atomic.Pointer[egressauthz.Config]{}
			current.Store(&tc.cfg)
			v := authHarness(t, client, current).Run(t, authRequest("api.example.com:443"))
			v.RequireBlocked(t, 500)
			v.RequireNoUpstream(t)
			if v.ImmediateDetails != "epe_request_headers_failed_closed" {
				t.Fatalf("unexpected failure detail: %q", v.ImmediateDetails)
			}
		})
	}
}

func TestScenario_EgressAuthzInFlightRequestKeepsSnapshot(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	calls := 0
	client := dns.NewClient(scenarioLookup(func(ctx context.Context, _ string, _ dns.Family) (dns.LookupResult, error) {
		calls++
		close(started)
		select {
		case <-release:
			return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: time.Minute}, nil
		case <-ctx.Done():
			return dns.LookupResult{}, ctx.Err()
		}
	}), 5*time.Second)
	current := &atomic.Pointer[egressauthz.Config]{}
	updateRules(t, current, authRule(egressauthz.Allow, "192.0.2.0/24", 443))
	h := authHarness(t, client, current)
	stream := enginetest.NewScriptedStream(context.Background(), authRequest("api.example.com:443").Build()...)
	done := make(chan error, 1)
	go func() { done <- h.RunStream(t, stream) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("request completed before lookup: %v", err)
	}

	// Publish a separate object; never mutate the old request's Config or slices.
	current.Store(&egressauthz.Config{})
	close(release)
	err := <-done
	v := enginetest.ParseVerdict(stream.Responses(), err)
	v.RequireUpstream(t, "192.0.2.1:443")
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
	if calls != 1 {
		t.Fatalf("DNS calls=%d, want cache hit on the next request", calls)
	}
}

func TestScenario_EgressAuthzDenialHasNoPolicyPayload(t *testing.T) {
	client := dns.NewClient(nil, time.Second)
	if err := client.SetRecord("api.example.com", []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("203.0.113.1"),
	}); err != nil {
		t.Fatal(err)
	}
	current := &atomic.Pointer[egressauthz.Config]{}
	publishPolicies(t, current,
		egressauthz.Policy{Name: "TrafficPolicy/team/first", Rules: []egressauthz.Rule{
			authRule(egressauthz.Allow, "192.0.2.0/24", 80),
			authRule(egressauthz.Deny, "192.0.2.0/24", 443),
		}},
		egressauthz.Policy{Name: "GlobalTrafficPolicy/second", Rules: []egressauthz.Rule{
			authRule(egressauthz.Deny, "198.51.100.0/24", 443),
		}},
	)
	v := authHarness(t, client, current).Run(t, authRequest("api.example.com:443"))
	requireDenied(t, v)
	if v.ImmediateBody != "" {
		t.Fatalf("denial must have no body: %q", v.ImmediateBody)
	}
	for _, response := range v.Raw {
		if headers := response.GetImmediateResponse().GetHeaders(); len(headers.GetSetHeaders()) != 0 || len(headers.GetRemoveHeaders()) != 0 {
			t.Fatalf("denial must not add policy headers: %v", headers)
		}
	}
}
