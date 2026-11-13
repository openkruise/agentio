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
	"net/netip"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/pkg/dns"
)

// Each request uses the production aggregate and reloadable authorizer, even with an empty rule chain.
func authHarness(t *testing.T, client *dns.Client, current *egressauthz.StaticAuthorizer) *enginetest.Harness {
	t.Helper()
	return enginetest.New(t, enginetest.Options{
		Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{}, nil
		},
		AuthorizeRequest: egressauthz.NewAggregate(client, current).Authorize,
	})
}

func authRequest(host string) *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", host, "/v1").Workload("default", "sandbox", nil)
}

func updateDenied(t *testing.T, current *egressauthz.StaticAuthorizer, cidrs ...string) {
	t.Helper()
	cfg := egressauthz.Config{}
	for _, cidr := range cidrs {
		cfg.DeniedCIDRs = append(cfg.DeniedCIDRs, netip.MustParsePrefix(cidr))
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	current.Update(cfg)
}

func requireDenied(t *testing.T, v *enginetest.Verdict) {
	t.Helper()
	v.RequireBlocked(t, 403)
	v.RequireNoUpstream(t)
	if v.ImmediateDetails != "epe_egress_denied" {
		t.Fatalf("unexpected denial reason: %q", v.ImmediateDetails)
	}
}

func TestScenario_EgressAuthzLiveRestrictionsOnCachedDNS(t *testing.T) {
	calls := 0
	client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		calls++
		return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: time.Minute}, nil
	}), time.Second)
	current := egressauthz.NewStaticAuthorizer(egressauthz.Config{})
	h := authHarness(t, client, current)
	h.Run(t, authRequest("api.example.com:443")).RequireUpstream(t, "192.0.2.1:443")
	updateDenied(t, current, "192.0.2.0/24")
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
	updateDenied(t, current)
	h.Run(t, authRequest("api.example.com:80")).RequireUpstream(t, "192.0.2.1:80")
	if calls != 1 {
		t.Fatalf("DNS calls=%d, want cached DNS across policy updates", calls)
	}
}

func TestScenario_EgressAuthzPinsOnlyAuthorizedCustomAddress(t *testing.T) {
	client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
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
	policy := egressauthz.NewStaticAuthorizer(egressauthz.Config{})
	updateDenied(t, policy, "192.0.2.1/32", "203.0.113.0/24")
	h := authHarness(t, client, policy)

	setRecord("192.0.2.1", "192.0.2.2")
	h.Run(t, authRequest("api.example.com:443")).RequireUpstream(t, "192.0.2.2:443")
	setRecord("192.0.2.3")
	h.Run(t, authRequest("api.example.com:443")).RequireUpstream(t, "192.0.2.3:443")
	setRecord("192.0.2.1", "203.0.113.1")
	requireDenied(t, h.Run(t, authRequest("api.example.com:443")))
}

func TestScenario_EgressAuthzChecksLiteralCONNECTDestination(t *testing.T) {
	client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("literal target must not query DNS")
	}), time.Second)
	policy := egressauthz.NewStaticAuthorizer(egressauthz.Config{})
	updateDenied(t, policy, "2001:db8:1::/48")
	h := authHarness(t, client, policy)
	request := func(port string) *enginetest.RequestBuilder {
		return enginetest.NewRequest("CONNECT", "[2001:db8::10]:"+port, "").
			Workload("default", "sandbox", nil)
	}
	h.Run(t, request("8443")).RequireUpstream(t, "[2001:db8::10]:8443")
	h.Run(t, request("443")).RequireUpstream(t, "[2001:db8::10]:443")
	requireDenied(
		t,
		h.Run(t, enginetest.NewRequest("CONNECT", "[2001:db8:1::10]:443", "").Workload("default", "sandbox", nil)),
	)
}

func TestScenario_EgressAuthzDNSFailureNeverEmitsTarget(t *testing.T) {
	client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("DNS unavailable")
	}), time.Second)
	policy := egressauthz.NewStaticAuthorizer(egressauthz.Config{})
	v := authHarness(t, client, policy).Run(t, authRequest("api.example.com:443"))
	v.RequireBlocked(t, 500)
	v.RequireNoUpstream(t)
	if v.ImmediateDetails != "epe_request_authorization_failed" {
		t.Fatalf("unexpected failure detail: %q", v.ImmediateDetails)
	}
}

func TestScenario_EgressAuthzLoadsCurrentPolicyAfterDNS(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	calls := 0
	client := dns.NewClient(dns.LookupFunc(func(ctx context.Context, _ string, _ dns.Family) (dns.LookupResult, error) {
		calls++
		close(started)
		select {
		case <-release:
			return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: time.Minute}, nil
		case <-ctx.Done():
			return dns.LookupResult{}, ctx.Err()
		}
	}), 5*time.Second)
	current := egressauthz.NewStaticAuthorizer(egressauthz.Config{})
	h := authHarness(t, client, current)
	stream := enginetest.NewScriptedStream(context.Background(), authRequest("api.example.com:443").Build()...)
	done := make(chan error, 1)
	go func() { done <- h.RunStream(t, stream) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("request completed before lookup: %v", err)
	}

	// Policies are loaded after DNS completes, so this request must use the update.
	updateDenied(t, current, "0.0.0.0/0")
	close(release)
	err := <-done
	v := enginetest.ParseVerdict(stream.Responses(), err)
	requireDenied(t, v)
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
	current := egressauthz.NewStaticAuthorizer(egressauthz.Config{})
	updateDenied(t, current, "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
	v := authHarness(t, client, current).Run(t, authRequest("api.example.com:443"))
	requireDenied(t, v)
	var body map[string]string
	if err := json.Unmarshal([]byte(v.ImmediateBody), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 3 || body["code"] != "epe_egress_denied" ||
		body["message"] != "Outbound destination is denied by policy." {
		t.Fatalf("unexpected public error: %v", body)
	}
	for _, response := range v.Raw {
		headers := response.GetImmediateResponse().GetHeaders()
		if len(headers.GetSetHeaders()) != 1 || headers.GetSetHeaders()[0].GetHeader().GetKey() != "content-type" ||
			len(headers.GetRemoveHeaders()) != 0 {
			t.Fatalf("unexpected denial headers: %v", headers)
		}
	}
}
