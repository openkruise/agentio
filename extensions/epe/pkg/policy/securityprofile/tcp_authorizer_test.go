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

package securityprofile

import (
	"context"
	"net/netip"
	"testing"
	"time"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/dns"
)

func TestHTTPAndTCPProfilePriority(t *testing.T) {
	regs, err := filter.Build(block.Definition(), bypass.Definition())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		firstTCP    securityv1.TCPAction
		cidr        string
		firstHTTP   bool
		lowerBypass bool
		want        engine.Disposition
	}{
		{name: "high TCP deny before lower HTTP bypass", firstTCP: securityv1.TCPAction_TCP_ACTION_DENY, cidr: "0.0.0.0/0", lowerBypass: true, want: engine.DispositionBlocked},
		{name: "high TCP allow before lower HTTP block", firstTCP: securityv1.TCPAction_TCP_ACTION_ALLOW, cidr: "0.0.0.0/0", want: engine.DispositionBypassed},
		{name: "lower HTTP bypass skips own TCP deny", firstTCP: securityv1.TCPAction_TCP_ACTION_DENY, cidr: "10.0.0.0/8", lowerBypass: true, want: engine.DispositionBypassed},
		{name: "no TCP match continues to lower HTTP block", firstTCP: securityv1.TCPAction_TCP_ACTION_DENY, cidr: "10.0.0.0/8", want: engine.DispositionBlocked},
		{name: "same profile HTTP block before TCP allow", firstTCP: securityv1.TCPAction_TCP_ACTION_ALLOW, cidr: "0.0.0.0/0", firstHTTP: true, want: engine.DispositionBlocked},
		{name: "high HTTP block before lower HTTP bypass", firstTCP: securityv1.TCPAction_TCP_ACTION_DENY, cidr: "10.0.0.0/8", firstHTTP: true, lowerBypass: true, want: engine.DispositionBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var firstRules []agents.SecurityRule
			if tc.firstHTTP {
				firstRules = []agents.SecurityRule{matchAllRule("earlier-http")}
			}
			a := compile(t, regs, "a", "ns", "1", firstRules)
			bRule := matchAllRule("lower-http")
			if tc.lowerBypass {
				bRule.Actions = agents.SecurityRuleActions{Bypass: true}
			}
			b := compile(t, regs, "b", "ns", "1", []agents.SecurityRule{bRule})
			a.Meta.SourceIdentity.UID = "a"
			b.Meta.SourceIdentity.UID = "b"
			a.TCPPolicy = &securityv1.TCPPolicy{
				Rules: []*securityv1.TCPRule{
					{Name: "first", Action: tc.firstTCP, Match: []*securityv1.TCPMatch{{Cidrs: []string{tc.cidr}}}},
				},
			}
			b.TCPPolicy = &securityv1.TCPPolicy{
				Rules: []*securityv1.TCPRule{
					{Name: "own-deny", Action: securityv1.TCPAction_TCP_ACTION_DENY, Match: []*securityv1.TCPMatch{{}}},
				},
			}
			req := testRequest("203.0.113.8")
			req.Port = 443
			req.Scheme = "https"
			targets := egressauthz.NewAggregate(dns.NewClient(nil, 0))
			resolve := NewResolver(benchStore{profiles: []*Profile{a, b}}, regs, nil, targets)
			resolution, err := resolve(t.Context(), subject.Subject{}, req)
			if err != nil {
				t.Fatal(err)
			}
			stream := &filter.Stream{
				RequestContext: filter.RequestContext{
					Request:  *req,
					Policies: filter.PolicySnapshot{DestinationAuthorizer: resolution.DestinationAuthorizer},
				},
			}
			result, err := engine.NewEngine(regs, 0).EvalRequestHeaders(t.Context(), stream, resolution.Units)
			if err != nil {
				t.Fatal(err)
			}
			if result.Disposition != tc.want {
				t.Fatalf("disposition=%v want=%v", result.Disposition, tc.want)
			}
			if tc.want == engine.DispositionBypassed {
				_, reply, err := targets.Authorize(t.Context(), stream)
				if err != nil || reply != nil {
					t.Fatalf("final authorization: reply=%v err=%v", reply, err)
				}
			}
		})
	}
}

func TestTCPCheckpointKeepsEarlierRestrictionsAfterTargetChange(t *testing.T) {
	profiles := []*Profile{
		{TCPPolicy: &securityv1.TCPPolicy{Rules: []*securityv1.TCPRule{{
			Match:  []*securityv1.TCPMatch{{Cidrs: []string{"10.0.0.0/8"}}},
			Action: securityv1.TCPAction_TCP_ACTION_DENY,
		}}}},
		{TCPPolicy: &securityv1.TCPPolicy{Rules: []*securityv1.TCPRule{{
			Match:  []*securityv1.TCPMatch{{Cidrs: []string{"0.0.0.0/0"}}},
			Action: securityv1.TCPAction_TCP_ACTION_ALLOW,
		}}}},
	}
	a := &tcpAuthorizer{profiles: profiles}
	stream := &filter.Stream{RequestContext: filter.RequestContext{
		Request:  httpreq.HTTPRequest{Host: "203.0.113.8", Port: 443},
		Policies: filter.PolicySnapshot{DestinationAuthorizer: a},
	}}
	targets := egressauthz.NewAggregate(dns.NewClient(nil, 0))
	action, err := a.checkpoint(0, targets)(t.Context(), stream)
	if err != nil || action.Kind() != filter.KindContinue {
		t.Fatalf("first checkpoint: action=%v err=%v", action.Kind(), err)
	}
	stream.Request.Host = "10.1.2.3"
	// A lower HTTP bypass must still reauthorize the previously visited prefix.
	_, reply, err := targets.Authorize(t.Context(), stream)
	if err != nil || reply == nil || reply.Status != 403 {
		t.Fatalf("rewritten target: reply=%v err=%v", reply, err)
	}
	// A lower TCP allow must not restore a candidate rejected by that prefix.
	action, err = a.checkpoint(1, targets)(t.Context(), stream)
	if err != nil || action.Kind() != filter.KindStop {
		t.Fatalf("second checkpoint: action=%v err=%v", action.Kind(), err)
	}
}

func TestTCPReauthorizationRecordsAllowMatchAfterTargetChange(t *testing.T) {
	profile := compile(t, nil, "higher", "ns", "1", nil)
	profile.TCPPolicy = &securityv1.TCPPolicy{Rules: []*securityv1.TCPRule{
		{
			Name:   "deny-test-net",
			Action: securityv1.TCPAction_TCP_ACTION_DENY,
			Match:  []*securityv1.TCPMatch{{Cidrs: []string{"192.0.2.0/24"}}},
		},
		{
			Name:   "allow-private",
			Action: securityv1.TCPAction_TCP_ACTION_ALLOW,
			Match:  []*securityv1.TCPMatch{{Cidrs: []string{"10.0.0.0/8"}}},
		},
	}}
	a := &tcpAuthorizer{profiles: []*Profile{profile}}
	stream := &filter.Stream{RequestContext: filter.RequestContext{
		Request:  httpreq.HTTPRequest{Host: "203.0.113.8", Port: 443},
		Policies: filter.PolicySnapshot{DestinationAuthorizer: a},
	}}
	stream.Info = &filter.StreamInfo{}
	targets := egressauthz.NewAggregate(dns.NewClient(nil, 0))
	action, err := a.checkpoint(0, targets)(t.Context(), stream)
	if err != nil || action.Kind() != filter.KindContinue {
		t.Fatalf("initial checkpoint: action=%v err=%v", action.Kind(), err)
	}
	rewritten := netip.MustParseAddrPort("10.1.2.3:443")
	stream.Upstream = &filter.UpstreamTarget{Address: &rewritten}
	upstream, reply, err := targets.Authorize(t.Context(), stream)
	if err != nil || reply != nil || upstream == nil || *upstream.Address != rewritten {
		t.Fatalf("rewritten target: upstream=%v reply=%v err=%v", upstream, reply, err)
	}
	record := stream.Info.Authorization
	if record == nil || record.Action != "allow" || record.Destination != rewritten.String() ||
		record.Policy != profile.ResourceName() || record.RuleIndex == nil || *record.RuleIndex != 1 {
		t.Fatalf("authorization=%+v, want allow from %s rule 1 for %s", record, profile.ResourceName(), rewritten)
	}
}

func TestTCPCheckpointFiltersDNSCandidatesAndPreservesOriginalTarget(t *testing.T) {
	private := netip.MustParseAddrPort("10.1.2.3:443")
	public := netip.MustParseAddrPort("203.0.113.8:443")
	for _, original := range []netip.AddrPort{{}, private, public} {
		t.Run(original.String(), func(t *testing.T) {
			client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
				return dns.LookupResult{Addresses: []netip.Addr{private.Addr(), public.Addr()}, TTL: time.Minute}, nil
			}), 0)
			a := &tcpAuthorizer{profiles: []*Profile{{TCPPolicy: &securityv1.TCPPolicy{Rules: []*securityv1.TCPRule{{
				Match:  []*securityv1.TCPMatch{{Cidrs: []string{"10.0.0.0/8"}}},
				Action: securityv1.TCPAction_TCP_ACTION_DENY,
			}}}}}}
			stream := &filter.Stream{RequestContext: filter.RequestContext{
				Request:  httpreq.HTTPRequest{Host: "api.example.com", Port: 443, OriginalDestination: original},
				Policies: filter.PolicySnapshot{DestinationAuthorizer: a},
			}}
			targets := egressauthz.NewAggregate(client)
			action, err := a.checkpoint(0, targets)(t.Context(), stream)
			if err != nil {
				t.Fatal(err)
			}
			if original == private {
				if action.Kind() != filter.KindStop {
					t.Fatal("denied original target fell back to another DNS address")
				}
				return
			}
			if action.Kind() != filter.KindContinue {
				t.Fatalf("action=%v, want continue to the next SP", action.Kind())
			}
			upstream, reply, err := targets.Authorize(t.Context(), stream)
			if err != nil || reply != nil || upstream == nil || *upstream.Address != public {
				t.Fatalf("upstream=%v reply=%v err=%v", upstream, reply, err)
			}
		})
	}
}

func TestTCPCheckpointMixedDNSDecisions(t *testing.T) {
	private := netip.MustParseAddr("10.1.2.3")
	public := netip.MustParseAddr("203.0.113.8")
	for _, tc := range []struct {
		name  string
		rules []*securityv1.TCPRule
		want  filter.ActionKind
	}{
		{name: "deny plus unmatched continues", rules: []*securityv1.TCPRule{{Action: securityv1.TCPAction_TCP_ACTION_DENY, Match: []*securityv1.TCPMatch{{Cidrs: []string{"10.0.0.0/8"}}}}}, want: filter.KindContinue},
		{name: "allow plus unmatched bypasses", rules: []*securityv1.TCPRule{{Action: securityv1.TCPAction_TCP_ACTION_ALLOW, Match: []*securityv1.TCPMatch{{Cidrs: []string{"203.0.113.0/24"}}}}}, want: filter.KindBypass},
		{name: "deny plus allow bypasses",
			rules: []*securityv1.TCPRule{
				{Action: securityv1.TCPAction_TCP_ACTION_DENY, Match: []*securityv1.TCPMatch{{Cidrs: []string{"10.0.0.0/8"}}}},
				{Action: securityv1.TCPAction_TCP_ACTION_ALLOW, Match: []*securityv1.TCPMatch{{}}},
			},
			want: filter.KindBypass},
		{name: "all denied stops", rules: []*securityv1.TCPRule{{Action: securityv1.TCPAction_TCP_ACTION_DENY, Match: []*securityv1.TCPMatch{{}}}}, want: filter.KindStop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
				return dns.LookupResult{Addresses: []netip.Addr{private, public}}, nil
			}), 0)
			a := &tcpAuthorizer{profiles: []*Profile{{TCPPolicy: &securityv1.TCPPolicy{Rules: tc.rules}}}}
			stream := &filter.Stream{RequestContext: filter.RequestContext{
				Request:  httpreq.HTTPRequest{Host: "mixed.example", Port: 443},
				Policies: filter.PolicySnapshot{DestinationAuthorizer: a},
			}}
			action, err := a.checkpoint(0, egressauthz.NewAggregate(client))(t.Context(), stream)
			if err != nil || action.Kind() != tc.want {
				t.Fatalf("action=%v want=%v err=%v", action.Kind(), tc.want, err)
			}
			if tc.want == filter.KindBypass {
				mutations := action.Mutations()
				if len(mutations) != 1 || *mutations[0].Route.Upstream.Address != netip.AddrPortFrom(public, 443) {
					t.Fatalf("bypass did not pin the explicitly allowed address: %+v", mutations)
				}
			}
		})
	}
}
