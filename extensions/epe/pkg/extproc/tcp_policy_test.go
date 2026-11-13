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

package extproc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/dns"
)

func TestSecurityProfileTCPFallthroughAfterHTTPRules(t *testing.T) {
	regs, err := filter.Build(bypass.Definition(), block.Definition(), headermutation.Definition())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		action    agents.SecurityRuleActions
		tcpAction agents.TCPActionType
		global    bool
		status    int
	}{
		{name: "empty HTTP rules", tcpAction: agents.TCPActionDeny, status: 403},
		{name: "mutation falls through", action: agents.SecurityRuleActions{HeaderManipulation: &agents.HeaderManipulationAction{Set: []agents.HeaderValue{{Name: "x-token", Value: "injected"}}}}, tcpAction: agents.TCPActionDeny, status: 403},
		{name: "bypass skips TCP deny", action: agents.SecurityRuleActions{Bypass: true}, tcpAction: agents.TCPActionDeny},
		{name: "block wins over TCP allow", action: agents.SecurityRuleActions{Block: &agents.BlockAction{StatusCode: 451}}, tcpAction: agents.TCPActionAllow, status: 451},
		{name: "bypass preserves platform deny", action: agents.SecurityRuleActions{Bypass: true}, tcpAction: agents.TCPActionDeny, global: true, status: 403},
		{name: "TCP allow pins address", tcpAction: agents.TCPActionAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := profilestore.MakeFakeStore(regs...)
			spec := agents.SecurityProfileSpec{
				TCPRules: []agents.TCPRule{
					{
						Name:   "target",
						Action: tc.tcpAction,
						Match:  []agents.TCPMatch{{CIDRs: []string{"10.0.0.0/8"}, Ports: []int32{443}}},
					},
				},
			}
			if tc.action.Bypass || tc.action.Block != nil || tc.action.HeaderManipulation != nil {
				spec.Rules = []agents.SecurityRule{
					{Name: "http", Match: []agents.RuleMatch{{Domains: []string{"*"}}}, Actions: tc.action},
				}
			}
			store.ProfileSet(
				&agents.SecurityProfile{ObjectMeta: metav1.ObjectMeta{Name: "profile", Namespace: "ns"}, Spec: spec},
			)
			global := egressauthz.Config{}
			if tc.global {
				global.DeniedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
			}
			targets := egressauthz.NewAggregate(dns.NewClient(nil, 0), egressauthz.NewStaticAuthorizer(global))
			srv := NewServer(ServerDeps{
				Registrations:    regs,
				Resolve:          securityprofile.NewResolver(store, regs, nil, targets),
				AuthorizeRequest: targets.Authorize,
			})
			state := newStreamState()
			headers := makeRequestHeaders("10.1.2.3:443", "/", "GET")
			responses, err := srv.HandleRequestHeaders(
				t.Context(),
				headers,
				makeAttrsWithLabels("ns", "pod", ""),
				state,
			)
			if err != nil {
				t.Fatal(err)
			}
			if tc.status != 0 {
				if got := int(responses[0].GetImmediateResponse().GetStatus().GetCode()); got != tc.status {
					t.Fatalf("status=%d, want %d: %v", got, tc.status, responses)
				}
			} else if got := responseUpstream(responses[0]).GetFields()[upstreamAddressField].GetStringValue(); got != "10.1.2.3:443" {
				t.Fatalf("target not pinned: %s", got)
			}
		})
	}
}

func TestSecurityProfileWholeProfilePriority(t *testing.T) {
	regs, err := filter.Build(bypass.Definition(), block.Definition(), headermutation.Definition())
	if err != nil {
		t.Fatal(err)
	}
	tcp := func(action agents.TCPActionType, cidr string) []agents.TCPRule {
		return []agents.TCPRule{{Name: "target", Action: action, Match: []agents.TCPMatch{{CIDRs: []string{cidr}}}}}
	}
	bypassRule := agents.SecurityRule{
		Name:    "bypass",
		Match:   []agents.RuleMatch{{Domains: []string{"*"}}},
		Actions: agents.SecurityRuleActions{Bypass: true},
	}
	blockRule := agents.SecurityRule{
		Name:    "block",
		Match:   []agents.RuleMatch{{Domains: []string{"*"}}},
		Actions: agents.SecurityRuleActions{Block: &agents.BlockAction{StatusCode: 451}},
	}
	for _, tc := range []struct {
		name   string
		first  agents.SecurityProfileSpec
		second agents.SecurityProfileSpec
		host   string
		status int
	}{
		{name: "higher TCP deny beats lower HTTP bypass", first: agents.SecurityProfileSpec{TCPRules: tcp(agents.TCPActionDeny, "10.0.0.0/8")}, second: agents.SecurityProfileSpec{Rules: []agents.SecurityRule{bypassRule}}, host: "10.1.2.3:443", status: 403},
		{name: "higher TCP allow beats lower HTTP block", first: agents.SecurityProfileSpec{TCPRules: tcp(agents.TCPActionAllow, "10.0.0.0/8")}, second: agents.SecurityProfileSpec{Rules: []agents.SecurityRule{blockRule}}, host: "10.1.2.3:443"},
		{name: "higher HTTP bypass beats lower TCP deny", first: agents.SecurityProfileSpec{Rules: []agents.SecurityRule{bypassRule}}, second: agents.SecurityProfileSpec{TCPRules: tcp(agents.TCPActionDeny, "0.0.0.0/0")}, host: "10.1.2.3:443"},
		{name: "unmatched higher TCP continues to HTTP", first: agents.SecurityProfileSpec{TCPRules: tcp(agents.TCPActionDeny, "10.0.0.0/8")}, second: agents.SecurityProfileSpec{Rules: []agents.SecurityRule{bypassRule}}, host: "203.0.113.8:443"},
		{name: "unmatched higher TCP continues to lower TCP", first: agents.SecurityProfileSpec{TCPRules: tcp(agents.TCPActionDeny, "10.0.0.0/8")}, second: agents.SecurityProfileSpec{TCPRules: tcp(agents.TCPActionDeny, "0.0.0.0/0")}, host: "203.0.113.8:443", status: 403},
		{name: "only complete chain defaults allow", first: agents.SecurityProfileSpec{TCPRules: tcp(agents.TCPActionDeny, "10.0.0.0/8")}, host: "203.0.113.8:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := profilestore.MakeFakeStore(regs...)
			firstPriority, secondPriority := int32(100), int32(200)
			tc.first.Priority = &firstPriority
			tc.second.Priority = &secondPriority
			store.ProfileSet(
				&agents.SecurityProfile{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "ns"}, Spec: tc.first},
			)
			store.ProfileSet(
				&agents.SecurityProfile{
					ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "ns"},
					Spec:       tc.second,
				},
			)
			targets := egressauthz.NewAggregate(dns.NewClient(nil, 0))
			srv := NewServer(
				ServerDeps{
					Registrations:    regs,
					Resolve:          securityprofile.NewResolver(store, regs, nil, targets),
					AuthorizeRequest: targets.Authorize,
				},
			)
			responses, err := srv.HandleRequestHeaders(
				t.Context(),
				makeRequestHeaders(tc.host, "/", "GET"),
				makeAttrsWithLabels("ns", "pod", ""),
				newStreamState(),
			)
			if err != nil {
				t.Fatal(err)
			}
			got := int(responses[0].GetImmediateResponse().GetStatus().GetCode())
			if got != tc.status {
				t.Fatalf("status=%d, want %d: %v", got, tc.status, responses)
			}
			if got == 0 && responseUpstream(responses[0]) == nil {
				t.Fatal("allowed destination was not pinned")
			}
		})
	}
}

// A checkpoint must fail locally just like final authorization; a transport
// error could let Envoy continue when failureModeAllow is enabled.
func TestTCPCheckpointResolutionFailureReturnsLocalReply(t *testing.T) {
	regs, err := filter.Build(bypass.Definition())
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []error{errors.New("private DNS failure"), context.DeadlineExceeded} {
		for _, checkpoint := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/checkpoint=%v", failure, checkpoint), func(t *testing.T) {
				store := profilestore.MakeFakeStore(regs...)
				spec := agents.SecurityProfileSpec{}
				if checkpoint {
					spec.TCPRules = []agents.TCPRule{
						{
							Name:   "deny-all",
							Action: agents.TCPActionDeny,
							Match:  []agents.TCPMatch{{CIDRs: []string{"0.0.0.0/0"}}},
						},
					}
				}
				store.ProfileSet(
					&agents.SecurityProfile{
						ObjectMeta: metav1.ObjectMeta{Name: "profile", Namespace: "ns"},
						Spec:       spec,
					},
				)
				client := dns.NewClient(
					dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
						return dns.LookupResult{}, failure
					}),
					0,
				)
				targets := egressauthz.NewAggregate(client)
				audit := &capturedAuditLogger{}
				server := NewServer(
					ServerDeps{
						AuditLogger:      audit,
						Registrations:    regs,
						Resolve:          securityprofile.NewResolver(store, regs, nil, targets),
						AuthorizeRequest: targets.Authorize,
					},
				)
				stream := &collectingStream{ctx: t.Context(),
					msgs: []*extProcPb.ProcessingRequest{
						{
							Request: &extProcPb.ProcessingRequest_RequestHeaders{
								RequestHeaders: makeRequestHeaders("blocked.example:443", "/", "GET"),
							},
							Attributes: makeAttrsWithLabels("ns", "pod", ""),
						},
					}}
				if err := server.Process(stream); err != nil {
					t.Fatalf("authorization escaped as transport failure: %v", err)
				}
				if len(stream.sent) != 1 {
					t.Fatalf("responses=%v", stream.sent)
				}
				reply := stream.sent[0].GetImmediateResponse()
				if reply.GetStatus().GetCode() != 500 || reply.GetDetails() != "epe_request_authorization_failed" ||
					strings.Contains(string(reply.GetBody()), failure.Error()) {
					t.Fatalf("reply=%v", reply)
				}
				if stream.sent[0].GetDynamicMetadata() != nil {
					t.Fatal("failed authorization published an upstream")
				}
				if len(audit.entries) != 1 {
					t.Fatalf("audit=%v", audit.entries)
				}
				entry := audit.entries[0]
				if entry.Authorization == nil || entry.Authorization.Action != "error" ||
					entry.Authorization.Reason != filter.AuthorizationReasonResolutionFailed ||
					!strings.Contains(entry.Error, failure.Error()) {
					t.Fatalf("audit=%+v", entry)
				}
			})
		}
	}
}
