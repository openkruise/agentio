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

type authorizerFunc func(context.Context, *filter.Stream, []netip.AddrPort) ([]netip.AddrPort, error)

func TestCandidatesSkipRequestPolicyAndFinalAuthorizationInvokesItOnce(t *testing.T) {
	private := netip.MustParseAddrPort("10.1.2.3:443")
	public := netip.MustParseAddrPort("203.0.113.8:443")
	loadErr := errors.New("policy unavailable")
	for _, outcome := range []string{"allow", "deny", "error"} {
		t.Run(outcome, func(t *testing.T) {
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
								if !slices.Equal(candidates, []netip.AddrPort{private, public}) {
									t.Fatalf(
										"request policy candidates=%v, want both addresses",
										candidates,
									)
								}
								if outcome == "error" {
									return nil, loadErr
								}
								if outcome == "deny" {
									return nil, nil
								}
								return candidates[1:], nil
							},
						),
					},
				},
				StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
			}
			a := NewAggregate(client)
			candidates, err := a.Candidates(t.Context(), stream)
			if err != nil || calls != 0 {
				t.Fatalf("candidates invoked request policy: calls=%d err=%v", calls, err)
			}
			if !slices.Equal(candidates, []netip.AddrPort{private, public}) {
				t.Fatalf("DNS candidates changed before policy evaluation: %v", candidates)
			}

			target, reply, err := a.Authorize(t.Context(), stream)
			wantCalls := 1
			if calls != wantCalls {
				t.Fatalf("request policy calls=%d, want %d", calls, wantCalls)
			}
			switch outcome {
			case "allow":
				if err != nil || reply != nil || target == nil || *target.Address != public {
					t.Fatalf("target=%v reply=%v err=%v", target, reply, err)
				}
			case "deny":
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
