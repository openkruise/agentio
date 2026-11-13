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
	"strconv"
	"testing"
	"time"

	"github.com/go-logr/logr"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/dns"
)

// BenchmarkTCPPolicyRequest includes binding, ordered HTTP/TCP execution and
// final authorization. DNS is either a literal or a warmed in-memory cache.
func BenchmarkTCPPolicyRequest(b *testing.B) {
	log.SetLogger(logr.Discard())
	regs := claimAll(b, nil)
	for _, count := range []int{1, 4, 16} {
		for _, outcome := range []string{"fallthrough", "allow-last", "deny-first"} {
			for _, host := range []string{"203.0.113.8", "cached.example"} {
				b.Run("profiles="+strconv.Itoa(count)+"/"+outcome+"/"+host, func(b *testing.B) {
					profiles := benchProfiles(b, regs, count, 4)
					for _, profile := range profiles {
						profile.TCPPolicy = &securityv1.TCPPolicy{Rules: []*securityv1.TCPRule{{
							Name:   "deny-private",
							Action: securityv1.TCPAction_TCP_ACTION_DENY,
							Match:  []*securityv1.TCPMatch{{Cidrs: []string{"10.0.0.0/8"}}},
						}}}
					}
					want := engine.DispositionPassthrough
					if outcome == "allow-last" {
						profiles[count-1].TCPPolicy.Rules[0].Action = securityv1.TCPAction_TCP_ACTION_ALLOW
						profiles[count-1].TCPPolicy.Rules[0].Match[0].Cidrs = []string{"0.0.0.0/0"}
						want = engine.DispositionBypassed
					} else if outcome == "deny-first" {
						profiles[0].TCPPolicy.Rules[0].Match[0].Cidrs = []string{"0.0.0.0/0"}
						want = engine.DispositionBlocked
					}
					client := dns.NewClient(
						dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
							return dns.LookupResult{
								Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.8")},
								TTL:       time.Hour,
							}, nil
						}),
						0,
					)
					targets := egressauthz.NewAggregate(client, egressauthz.NewStaticAuthorizer(egressauthz.Config{}))
					resolve := NewResolver(benchStore{profiles: profiles}, regs, nil, targets)
					e := engine.NewEngine(regs, 0)
					req := testRequest(host)
					req.Port = 443
					ctx := b.Context()
					if _, err := client.Resolve(ctx, "cached.example", dns.IPv4Only); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						res, err := resolve(ctx, subject.Subject{}, req)
						if err != nil {
							b.Fatal(err)
						}
						stream := &filter.Stream{
							RequestContext: filter.RequestContext{
								Request:  *req,
								Policies: filter.PolicySnapshot{DestinationAuthorizer: res.DestinationAuthorizer},
							},
							StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
						}
						result, err := e.EvalRequestHeaders(ctx, stream, res.Units)
						if err != nil || result.Disposition != want {
							b.Fatalf("evaluation: disposition=%v want=%v err=%v", result.Disposition, want, err)
						}
						if result.Disposition == engine.DispositionBlocked {
							continue
						}
						if result.Route != nil {
							stream.Upstream = result.Route.Upstream
						}
						target, reply, err := targets.Authorize(ctx, stream)
						if err != nil || reply != nil || target == nil {
							b.Fatalf("authorization: target=%v reply=%v err=%v", target, reply, err)
						}
						benchSink = target
					}
				})
			}
		}
	}
}

func BenchmarkResolverNoMatch(b *testing.B) {
	regs := claimAll(b, nil)
	for _, count := range []int{1, 4, 16} {
		b.Run("profiles="+strconv.Itoa(count), func(b *testing.B) {
			resolve := NewResolver(benchStore{profiles: benchMissProfiles(b, regs, count, 8)}, regs, nil, nil)
			req := testRequest("api.example.com")
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				res, err := resolve(b.Context(), subject.Subject{}, req)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = res
			}
		})
	}
}
