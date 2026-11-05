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

package trafficpolicy

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"

	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/pkg/dns"
)

type benchmarkLookup struct{}

func (benchmarkLookup) Lookup(context.Context, string, dns.Family) (dns.LookupResult, error) {
	return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.7")}, TTL: time.Hour}, nil
}

// BenchmarkEgressAuthorization includes production caller snapshot preparation,
// destination evaluation and target construction. DNS cache misses are excluded.
func BenchmarkEgressAuthorization(b *testing.B) {
	ctx := ctrllog.IntoContext(context.Background(), logr.Discard())
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprintf("N%d", count), func(b *testing.B) {
			_, aggregate, _, _ := benchFixture(count)
			for _, mode := range []string{"original", "literal", "cachedDNS", "denied"} {
				b.Run(mode, func(b *testing.B) {
					authorize := egressauthz.NewAggregate(
						dns.NewClient(benchmarkLookup{}, time.Second),
						NewAuthorizer(),
					).Authorize
					st := &filter.Stream{RequestContext: filter.RequestContext{Caller: filter.CallerContext{
						Subject: subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod-0"}},
					},
						Request: httpreq.HTTPRequest{Host: "203.0.113.7", Port: 443}},
					}
					switch mode {
					case "original":
						st.Request.OriginalDestination = netip.MustParseAddrPort("203.0.113.7:443")
					case "cachedDNS":
						st.Request.Host = "bench.example.com"
					case "denied":
						st.Request.Host = "198.51.100.7"
					}
					input := st.RequestContext
					prepare := NewContextResolver(aggregate, true)
					caller, err := prepare(ctx, input)
					if err != nil {
						b.Fatal(err)
					}
					st.RequestContext = caller
					target, reply, err := authorize(ctx, st)
					if err != nil {
						b.Fatal(err)
					}
					if mode == "denied" {
						if reply == nil || reply.Status != 403 {
							b.Fatal("denial not exercised")
						}
					} else if target == nil || reply != nil {
						b.Fatal("allow not exercised")
					}
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						caller, err := prepare(ctx, input)
						if err != nil {
							b.Fatal(err)
						}
						st.RequestContext = caller
						_, _, err = authorize(ctx, st)
						if err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
