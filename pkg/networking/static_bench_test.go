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

package networking

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

var benchmarkFilter proto.Message
var benchmarkResources []model.Resource

func BenchmarkStaticFilters(b *testing.B) {
	for _, tc := range []struct {
		name  string
		build func() proto.Message
	}{
		{"ConnectAuthority", func() proto.Message { return connectAuthorityHTTPFilter }},
		{"LegacyPeerMetadata", func() proto.Message { return legacyPeerMetadataFilter }},
		{"SNIHostRBAC", func() proto.Message { return sniHostMatchRBACFilter }},
		{"ConnectTLSIdentity", func() proto.Message { return connectProxyTLSIdentityHTTPFilter }},
		{"RelayDownstream", func() proto.Message { return relayDownstreamFilter }},
		{"SNIDenialReason", func() proto.Message { return sniDenialReasonFilter }},
		{"CaptureSNI", func() proto.Message { return captureSNIFilter }},
		{"OuterTLSIdentity", func() proto.Message { return outerTLSIdentityFilter }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			test.SetForTest(b, &features.EnableSNITrafficPolicy, true)
			b.ReportAllocs()
			for b.Loop() {
				benchmarkFilter = tc.build()
			}
		})
	}
}

// Measure the complete gateway build, including validation and the final xDS
// resource serialization that caching nested filter configs cannot eliminate.
func BenchmarkGatewayBuild(b *testing.B) {
	for _, policy := range []bool{false, true} {
		name := "StaticTLS"
		if policy {
			name = "SNIPolicy"
		}
		b.Run(name, func(b *testing.B) {
			test.SetForTest(b, &features.EnableSNITrafficPolicy, policy)
			test.SetForTest(b, &features.GatewayRootCAPath, "/etc/ssl/cert.pem")
			inputs := Inputs{
				Gateway: testGateway(&configv1.EgressGateway{
					TlsTermination: &configv1.TlsTerminationConfig{
						IncludeHosts: []string{"*.example.com"},
						ExcludeHosts: []string{"legacy.example.com"},
					},
					Tcp: &configv1.TcpSettings{IdleTimeout: durationpb.New(2 * time.Minute)},
					Http: &configv1.GatewayHttpSettings{
						StreamIdleTimeout: durationpb.New(3 * time.Minute),
						Routing: &configv1.HttpRoutingSettings{
							Fallback: &configv1.HttpRouteSettings{Timeout: durationpb.New(12 * time.Second)},
						},
					},
					ConnectRateLimit: &configv1.LocalRateLimitSettings{TokenBucket: &configv1.TokenBucket{
						MaxTokens:     20,
						TokensPerFill: 5,
						FillInterval:  durationpb.New(time.Second),
					}},
					ServiceEntries: []*configv1.EgressServiceEntry{{
						Hosts:     []string{"api.example.com"},
						Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "192.0.2.10"}},
					}},
				}),
				GlobalExtProc: &configv1.ExtProcProvider{
					Service:          "epe.agentio-system.svc",
					Port:             9002,
					MessageTimeout:   "350ms",
					FailureModeAllow: true,
				},
				DiscoveryAddress: "agentiod.agentio-system.svc:15012",
				TrustDomain:      "cluster.local",
			}
			b.ReportAllocs()
			for b.Loop() {
				var err error
				benchmarkResources, err = Build(inputs)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
