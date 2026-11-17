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

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	dfpclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfpcommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	dfphttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	dfpnetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// Every consumer of a named cache must receive the same configuration, including
// gateways without an EPE provider.
func TestDFPAddressFilterInGatewayGraph(t *testing.T) {
	configured := &configv1.DnsCacheSettings{
		MaxHosts:           new(uint32(8192)),
		MaxPendingRequests: new(uint32(2048)),
	}
	for _, tc := range []struct {
		name     string
		legacy   bool
		settings *configv1.DnsCacheSettings
		hosts    uint32
		pending  uint32
		ttl      time.Duration
		custom   bool
	}{
		{"native defaults", false, nil, 16384, 4096, 2 * time.Minute, false},
		{"legacy defaults", true, nil, 16384, 4096, 2 * time.Minute, false},
		{"empty settings", false, &configv1.DnsCacheSettings{}, 16384, 4096, 2 * time.Minute, false},
		{"native configured", false, configured, 8192, 2048, 2 * time.Minute, false},
		{"legacy configured", true, configured, 8192, 2048, 2 * time.Minute, false},
		{"capacity only", false, &configv1.DnsCacheSettings{MaxHosts: new(uint32(2048))}, 2048, 4096, 2 * time.Minute, false},
		{"pending only", false, &configv1.DnsCacheSettings{MaxPendingRequests: new(uint32(2048))}, 16384, 2048, 2 * time.Minute, false},
		{"configured custom restrictions", false, configured, 8192, 2048, 2 * time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacy := tc.legacy
			var authorization *configv1.EgressAuthorization
			if tc.custom {
				authorization = &configv1.EgressAuthorization{
					DeniedCidrs: []string{"100.100.100.200/32", "2001:db8::/64"},
				}
			}
			resources, err := Build(Inputs{
				EgressAuthorization: authorization,
				Gateway:             testGateway(&configv1.EgressGateway{DnsCache: tc.settings}),
				LegacyGateway:       legacy,
				DiscoveryAddress:    "agentiod:15012",
				TrustDomain:         "cluster.local",
			})
			if err != nil {
				t.Fatal(err)
			}
			caches := map[string]*dfpcommonv3.DnsCacheConfig{}
			clusters := messagesOf(
				t,
				resources,
				model.ClusterType,
				func() *clusterv3.Cluster { return &clusterv3.Cluster{} },
			)
			for name, cluster := range clusters {
				if cluster.GetClusterType().GetName() != "envoy.clusters.dynamic_forward_proxy" {
					continue
				}
				cfg := &dfpclusterv3.ClusterConfig{}
				if err := cluster.GetClusterType().GetTypedConfig().UnmarshalTo(cfg); err != nil {
					t.Fatal(err)
				}
				caches[name] = cfg.GetDnsCacheConfig()
			}
			listeners := messagesOf(
				t,
				resources,
				model.ListenerType,
				func() *listenerv3.Listener { return &listenerv3.Listener{} },
			)
			for name, listener := range listeners {
				for _, chain := range listener.GetFilterChains() {
					for _, filter := range chain.GetFilters() {
						key := name + "/" + chain.GetName() + "/" + filter.GetName()
						switch filter.GetName() {
						case "envoy.filters.network.sni_dynamic_forward_proxy":
							cfg := &dfpnetworkv3.FilterConfig{}
							if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
								t.Fatal(err)
							}
							caches[key] = cfg.GetDnsCacheConfig()
						case "envoy.filters.network.http_connection_manager":
							hcm := &hcmv3.HttpConnectionManager{}
							if err := filter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
								t.Fatal(err)
							}
							for _, httpFilter := range hcm.GetHttpFilters() {
								if httpFilter.GetName() == "envoy.filters.http.dynamic_forward_proxy" {
									cfg := &dfphttpv3.FilterConfig{}
									if err := httpFilter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
										t.Fatal(err)
									}
									caches[key] = cfg.GetDnsCacheConfig()
								}
							}
						}
					}
				}
			}
			if !legacy {
				if len(caches) != 0 {
					t.Fatalf("native gateway still uses DFP: %v", caches)
				}
				for _, name := range []string{
					PassthroughCluster, TLSConnectOriginate, TLSProxyOriginate, TLSPassthrough,
				} {
					if clusters[name].GetType() != clusterv3.Cluster_ORIGINAL_DST {
						t.Fatalf("%s must use ORIGINAL_DST", name)
					}
				}
				for _, listener := range listeners {
					for _, chain := range listener.FilterChains {
						for _, filter := range chain.Filters {
							if filter.Name != "agentio.tcp_policy" {
								continue
							}
							typed := &udpatypev1.TypedStruct{}
							if err := filter.GetTypedConfig().UnmarshalTo(typed); err != nil {
								t.Fatal(err)
							}
							dns := typed.Value.Fields["filter_config"].GetStructValue().Fields["value"].GetStructValue().Fields["dns"].GetStructValue()
							if dns.Fields["resolver"].GetStringValue() != DNSCacheName ||
								dns.Fields["max_hosts"].GetNumberValue() != float64(tc.hosts) ||
								dns.Fields["max_pending_requests"].GetNumberValue() != float64(tc.pending) {
								t.Fatalf("native DNS limits were not propagated: %v", dns)
							}
						}
					}
				}
			}
			for name, cache := range caches {
				t.Run(name, func(t *testing.T) {
					if err := cache.ValidateAll(); err != nil {
						t.Fatal(err)
					}
					if !proto.Equal(cache, caches[HTTPDynamicForwardProxy]) {
						t.Fatal("DFP consumers disagree on the shared DNS cache configuration")
					}
					pending := cache.GetDnsCacheCircuitBreaker().GetMaxPendingRequests()
					if cache.GetMaxHosts().GetValue() != tc.hosts ||
						pending.GetValue() != tc.pending ||
						cache.GetHostTtl().AsDuration() != tc.ttl {
						t.Fatalf("DNS cache settings were not propagated: %v", cache)
					}
					if cache.GetResolvedAddressFilter() != nil || cache.GetName() != DNSCacheName {
						t.Fatal("address authorization must not change the shared DNS cache")
					}
				})
			}
		})
	}
}

func TestEgressAuthorizationCacheIdentity(t *testing.T) {
	name := func(cidrs ...string) string {
		return (&resourceBuilder{egressAuthorization: &configv1.EgressAuthorization{DeniedCidrs: cidrs}}).dnsCacheConfig().Name
	}
	if name("192.0.2.1/24", "2001:db8::/64") != name("2001:db8::1/64", "192.0.2.0/24", "192.0.2.0/24") {
		t.Fatal("equivalent restrictions must reuse the cache")
	}
	if name("192.0.2.0/24") != name("192.0.3.0/24") || name() != DNSCacheName {
		t.Fatal("authorization update changed cache identity")
	}
	if name("127.0.0.0/8") != name() {
		t.Fatal("repeating a built-in restriction changes the cache")
	}
	for _, tc := range []struct {
		legacy bool
		cidr   string
	}{{false, "invalid"}, {true, "192.0.2.0/24"}} {
		_, err := Build(Inputs{
			Gateway:             testGateway(nil),
			LegacyGateway:       tc.legacy,
			EgressAuthorization: &configv1.EgressAuthorization{DeniedCidrs: []string{tc.cidr}}})
		if err == nil {
			t.Fatalf("accepted unsupported authorization: %+v", tc)
		}
	}
}
