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
	"fmt"
	"net/netip"
	"slices"
	"testing"

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
// SNI forwarding and gateways without an EPE provider.
func TestDFPAddressFilterInGatewayGraph(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			resources, err := Build(Inputs{
				Gateway:          testGateway(&configv1.EgressGateway{}),
				LegacyGateway:    legacy,
				DiscoveryAddress: "agentiod:15012",
				TrustDomain:      "cluster.local",
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
			for _, name := range []string{HTTPDynamicForwardProxy, TLSConnectOriginate} {
				cfg := &dfpclusterv3.ClusterConfig{}
				if err := clusters[name].GetClusterType().GetTypedConfig().UnmarshalTo(cfg); err != nil {
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
			for name, cache := range caches {
				t.Run(name, func(t *testing.T) {
					if err := cache.ValidateAll(); err != nil {
						t.Fatal(err)
					}
					if !proto.Equal(cache, caches[HTTPDynamicForwardProxy]) {
						t.Fatal("DFP consumers disagree on the shared DNS cache configuration")
					}
					if legacy {
						if cache.GetResolvedAddressFilter() != nil {
							t.Fatal("legacy gateway received an unsupported DNS cache field")
						}
						return
					}
					if cache.GetResolvedAddressFilter() == nil {
						t.Fatal("DFP destination IP filter is missing")
					}
					if cache.GetResolvedAddressFilter().GetInvertMatch() {
						t.Fatal("denied ranges must not be inverted")
					}
					var ranges []string
					for _, cidr := range cache.GetResolvedAddressFilter().GetRanges() {
						ranges = append(
							ranges,
							netip.PrefixFrom(netip.MustParseAddr(cidr.AddressPrefix), int(cidr.PrefixLen.GetValue())).
								String(),
						)
					}
					want := []string{
						"127.0.0.0/8", "::1/128", "0.0.0.0/32", "::/128", "169.254.0.0/16", "fe80::/10",
						"::ffff:127.0.0.0/104", "::ffff:0.0.0.0/128", "::ffff:169.254.0.0/112",
					}
					slices.Sort(ranges)
					slices.Sort(want)
					if !slices.Equal(ranges, want) {
						t.Fatalf("denied IP ranges = %v, want %v", ranges, want)
					}
				})
			}
		})
	}
}
