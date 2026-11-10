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
	"regexp"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayTCPPassthrough(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		gateway, err := config.Apply(`
tcpPassthrough:
- cidrs: [10.20.1.2/16, '2001:db8::/32']
  ports: [3306, 5432]
- ports: [6379]
- cidrs: [192.168.10.20/32]
tcp:
  idleTimeout: 23s
  maxConnectionDuration: 420s
`, &configv1.EgressGateway{})
		if err != nil {
			t.Fatal(err)
		}
		resources, err := Build(
			Inputs{
				LegacyGateway:    legacy,
				DiscoveryAddress: "agentiod:15012",
				TrustDomain:      "cluster.local",
				Gateway:          testGateway(gateway),
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		listeners := messagesOf(
			t,
			resources,
			model.ListenerType,
			func() *listenerv3.Listener { return &listenerv3.Listener{} },
		)
		for _, filter := range findHCM(t, listeners[ConnectTerminate]).HttpFilters {
			if filter.Name != "agentio.connect_authority" && filter.Name != "connect_authority" {
				continue
			}
			capture := &setstatehttpv3.Config{}
			if err := filter.GetTypedConfig().UnmarshalTo(capture); err != nil {
				t.Fatal(err)
			}
			if !capture.ClearRouteCache {
				t.Fatal("CIDR routing uses a stale route before destination capture")
			}
		}
		listener := listeners[TCPPassthrough]
		if listener == nil || len(listener.ListenerFilters) != 1 ||
			listener.ListenerFilters[0].Name != "envoy.filters.listener.original_dst" {
			t.Fatalf("legacy=%t: passthrough must not run protocol inspectors: %v", legacy, listener)
		}
		chain := listener.FilterChains[0]
		if chain.TransportSocket != nil {
			t.Fatal("TCP passthrough must preserve TLS bytes")
		}
		tcp := &tcpproxyv3.TcpProxy{}
		if err := chain.Filters[len(chain.Filters)-1].GetTypedConfig().UnmarshalTo(tcp); err != nil {
			t.Fatal(err)
		}
		if tcp.GetCluster() != PassthroughCluster || tcp.IdleTimeout.AsDuration() != 23*time.Second ||
			tcp.MaxDownstreamConnectionDuration.AsDuration() != 7*time.Minute {
			t.Fatalf("TCP forwarding lost its target or limits: %v", tcp)
		}
		clusters := messagesOf(
			t,
			resources,
			model.ClusterType,
			func() *clusterv3.Cluster { return &clusterv3.Cluster{} },
		)
		if clusters[TCPPassthrough] == nil {
			t.Fatal("missing internal TCP cluster")
		}
		routes := messagesOf(
			t,
			resources,
			model.RouteType,
			func() *routev3.RouteConfiguration { return &routev3.RouteConfiguration{} },
		)
		var passthrough []*routev3.Route
		for _, route := range routes[ConnectTerminate].VirtualHosts[0].Routes {
			if route.GetRoute().GetCluster() == TCPPassthrough {
				passthrough = append(passthrough, route)
			}
		}
		if len(passthrough) != 3 {
			t.Fatalf("routes=%v", passthrough)
		}
		address := passthrough[0].Match.FilterState[0]
		if address.Key != "envoy.filters.listener.original_dst.local_ip" ||
			address.GetAddressMatch().Ranges[0].AddressPrefix != "10.20.0.0" {
			t.Fatalf("must match normalized original destination: %v", address)
		}
		ports := regexp.MustCompile(
			"^(?:" + passthrough[0].Match.Headers[0].GetStringMatch().GetSafeRegex().Regex + ")$",
		)
		for _, authority := range []string{"10.20.1.2:3306", "[2001:db8::1]:5432", "10.20.1.2:03306"} {
			if !ports.MatchString(authority) {
				t.Errorf("port match missed %s", authority)
			}
		}
		if ports.MatchString("10.20.1.2:33060") || len(passthrough[1].Match.FilterState) != 0 ||
			len(passthrough[2].Match.Headers) != 0 {
			t.Fatal("port-only, CIDR-only or exact port matching changed")
		}
	}
}

func TestGatewayTCPPassthroughOmitted(t *testing.T) {
	resources, err := Build(
		Inputs{DiscoveryAddress: "agentiod:15012", TrustDomain: "cluster.local", Gateway: testGateway(nil)},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range resources {
		if resource.XDSName == TCPPassthrough {
			t.Fatal("omitted tcpPassthrough added a forwarding path")
		}
	}
}
