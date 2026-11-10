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
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	internalv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/bootstrap/internal_listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
)

// Uses production CONNECT routes, original-destination state and TCP listener.
// HBONE identity/admission is replaced with plain HTTP for this forwarding test.
func TestEnvoyTCPPassthroughServerFirst(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	test.SetForTest(t, &features.EnableSNITrafficPolicy, false)
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address, cidr := "127.0.0.1:0", "127.0.0.0/8"
			if network == "tcp6" {
				address, cidr = "[::1]:0", "::1/128"
			}
			origin, err := net.Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			t.Cleanup(func() {
				if err := origin.Close(); err != nil {
					t.Error(err)
				}
				workers.Wait()
			})
			workers.Go(func() {
				for {
					connection, err := origin.Accept()
					if err != nil {
						return
					}
					workers.Go(func() {
						defer func() {
							if err := connection.Close(); err != nil {
								t.Logf("close origin connection: %v", err)
							}
						}()
						if _, err := io.WriteString(connection, "server-first\n"); err != nil {
							return
						}
						if _, err := io.Copy(connection, connection); err != nil {
							t.Logf("origin connection closed: %v", err)
						}
					})
				}
			})
			port := uint32(origin.Addr().(*net.TCPAddr).Port)
			for _, tc := range []struct {
				name             string
				matches          []*configv1.TcpPassthroughMatch
				allowed          bool
				zeroPrefixedPort bool
			}{
				{name: "CIDR and port", matches: []*configv1.TcpPassthroughMatch{{Cidrs: []string{cidr}, Ports: []uint32{port}}}, allowed: true},
				{name: "CIDR only", matches: []*configv1.TcpPassthroughMatch{{Cidrs: []string{cidr}}}, allowed: true},
				{name: "port only", matches: []*configv1.TcpPassthroughMatch{{Ports: []uint32{port}}}, allowed: true},
				{name: "empty entry", matches: []*configv1.TcpPassthroughMatch{{}}, allowed: true},
				{name: "entries are ORed", matches: []*configv1.TcpPassthroughMatch{{Cidrs: []string{"192.0.2.0/24"}}, {Ports: []uint32{port}}}, allowed: true},
				{name: "ports are ORed", matches: []*configv1.TcpPassthroughMatch{{Ports: []uint32{1, port}}}, allowed: true},
				{name: "CIDRs are ORed", matches: []*configv1.TcpPassthroughMatch{{Cidrs: []string{"192.0.2.0/24", cidr}}}, allowed: true},
				{name: "port miss continues to next entry", matches: []*configv1.TcpPassthroughMatch{{Cidrs: []string{cidr}, Ports: []uint32{1}}, {Ports: []uint32{port}}}, allowed: true},
				{name: "zero-prefixed port", matches: []*configv1.TcpPassthroughMatch{{Ports: []uint32{port}}}, allowed: true, zeroPrefixedPort: true},
				{name: "CIDR miss", matches: []*configv1.TcpPassthroughMatch{{Cidrs: []string{"192.0.2.0/24"}, Ports: []uint32{port}}}},
				{name: "port miss", matches: []*configv1.TcpPassthroughMatch{{Cidrs: []string{cidr}, Ports: []uint32{1}}}},
				{name: "unconfigured"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					gateway := &configv1.EgressGateway{TcpPassthrough: tc.matches}
					b := &resourceBuilder{}
					settings := effectiveConfig{gateway: gateway}
					listeners, err := b.listeners(settings, "cluster.local")
					if err != nil {
						t.Fatal(err)
					}
					routes, err := b.routes(gateway)
					if err != nil {
						t.Fatal(err)
					}
					connectHCM, err := b.buildConnectHCM(settings)
					if err != nil {
						t.Fatal(err)
					}
					connectHCM.HttpFilters = []*hcmv3.HttpFilter{
						connectHCM.HttpFilters[0],
						connectHCM.HttpFilters[len(connectHCM.HttpFilters)-1],
					}
					connectHCM.RouteSpecifier = &hcmv3.HttpConnectionManager_RouteConfig{RouteConfig: routes[0]}
					outer := &listenerv3.Listener{
						Name:    "connect",
						Address: socketAddress("127.0.0.1", 0),
						FilterChains: []*listenerv3.FilterChain{{Filters: []*listenerv3.Filter{
							networkFilter("envoy.filters.network.http_connection_manager", b.pack(connectHCM)),
						}}},
					}
					// A closed fallback makes route misses observable without involving EPE.
					fallback := &listenerv3.Listener{
						Name: MainInternal,
						ListenerSpecifier: &listenerv3.Listener_InternalListener{
							InternalListener: &listenerv3.Listener_InternalListenerConfig{},
						},
						FilterChains: []*listenerv3.FilterChain{
							{Filters: b.applicationTCPFilters(settings, nil, BlackHoleCluster, nil)},
						},
					}
					cfg := &bootstrapv3.Bootstrap{
						BootstrapExtensions: []*corev3.TypedExtensionConfig{
							{
								Name:        "envoy.bootstrap.internal_listener",
								TypedConfig: b.pack(&internalv3.InternalListener{}),
							},
						},
						StaticResources: &bootstrapv3.Bootstrap_StaticResources{
							Listeners: []*listenerv3.Listener{outer, fallback},
							Clusters: []*clusterv3.Cluster{
								b.buildInternalCluster(MainInternal),
								b.buildPassthroughCluster(),
								buildBlackHoleCluster(),
							},
						},
						Admin: &bootstrapv3.Admin{Address: socketAddress("127.0.0.1", 0)},
					}
					for _, listener := range listeners {
						if listener.Name == TCPPassthrough {
							cfg.StaticResources.Listeners = append(cfg.StaticResources.Listeners, listener)
							cfg.StaticResources.Clusters = append(
								cfg.StaticResources.Clusters,
								b.buildInternalCluster(TCPPassthrough),
							)
						}
					}
					if b.err != nil {
						t.Fatal(b.err)
					}
					data, err := protojson.Marshal(cfg)
					if err != nil {
						t.Fatal(err)
					}
					proxy, _ := runCompatibilityEnvoy(t, binary, string(data))
					connection, err := net.DialTimeout("tcp", proxy, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := connection.Close(); err != nil {
							t.Error(err)
						}
					})
					if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					destination := origin.Addr().String()
					if tc.zeroPrefixedPort {
						destination = net.JoinHostPort(
							origin.Addr().(*net.TCPAddr).IP.String(),
							fmt.Sprintf("0%d", port),
						)
					}
					if _, err := fmt.Fprintf(
						connection,
						"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
						destination,
						destination,
					); err != nil {
						t.Fatal(err)
					}
					reader := bufio.NewReader(connection)
					status, err := reader.ReadString('\n')
					if !tc.allowed && err == nil && strings.Contains(status, " 503 ") {
						return
					}
					if err != nil || !strings.Contains(status, " 200 ") {
						t.Fatalf("CONNECT status=%q err=%v", status, err)
					}
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							t.Fatal(err)
						}
						if line == "\r\n" {
							break
						}
					}
					banner, err := reader.ReadString('\n')
					if !tc.allowed {
						if err == nil || banner != "" {
							t.Fatalf("unmatched connection reached origin: banner=%q err=%v", banner, err)
						}
						return
					}
					if err != nil || banner != "server-first\n" {
						t.Fatalf("server-first banner=%q err=%v", banner, err)
					}
					payload := "GET / HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n"
					if _, err := io.WriteString(connection, payload); err != nil {
						t.Fatal(err)
					}
					echo := make([]byte, len(payload))
					if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != payload {
						t.Fatalf("TCP bytes changed: %q err=%v", echo, err)
					}
				})
			}
		})
	}
}
