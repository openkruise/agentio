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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	extprocservice "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc"
	"github.com/openkruise/agentio/pkg/model"
)

// Exercise the production destination filters with real Envoy, including an EPE
// that deliberately pins an address denied only by the gateway configuration.
func TestEnvoyEgressAuthorizationUpdate(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var originIP netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
			originIP = prefix.Addr()
			break
		}
	}
	if !originIP.IsValid() {
		t.Fatal("a non-loopback IPv4 interface is required")
	}
	var originCalls, epeCalls atomic.Int64
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		originCalls.Add(1)
		if request.Method == http.MethodConnect {
			connection, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := fmt.Fprintf(
				buffer,
				"HTTP/1.1 200 Connection Established\r\n\r\n%s\n",
				request.Host,
			); err != nil {
				t.Error(err)
			}
			if err := buffer.Flush(); err != nil {
				t.Error(err)
			}
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	if err := origin.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	origin.Listener, err = net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	origin.Start()
	t.Cleanup(origin.Close)
	target := netip.AddrPortFrom(originIP, uint16(origin.Listener.Addr().(*net.TCPAddr).Port))
	rpc, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	processor := grpc.NewServer()
	extprocservice.RegisterExternalProcessorServer(processor, extproc.NewServer(extproc.ServerDeps{
		AuthorizeRequest: func(_ context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
			epeCalls.Add(1)
			selected := target
			if stream.Request.Path == "/loopback" {
				selected = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), target.Port())
			}
			if stream.Request.Method == http.MethodConnect {
				selected = netip.MustParseAddrPort("127.0.0.1:1")
			}
			return &filter.UpstreamTarget{Address: &selected}, nil, nil
		},
	}))
	go func() {
		if err := processor.Serve(rpc); err != nil {
			t.Errorf("EPE server: %v", err)
		}
	}()
	t.Cleanup(processor.Stop)
	provider := &configv1.ExtProcProvider{Service: "127.0.0.1", Port: uint32(rpc.Addr().(*net.TCPAddr).Port)}
	for _, pinned := range []bool{false, true} {
		t.Run(fmt.Sprintf("epe=%t", pinned), func(t *testing.T) {
			directory := t.TempDir()
			cdsPath, ldsPath := filepath.Join(directory, "cds.json"), filepath.Join(directory, "lds.json")
			writeResources := func(path, typeURL, version string, resources ...*anypb.Any) {
				t.Helper()
				data, err := protojson.Marshal(
					&discoveryv3.DiscoveryResponse{TypeUrl: typeURL, VersionInfo: version, Resources: resources},
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".tmp", path); err != nil {
					t.Fatal(err)
				}
			}
			update := func(version string, denied []string, port uint32) {
				t.Helper()
				b := &resourceBuilder{egressAuthorization: &configv1.EgressAuthorization{DeniedCidrs: denied}}
				settings := effectiveConfig{gateway: &configv1.EgressGateway{}}
				clusters := []*anypb.Any{
					b.pack(b.buildDFPCluster(HTTPDynamicForwardProxy, true, false, nil)),
					b.pack(b.buildPassthroughCluster()),
				}
				if pinned {
					settings.extProc = provider
					clusters = append(clusters, b.pack(b.buildExtProcCluster(provider, ExtProcCluster)))
				}
				manager, err := b.buildForwardHCM(HTTPDynamicForwardProxy, settings, false)
				if err != nil {
					t.Fatal(err)
				}
				manager.RouteSpecifier = &hcmv3.HttpConnectionManager_RouteConfig{
					RouteConfig: b.buildForwardRoute(HTTPDynamicForwardProxy, settings.gateway),
				}
				// Model the original destination restored from the outer HBONE tunnel.
				manager.HttpFilters = append(
					[]*hcmv3.HttpFilter{httpFilter("test.original_target", b.pack(&httpstate.Config{
						OnRequestHeaders: []*common.FilterStateValue{
							{
								Key: &common.FilterStateValue_ObjectKey{
									ObjectKey: "envoy.filters.listener.original_dst.local_ip",
								},
								Value: &common.FilterStateValue_FormatString{
									FormatString: formatString("%REQ(x-test-original-target)%"),
								},
							},
							{
								Key: &common.FilterStateValue_ObjectKey{ObjectKey: originalDstAddressKey},
								Value: &common.FilterStateValue_FormatString{
									FormatString: formatString("%REQ(x-test-original-target)%"),
								},
							},
						},
					}))},
					manager.HttpFilters...)
				listener := &listenerv3.Listener{
					Name:    "egress",
					Address: socketAddress("127.0.0.1", port),
					FilterChains: []*listenerv3.FilterChain{{Filters: []*listenerv3.Filter{
						networkFilter("envoy.filters.network.http_connection_manager", b.pack(manager)),
					}}}}
				writeResources(cdsPath, model.ClusterType, version, clusters...)
				writeResources(ldsPath, model.ListenerType, version, b.pack(listener))
				if b.err != nil {
					t.Fatal(b.err)
				}
			}
			update("1", nil, 0)
			cfg := &bootstrapv3.Bootstrap{
				Node: &corev3.Node{Id: "egress-test", Cluster: "egress-test"},
				DynamicResources: &bootstrapv3.Bootstrap_DynamicResources{
					CdsConfig: &corev3.ConfigSource{ConfigSourceSpecifier: &corev3.ConfigSource_Path{Path: cdsPath}},
					LdsConfig: &corev3.ConfigSource{ConfigSourceSpecifier: &corev3.ConfigSource_Path{Path: ldsPath}},
				},
				Admin: &bootstrapv3.Admin{Address: socketAddress("127.0.0.1", 0)},
			}
			data, err := protojson.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			address, _ := runCompatibilityEnvoy(t, binary, string(data))
			port := uint32(netip.MustParseAddrPort(address).Port())
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			t.Cleanup(client.CloseIdleConnections)
			request := func(loopback bool) int {
				t.Helper()
				path, host := "/", target.String()
				if loopback {
					path, host = "/loopback", net.JoinHostPort("127.0.0.1", fmt.Sprint(target.Port()))
				}
				if pinned {
					host = "unresolvable.invalid"
				}
				req, err := http.NewRequest(http.MethodGet, "http://"+address+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = host
				req.Header.Set("x-test-original-target", net.JoinHostPort("127.0.0.1", fmt.Sprint(target.Port())))
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				return response.StatusCode
			}
			proxyRequest := func(loopback bool) int {
				t.Helper()
				connection, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := connection.Close(); err != nil {
						t.Error(err)
					}
				}()
				if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				proxy := target
				if loopback {
					proxy = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), target.Port())
				}
				// The external proxy owns this inner target; the gateway only dials proxy.
				const authority = "127.0.0.1:443"
				if _, err := fmt.Fprintf(
					connection,
					"CONNECT %s HTTP/1.1\r\nHost: %s\r\nx-test-original-target: %s\r\n\r\n",
					authority,
					authority,
					proxy,
				); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(connection)
				response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode == http.StatusOK {
					forwarded, err := reader.ReadString('\n')
					if err != nil || forwarded != authority+"\n" {
						t.Fatalf("proxy received authority %q: %v", forwarded, err)
					}
				}
				return response.StatusCode
			}
			for i, denied := range [][]string{nil, {originIP.String() + "/32"}, nil} {
				want, proxyWant := http.StatusOK, http.StatusOK
				if len(denied) > 0 {
					want = http.StatusServiceUnavailable
					proxyWant = http.StatusForbidden
				}
				if i > 0 {
					update(fmt.Sprint(i+1), denied, port)
				}
				deadline := time.Now().Add(10 * time.Second)
				for {
					status, proxyStatus := request(false), proxyRequest(false)
					if status == want && proxyStatus == proxyWant {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf(
							"update %d: HTTP/proxy status = %d/%d, want %d/%d",
							i, status, proxyStatus, want, proxyWant,
						)
					}
					time.Sleep(20 * time.Millisecond)
				}
				before, beforeEPE := originCalls.Load(), epeCalls.Load()
				if status := request(true); status != http.StatusServiceUnavailable {
					t.Fatalf("mandatory loopback restriction: status = %d", status)
				}
				if len(denied) > 0 && request(false) != want {
					t.Fatal("denied upstream became reachable")
				}
				if status := proxyRequest(true); status != http.StatusForbidden {
					t.Fatalf("loopback proxy status = %d", status)
				}
				if originCalls.Load() != before {
					t.Fatal("a denied request reached the origin")
				}
				if pinned && epeCalls.Load() == beforeEPE {
					t.Fatal("EPE was not called")
				}
			}
		})
	}
}

func TestEnvoyEgressAuthorizationCONNECT(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	b := &resourceBuilder{
		egressAuthorization: &configv1.EgressAuthorization{
			DeniedCidrs: []string{"100.100.100.200/32", "2001:db8::/64"},
		},
	}
	manager, err := b.buildConnectHCM(effectiveConfig{gateway: &configv1.EgressGateway{}})
	if err != nil {
		t.Fatal(err)
	}
	// Isolate admission from HBONE identity/Porter; TCP is checked after routing.
	manager.HttpFilters = []*hcmv3.HttpFilter{
		manager.HttpFilters[0],
		httpFilter("envoy.filters.http.router", b.pack(&routerv3.Router{})),
	}
	manager.RouteSpecifier = &hcmv3.HttpConnectionManager_RouteConfig{RouteConfig: &routev3.RouteConfiguration{
		Name: "admission",
		VirtualHosts: []*routev3.VirtualHost{{
			Name:    "all",
			Domains: []string{"*"},
			Routes: []*routev3.Route{
				{
					Match: &routev3.RouteMatch{
						PathSpecifier: &routev3.RouteMatch_ConnectMatcher_{
							ConnectMatcher: &routev3.RouteMatch_ConnectMatcher{},
						},
					},
					Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{Status: 200}},
				},
			}}},
	}}
	b.configureUDPHCM(manager)
	cfg := &bootstrapv3.Bootstrap{StaticResources: &bootstrapv3.Bootstrap_StaticResources{
		Clusters: []*clusterv3.Cluster{},
		Listeners: []*listenerv3.Listener{
			{
				Name:    "admission",
				Address: socketAddress("127.0.0.1", 0),
				FilterChains: []*listenerv3.FilterChain{
					{
						Filters: []*listenerv3.Filter{
							networkFilter("envoy.filters.network.http_connection_manager", b.pack(manager)),
						},
					},
				},
			},
		},
	},
		Admin: &bootstrapv3.Admin{Address: socketAddress("127.0.0.1", 0)}}
	data, err := protojson.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	address, _ := runCompatibilityEnvoy(t, binary, string(data))
	for _, udp := range []bool{false, true} {
		for _, ip := range []string{"127.0.0.1", "0.0.0.0", "169.254.169.254", "100.100.100.200", "::1", "::", "fe80::1", "::ffff:127.0.0.1", "2001:db8::1", "10.20.30.40"} {
			if udp && strings.Contains(ip, ":") {
				continue // The supported CONNECT-UDP contract is IPv4 only.
			}
			t.Run(fmt.Sprintf("udp=%t/%s", udp, ip), func(t *testing.T) {
				connection, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := connection.Close(); err != nil {
						t.Error(err)
					}
				}()
				if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				request := fmt.Sprintf(
					"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
					net.JoinHostPort(ip, "443"),
					net.JoinHostPort(ip, "443"),
				)
				if udp {
					request = fmt.Sprintf(
						"GET /.well-known/masque/udp/%s/443/ HTTP/1.1\r\nHost: gateway\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n",
						ip,
					)
				}
				if _, err := io.WriteString(connection, request); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(connection), nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				want := http.StatusForbidden
				if !udp || ip == "10.20.30.40" {
					want = http.StatusOK
				}
				if response.StatusCode != want {
					t.Fatalf("status = %d, want %d", response.StatusCode, want)
				}
			})
		}
	}
}
