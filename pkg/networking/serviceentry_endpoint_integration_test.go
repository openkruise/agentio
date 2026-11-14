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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	internal "github.com/envoyproxy/go-control-plane/envoy/extensions/bootstrap/internal_listener/v3"
	dfpcluster "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	dfphttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	dfpsni "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	cares "github.com/envoyproxy/go-control-plane/envoy/extensions/network/dns_resolver/cares/v3"
	tlsconfig "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	extprocservice "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	mdns "github.com/miekg/dns"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/security/pki"
)

// Exercise production endpoint binding through CONNECT, internal listeners, EPE,
// and real TLS. The DNS server counts packets and returns NXDOMAIN for every name.
func TestEnvoyEndpointServiceEntry(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	test.SetForTest(t, &features.EnableSNITrafficPolicy, false)
	ca, err := pki.NewSelfSignedCA("endpoint-binding-test", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.GenerateRSA(t.Context(), pki.LeafOptions{
		DNSNames:    []string{"allowed.invalid", "other.invalid", "shared.invalid", "unrelated.invalid"},
		Server:      true,
		CurrentTime: time.Now(),
		Lifetime:    30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(leaf.CertificatePEM, leaf.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertificatePEM())
	rootPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(rootPath, ca.CertificatePEM(), 0600); err != nil {
		t.Fatal(err)
	}
	test.SetForTest(t, &features.GatewayRootCAPath, rootPath)
	for _, mode := range []string{"http", "http_no_epe", "passthrough", "terminate", "terminate_no_epe", "passthrough_policy", "terminate_policy"} {
		t.Run(mode, func(t *testing.T) {
			test.SetForTest(t, &features.EnableSNITrafficPolicy, strings.HasSuffix(mode, "policy"))
			var originCalls, originHandshakes, originConnections, dnsQueries, epeCalls atomic.Int64
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originCalls.Add(1)
				sni := ""
				if r.TLS != nil {
					sni = r.TLS.ServerName
				}
				body := fmt.Sprintf("%s|%s|%s", r.Context().Value(http.LocalAddrContextKey), r.Host, sni)
				if r.Method == http.MethodConnect {
					conn, buffer, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := fmt.Fprintf(
						buffer,
						"HTTP/1.1 200 Connection Established\r\n\r\n%s",
						body,
					); err != nil {
						t.Error(err)
					}
					if err := buffer.Flush(); err != nil {
						t.Error(err)
					}
					if err := conn.Close(); err != nil {
						t.Logf("close CONNECT origin: %v", err)
					}
					return
				}
				if _, err := io.WriteString(w, body); err != nil {
					t.Errorf("origin response: %v", err)
				}
			}))
			origin.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					originConnections.Add(1)
				}
			}
			if err := origin.Listener.Close(); err != nil {
				t.Fatal(err)
			}
			origin.Listener, err = net.Listen("tcp4", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			isPassthrough := strings.HasPrefix(mode, "passthrough")
			isTLS := isPassthrough || strings.HasPrefix(mode, "terminate")
			if isTLS {
				origin.TLS = &tls.Config{
					Certificates: []tls.Certificate{certificate},
					MinVersion:   tls.VersionTLS12,
					GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
						originHandshakes.Add(1)
						return nil, nil
					},
				}
				origin.StartTLS()
			} else {
				origin.Start()
			}
			t.Cleanup(origin.Close)
			originPort := uint32(origin.Listener.Addr().(*net.TCPAddr).Port)
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			dnsStarted := make(chan struct{})
			dnsDone := make(chan error, 1)
			dnsServer := &mdns.Server{PacketConn: packet,
				NotifyStartedFunc: func() { close(dnsStarted) },
				Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
					dnsQueries.Add(1)
					response := new(mdns.Msg)
					response.SetRcode(request, mdns.RcodeNameError)
					if err := w.WriteMsg(response); err != nil {
						t.Errorf("DNS response: %v", err)
					}
				}),
			}
			go func() { dnsDone <- dnsServer.ActivateAndServe() }()
			<-dnsStarted
			t.Cleanup(func() {
				if err := dnsServer.Shutdown(); err != nil {
					t.Error(err)
				}
				if err := <-dnsDone; err != nil {
					t.Error(err)
				}
			})
			dnsAddress := packet.LocalAddr().(*net.UDPAddr)
			epePort := uint32(0)
			if !isPassthrough && !strings.HasSuffix(mode, "no_epe") {
				dnsClient := dns.NewClient(dns.NewTransport([]string{dnsAddress.String()}, time.Second), time.Second)
				processor := grpc.NewServer()
				extprocservice.RegisterExternalProcessorServer(processor, extproc.NewServer(extproc.ServerDeps{
					AuthorizeRequest: func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
						epeCalls.Add(1)
						if stream.Request.Method == http.MethodConnect {
							if stream.Upstream != nil {
								t.Error("application CONNECT acquired a ServiceEntry target")
							}
						} else if stream.Request.OriginalDestination.Addr().String() != "127.0.0.3" &&
							(stream.Upstream == nil || *stream.Upstream.Address != stream.Request.OriginalDestination) {
							t.Errorf(
								"EPE lost original target: upstream=%v original=%v",
								stream.Upstream,
								stream.Request.OriginalDestination,
							)
						}
						if stream.Request.OriginalDestination.Addr().String() == "127.0.0.3" && stream.Upstream != nil {
							t.Error("an unmatched endpoint acquired a pinned target")
						}
						cfg := egressauthz.Config{}
						if stream.Request.Path == "/deny" {
							cfg.DeniedCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
						}
						return egressauthz.NewAggregate(dnsClient, cfg).Authorize(ctx, stream)
					},
				}))
				rpc, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				epePort = uint32(rpc.Addr().(*net.TCPAddr).Port)
				go func() {
					if err := processor.Serve(rpc); err != nil {
						t.Errorf("EPE server: %v", err)
					}
				}()
				t.Cleanup(processor.Stop)
			}
			config := endpointServiceEntryConfig(t, mode, epePort, uint32(dnsAddress.Port), leaf)
			address, _ := runCompatibilityEnvoy(t, binary, config)
			type trafficCase struct {
				name   string
				ip     string
				sni    string
				host   string
				path   string
				status int
			}
			cases := []trafficCase{
				{"allowed", "127.0.0.1", "allowed.invalid", "allowed.invalid", "/", 200},
				{"second_endpoint", "127.0.0.2", "other.invalid", "other.invalid", "/", 200},
				{"wrong_host", "127.0.0.1", "allowed.invalid", "unrelated.invalid", "/", 403},
				{"host_for_other_endpoint", "127.0.0.1", "allowed.invalid", "other.invalid", "/", 403},
				{"shared_endpoint", "127.0.0.1", "shared.invalid", "shared.invalid", "/", 200},
				{"preserve_selected_endpoint", "127.0.0.2", "allowed.invalid", "allowed.invalid", "/", 200},
				{"authority_port", "127.0.0.1", "allowed.invalid", "allowed.invalid:1", "/", 200},
				{"uppercase", "127.0.0.1", "ALLOWED.invalid", "ALLOWED.invalid", "/", 200},
				{"trailing_dot", "127.0.0.1", "allowed.invalid.", "allowed.invalid.", "/", 200},
				{"connect", "127.0.0.1", "allowed.invalid", "127.0.0.1:443", "/", 200},
			}
			if isPassthrough {
				// Passthrough can validate SNI, but cannot inspect the encrypted Host.
				cases[2].status, cases[3].status = 200, 200
				cases = append(
					cases,
					trafficCase{"unmatched_ip_without_sni", "127.0.0.3", "", "unrelated.invalid", "/", 0},
				)
			}
			cases = append(cases, trafficCase{"opaque", "127.0.0.1", "", "", "/", 0})
			if isTLS {
				cases = append(cases,
					trafficCase{"wrong_sni", "127.0.0.1", "unrelated.invalid", "allowed.invalid", "/", 0},
					trafficCase{"sni_for_other_endpoint", "127.0.0.1", "other.invalid", "other.invalid", "/", 0},
					trafficCase{"missing_sni", "127.0.0.1", "", "allowed.invalid", "/", 0},
				)
				if !isPassthrough {
					cases = append(cases, trafficCase{"post_tls_tcp", "127.0.0.1", "allowed.invalid", "", "/", 200})
				}
			}
			if epePort != 0 {
				cases = append(
					cases,
					trafficCase{"epe_denial", "127.0.0.1", "allowed.invalid", "allowed.invalid", "/deny", 403},
				)
			}
			if features.EnableSNITrafficPolicy {
				cases = append(
					cases,
					trafficCase{"policy_denial", "127.0.0.1", "allowed.invalid", "allowed.invalid", "/", 0},
				)
			}
			fallbackStatus := 503
			if epePort != 0 {
				fallbackStatus = 500
			} else if isPassthrough {
				fallbackStatus = 0
			}
			cases = append(
				cases,
				trafficCase{"unmatched_ip", "127.0.0.3", "unrelated.invalid", "unrelated.invalid", "/", fallbackStatus},
			)
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					before, handshakes, authorized := originCalls.Load(), originHandshakes.Load(), epeCalls.Load()
					connections := originConnections.Load()
					conn, err := net.DialTimeout("tcp4", address, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := conn.Close(); err != nil {
							t.Logf("close test connection: %v", err)
						}
					}()
					if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					target := net.JoinHostPort(tc.ip, strconv.Itoa(int(originPort)))
					action := ""
					if tc.name == "policy_denial" {
						action = "X-Test-TLS-Action: deny\r\n"
					}
					if _, err := fmt.Fprintf(
						conn,
						"CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n",
						target,
						target,
						action,
					); err != nil {
						t.Fatal(err)
					}
					response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
					if err != nil || response.StatusCode != 200 {
						t.Fatalf("CONNECT: %v %v", response, err)
					}
					if tc.name == "opaque" {
						if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
							t.Fatal(err)
						}
						if _, err := conn.Write([]byte("\x00opaque")); err != nil {
							t.Fatal(err)
						}
						buffer := make([]byte, 1)
						if n, err := conn.Read(
							buffer,
						); n != 0 || err == nil || originConnections.Load() != connections ||
							dnsQueries.Load() != 0 {
							t.Fatalf("opaque TCP bypassed endpoint identity binding: n=%d error=%v", n, err)
						}
						return
					}
					if isTLS {
						client := tls.Client(
							conn,
							&tls.Config{
								RootCAs:            roots,
								ServerName:         tc.sni,
								MinVersion:         tls.VersionTLS12,
								InsecureSkipVerify: tc.sni == "", // Negative test: omit SNI independently of certificate verification.
							},
						)
						err := client.Handshake()
						if tc.status == 0 {
							if err == nil || originHandshakes.Load() != handshakes {
								t.Fatalf(
									"invalid SNI reached origin: handshake=%v origin handshakes=%d",
									err,
									originHandshakes.Load()-handshakes,
								)
							}
							if (dnsQueries.Load() > 0) != (tc.name == "unmatched_ip") {
								t.Fatalf("unexpected DNS packets: %d", dnsQueries.Load())
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						conn = client
					}
					if tc.name == "post_tls_tcp" {
						if _, err := conn.Write([]byte("\x00opaque\r\n\r\n")); err != nil {
							t.Fatal(err)
						}
						response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
						if err != nil {
							t.Fatal(err)
						}
						if err := response.Body.Close(); err != nil {
							t.Fatal(err)
						}
						if response.StatusCode != 400 || originHandshakes.Load() != handshakes+1 ||
							dnsQueries.Load() != 0 {
							t.Fatalf("opaque TLS did not reach the bound endpoint without DNS: %s", response.Status)
						}
						return
					}
					method, path := http.MethodGet, tc.path
					if tc.name == "connect" {
						method, path = http.MethodConnect, tc.host
					}
					if _, err := fmt.Fprintf(
						conn,
						"%s %s HTTP/1.1\r\nHost: %s\r\nagentio.route.upstream: 127.0.0.99:1\r\n\r\n",
						method,
						path,
						tc.host,
					); err != nil {
						t.Fatal(err)
					}
					reader := bufio.NewReader(conn)
					response, err = http.ReadResponse(reader, &http.Request{Method: method})
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					if err := response.Body.Close(); err != nil {
						t.Fatal(err)
					}
					if err != nil || response.StatusCode != tc.status {
						t.Fatalf("response: %s %q %v, want %d", response.Status, body, err, tc.status)
					}
					if tc.status == 200 {
						parts := strings.SplitN(string(body), "|", 3)
						if len(parts) != 3 || parts[0] != target || parts[1] != tc.host ||
							(isTLS && !strings.EqualFold(parts[2], strings.TrimSuffix(tc.sni, "."))) {
							t.Fatalf(
								"origin = %q, want original address %s Host %s SNI %s",
								body,
								target,
								tc.host,
								tc.sni,
							)
						}
						if epePort != 0 && epeCalls.Load() != authorized+1 {
							t.Fatal("explicit target skipped EPE authorization")
						}
						if !isPassthrough && method != http.MethodConnect {
							// A second request on the same connection must re-check Host.
							if _, err := io.WriteString(
								conn,
								"GET / HTTP/1.1\r\nHost: unrelated.invalid\r\n\r\n",
							); err != nil {
								t.Fatal(err)
							}
							second, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
							if err != nil || second.StatusCode != 403 {
								t.Fatalf("reused connection accepted another Host: %v %v", second, err)
							}
							if err := second.Body.Close(); err != nil {
								t.Fatal(err)
							}
							if originCalls.Load() != before+1 {
								t.Fatal("reused connection bypassed Host guard")
							}
						}
					} else if originCalls.Load() != before {
						t.Fatal("denied request reached origin")
					}
					if tc.name != "epe_denial" && tc.status == 403 && epeCalls.Load() != authorized {
						t.Fatal("Host mismatch was not rejected before EPE")
					}
					if (dnsQueries.Load() > 0) != (tc.name == "unmatched_ip") {
						t.Fatalf("unexpected DNS packets: %d", dnsQueries.Load())
					}
				})
			}
			t.Logf(
				"mode=%s origin requests=%d EPE authorizations=%d DNS packets=%d",
				mode,
				originCalls.Load(),
				epeCalls.Load(),
				dnsQueries.Load(),
			)
		})
	}
}

func endpointServiceEntryConfig(
	t *testing.T,
	mode string,
	epePort, dnsPort uint32,
	certificate pki.IssuedCertificate,
) string {
	t.Helper()
	b := &resourceBuilder{}
	config := effectiveConfig{gateway: &configv1.EgressGateway{ServiceEntries: []*configv1.EgressServiceEntry{
		{
			Hosts:     []string{"allowed.invalid"},
			Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "127.0.0.1"}, {Address: "127.0.0.2"}},
		},
		{Hosts: []string{"other.invalid"}, Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "127.0.0.2"}}},
		{Hosts: []string{"shared.invalid"}, Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "127.0.0.1"}}},
	}}}
	if strings.HasPrefix(mode, "terminate") {
		config.gateway.TlsTermination = &configv1.TlsTerminationConfig{IncludeHosts: []string{"*"}}
	}
	if epePort != 0 {
		config.extProc = &configv1.ExtProcProvider{Service: "127.0.0.1", Port: epePort, MessageTimeout: "1s"}
	}
	listeners, err := b.buildListeners(config, "cluster.local")
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := b.buildClusters(config)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := b.buildRoutes(config.gateway)
	if err != nil {
		t.Fatal(err)
	}
	outer := &hcm.HttpConnectionManager{
		StatPrefix:     "connect",
		UpgradeConfigs: []*hcm.HttpConnectionManager_UpgradeConfig{{UpgradeType: "CONNECT"}},
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{RouteConfig: routes[0]},
		HttpFilters: []*hcm.HttpFilter{connectAuthorityHTTPFilter,
			httpFilter("envoy.filters.http.router", b.pack(&router.Router{}))},
	}
	if features.EnableSNITrafficPolicy {
		action := "passthrough"
		if strings.HasPrefix(mode, "terminate") {
			action = "terminate"
		}
		// Inject the module decision so this test needs only the stock Envoy binary.
		decision := httpFilter(
			"test.tls_action",
			b.pack(&httpstate.Config{OnRequestHeaders: []*common.FilterStateValue{{
				Key:                &common.FilterStateValue_ObjectKey{ObjectKey: tlsActionKey},
				FactoryKey:         "envoy.hashable_string",
				ReadOnly:           true,
				SharedWithUpstream: common.FilterStateValue_ONCE,
				Value: &common.FilterStateValue_FormatString{FormatString: formatString(
					"%CEL('x-test-tls-action' in request.headers ? request.headers['x-test-tls-action'] : '" + action + "')%",
				)},
			}}}),
		)
		outer.HttpFilters = append([]*hcm.HttpFilter{decision}, outer.HttpFilters...)
	}
	// Replace HBONE mTLS/Porter with HTTP CONNECT, keeping destination restoration.
	listeners[0] = &listener.Listener{
		Name:    "test",
		Address: socketAddress("127.0.0.1", 0),
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{networkFilter("envoy.filters.network.http_connection_manager", b.pack(outer))},
		}},
	}
	// Loopback origins are a harness-only exception; destination restrictions have separate runtime tests.
	cache := (&resourceBuilder{legacyGateway: true}).dnsCacheConfig()
	cache.TypedDnsResolverConfig = typedCoreExtension(
		"envoy.network.dns_resolver.cares",
		b.pack(&cares.CaresDnsResolverConfig{
			Resolvers:          []*core.Address{socketAddress("127.0.0.1", dnsPort)},
			DnsResolverOptions: &core.DnsResolverOptions{NoDefaultSearchDomain: true},
		}),
	)
	for _, l := range listeners {
		l.ListenerFilters = slices.DeleteFunc(l.ListenerFilters, func(f *listener.ListenerFilter) bool {
			return f.Name == "envoy.filters.listener.dynamic_modules"
		})
		for _, chain := range l.FilterChains {
			// The stock-Envoy fixture injects policy decisions and tests endpoint binding.
			chain.Filters = slices.DeleteFunc(
				chain.Filters,
				func(f *listener.Filter) bool { return f.Name == "agentio.tcp_policy" },
			)
			if chain.Name == tlsTerminateChain {
				chain.TransportSocket.ConfigType = &core.TransportSocket_TypedConfig{
					TypedConfig: b.pack(&tlsconfig.DownstreamTlsContext{
						CommonTlsContext: &tlsconfig.CommonTlsContext{TlsCertificates: []*tlsconfig.TlsCertificate{
							{
								CertificateChain: &core.DataSource{
									Specifier: &core.DataSource_InlineBytes{InlineBytes: certificate.CertificatePEM},
								},
								PrivateKey: &core.DataSource{
									Specifier: &core.DataSource_InlineBytes{InlineBytes: certificate.PrivateKeyPEM},
								},
							},
						}},
					}),
				}
			}
			for _, f := range chain.Filters {
				switch f.Name {
				case "envoy.filters.network.http_connection_manager":
					manager := &hcm.HttpConnectionManager{}
					if err := f.GetTypedConfig().UnmarshalTo(manager); err != nil {
						t.Fatal(err)
					}
					manager.HttpFilters = slices.DeleteFunc(manager.HttpFilters, func(filter *hcm.HttpFilter) bool {
						return filter.Name == "agentio.connect_proxy_authorization"
					})
					if rds := manager.GetRds(); rds != nil {
						manager.RouteSpecifier = &hcm.HttpConnectionManager_RouteConfig{
							RouteConfig: b.buildForwardRoute(rds.RouteConfigName, config.gateway),
						}
					}
					for _, hf := range manager.HttpFilters {
						if hf.Name == "envoy.filters.http.dynamic_forward_proxy" {
							hf.ConfigType = &hcm.HttpFilter_TypedConfig{TypedConfig: b.pack(&dfphttp.FilterConfig{
								ImplementationSpecifier: &dfphttp.FilterConfig_DnsCacheConfig{
									DnsCacheConfig: cache,
								},
								AllowDynamicHostFromFilterState: true,
							})}
						}
					}
					f.ConfigType = &listener.Filter_TypedConfig{TypedConfig: b.pack(manager)}
				case "envoy.filters.network.sni_dynamic_forward_proxy":
					cfg := &dfpsni.FilterConfig{}
					if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
						t.Fatal(err)
					}
					cfg.DnsCacheConfig = cache
					f.ConfigType = &listener.Filter_TypedConfig{TypedConfig: b.pack(cfg)}
				}
			}
		}
	}
	for _, c := range clusters {
		if c.GetClusterType().GetName() == "envoy.clusters.dynamic_forward_proxy" {
			cfg := &dfpcluster.ClusterConfig{}
			if err := c.GetClusterType().GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			cfg.ClusterImplementationSpecifier = &dfpcluster.ClusterConfig_DnsCacheConfig{DnsCacheConfig: cache}
			c.GetClusterType().TypedConfig = b.pack(cfg)
		}
	}
	if b.err != nil {
		t.Fatal(b.err)
	}
	data, err := protojson.Marshal(&bootstrap.Bootstrap{
		BootstrapExtensions: []*core.TypedExtensionConfig{
			typedCoreExtension("envoy.bootstrap.internal_listener", b.pack(&internal.InternalListener{})),
		},
		StaticResources: &bootstrap.Bootstrap_StaticResources{Listeners: listeners, Clusters: clusters},
		Admin:           &bootstrap.Admin{Address: socketAddress("127.0.0.1", 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
