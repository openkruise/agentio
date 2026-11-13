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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	internal "github.com/envoyproxy/go-control-plane/envoy/extensions/bootstrap/internal_listener/v3"
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	httpstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	tlsconfig "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/security/pki"
)

// Uses generated post-termination filters and clusters with real TLS on both
// sides. Static certificates and original-destination capture replace SDS/HBONE.
func TestEnvoyPostTLSForwarding(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	// Docker resolves its hostname to a non-loopback interface address, which
	// keeps successful DFP requests outside the default denied ranges.
	upstreamHost, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewSelfSignedCA("post-tls-test", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertificatePEM())
	certificates := map[string]tls.Certificate{}
	leaves := map[string]pki.IssuedCertificate{}
	for _, name := range []string{upstreamHost, "localhost", "inner.invalid"} {
		leaf, err := ca.GenerateRSA(t.Context(), pki.LeafOptions{
			DNSNames:    []string{name},
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
		certificates[name], leaves[name] = certificate, leaf
	}
	rootPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(rootPath, ca.CertificatePEM(), 0600); err != nil {
		t.Fatal(err)
	}
	test.SetForTest(t, &features.GatewayRootCAPath, rootPath)
	payload := []byte("\x00opaque application bytes after TLS termination")
	for _, mode := range []string{
		"tcp", "nested_tls", "bad_certificate", "idle", "loopback_tcp",
		"passthrough", "passthrough_no_sni", "passthrough_dns_failure", "passthrough_loopback",
		"passthrough_port_override",
		"http1", "http2", "fqdn_http1", "fqdn_http2",
		"loopback_http1", "loopback_http2", "connect_http1", "connect_http2", "connect_pinned_http1", "connect_pinned_http2",
	} {
		t.Run(mode, func(t *testing.T) {
			isHTTP := strings.Contains(mode, "http")
			passthrough := strings.HasPrefix(mode, "passthrough")
			serverName := upstreamHost
			if strings.Contains(mode, "loopback") {
				serverName = "localhost"
			}
			closeResource := func(resource io.Closer) {
				if err := resource.Close(); err != nil {
					t.Logf("close test transport: %v", err)
				}
			}
			var handshakes atomic.Int32
			upstreamTLS := &tls.Config{
				Certificates: []tls.Certificate{certificates[serverName]},
				MinVersion:   tls.VersionTLS12,
			}
			if mode == "bad_certificate" {
				upstreamTLS.Certificates = []tls.Certificate{certificates["inner.invalid"]}
			}
			upstreamTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				handshakes.Add(1)
				if hello.ServerName != serverName {
					return nil, fmt.Errorf("upstream SNI = %q, want outer %s", hello.ServerName, serverName)
				}
				if !isHTTP && len(hello.SupportedProtos) != 0 {
					return nil, fmt.Errorf("TCP advertised ALPN %v", hello.SupportedProtos)
				}
				return nil, nil
			}
			var upstreamAddress string
			completed := make(chan error, 1)
			if isHTTP {
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodConnect && r.ProtoMajor == 1 {
						conn, buffer, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Errorf("hijack CONNECT: %v", err)
							return
						}
						defer closeResource(conn)
						if _, err := fmt.Fprintf(
							buffer,
							"HTTP/1.1 200 Connection Established\r\n\r\n%s %s",
							r.Method,
							r.Proto,
						); err != nil {
							t.Errorf("CONNECT response: %v", err)
						}
						if err := buffer.Flush(); err != nil {
							t.Errorf("flush CONNECT: %v", err)
						}
						return
					}
					if _, err := fmt.Fprintf(w, "%s %s %s", r.Method, r.Proto, r.Host); err != nil {
						t.Errorf("HTTP origin: %v", err)
					}
				}))
				closeResource(origin.Listener)
				origin.Listener, err = net.Listen("tcp4", net.JoinHostPort(serverName, "0"))
				if err != nil {
					t.Fatal(err)
				}
				origin.EnableHTTP2 = strings.HasSuffix(mode, "http2")
				origin.TLS = upstreamTLS
				origin.StartTLS()
				t.Cleanup(origin.Close)
				upstreamAddress = origin.Listener.Addr().String()
			} else {
				origin, err := tls.Listen("tcp4", net.JoinHostPort(serverName, "0"), upstreamTLS)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { closeResource(origin) })
				upstreamAddress = origin.Addr().String()
				go func() {
					conn, err := origin.Accept()
					if err != nil {
						completed <- err
						return
					}
					defer closeResource(conn)
					if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						completed <- err
						return
					}
					if mode == "nested_tls" {
						conn = tls.Server(
							conn,
							&tls.Config{
								Certificates: []tls.Certificate{certificates["inner.invalid"]},
								MinVersion:   tls.VersionTLS12,
							},
						)
					}
					data := make([]byte, len(payload))
					if _, err := io.ReadFull(conn, data); err != nil {
						completed <- err
						return
					}
					if !bytes.Equal(data, payload) {
						completed <- fmt.Errorf("payload changed: %q", data)
						return
					}
					_, err = conn.Write(data)
					completed <- err
				}()
			}
			_, upstreamPort, err := net.SplitHostPort(upstreamAddress)
			if err != nil {
				t.Fatal(err)
			}
			// A connection to the original IP would fail; only SNI resolution reaches the origin.
			original := net.JoinHostPort("127.0.0.2", upstreamPort)
			if mode == "passthrough_port_override" {
				original = "127.0.0.2:443"
			}
			address := startTLSEnvoy(t, binary, original, leaves[serverName], mode)
			clientTLS := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}
			if mode == "passthrough_no_sni" {
				clientTLS.ServerName = "127.0.0.1" // Go omits SNI for literal IPs.
			} else if mode == "passthrough_dns_failure" {
				clientTLS.ServerName = "unresolvable.invalid"
			} else if mode == "passthrough_port_override" {
				clientTLS.ServerName = net.JoinHostPort(upstreamHost, upstreamPort)
			}
			if strings.HasPrefix(mode, "connect") && strings.HasSuffix(mode, "http1") {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, clientTLS)
				if err != nil {
					t.Fatal(err)
				}
				defer closeResource(conn)
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(
					conn,
					"CONNECT inner.invalid:443 HTTP/1.1\r\nHost: inner.invalid:443\r\n\r\n",
				); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(conn)
				response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
				if err != nil {
					t.Fatal(err)
				}
				defer closeResource(response.Body)
				body := make([]byte, len("CONNECT HTTP/1.1"))
				if _, err := io.ReadFull(reader, body); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 200 || string(body) != "CONNECT HTTP/1.1" {
					t.Fatalf("CONNECT response = %s %q", response.Status, body)
				}
				return
			}
			if isHTTP {
				transport := &http.Transport{
					TLSClientConfig:   clientTLS,
					ForceAttemptHTTP2: strings.HasSuffix(mode, "http2"),
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp", address)
					},
				}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				method := http.MethodGet
				if strings.HasPrefix(mode, "connect") {
					method = http.MethodConnect
				}
				_, port, err := net.SplitHostPort(upstreamAddress)
				if err != nil {
					t.Fatal(err)
				}
				request, err := http.NewRequest(method, "https://"+net.JoinHostPort(serverName, port)+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				if method == http.MethodConnect {
					request.Host = "inner.invalid:443"
				} else if strings.HasPrefix(mode, "fqdn") {
					request.Host = net.JoinHostPort(serverName+".", port)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer closeResource(response.Body)
				protocol := "HTTP/1.1"
				if strings.HasSuffix(mode, "http2") {
					protocol = "HTTP/2.0"
				}
				if strings.HasPrefix(mode, "loopback") {
					body, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != http.StatusServiceUnavailable ||
						!strings.Contains(string(body), "DNS resolution failure") {
						t.Fatalf("denied destination response = %s %q", response.Status, body)
					}
					if handshakes.Load() != 0 {
						t.Fatal("denied destination opened an upstream TLS connection")
					}
					return
				}
				wantBody := method + " " + protocol + " " + request.Host
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 200 || string(body) != wantBody || response.Proto != protocol {
					t.Fatalf(
						"response = %s %s %q, want %s %q",
						response.Status,
						response.Proto,
						body,
						protocol,
						wantBody,
					)
				}
				return
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", address, clientTLS)
			if passthrough && mode != "passthrough" {
				if err == nil {
					closeResource(conn)
					t.Fatal("invalid TLS destination completed a handshake")
				}
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					t.Fatalf("invalid TLS destination timed out instead of closing: %v", err)
				}
				if handshakes.Load() != 0 {
					t.Fatal("invalid TLS destination opened an upstream connection")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer closeResource(conn)
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if mode == "nested_tls" {
				conn = tls.Client(
					conn,
					&tls.Config{RootCAs: roots, ServerName: "inner.invalid", MinVersion: tls.VersionTLS12},
				)
			}
			if mode != "idle" {
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			data := make([]byte, len(payload))
			_, err = io.ReadFull(conn, data)
			if mode == "idle" || mode == "bad_certificate" || mode == "loopback_tcp" {
				var timeout net.Error
				if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
					t.Fatalf("expected connection close, got data=%q error=%v", data, err)
				}
				if (mode == "idle" || mode == "loopback_tcp") && handshakes.Load() != 0 {
					t.Fatal("denied connection opened an upstream connection")
				}
				if mode == "bad_certificate" && handshakes.Load() != 1 {
					t.Fatal("certificate rejection must exercise the original upstream TLS handshake")
				}
				return
			}
			if err != nil || !bytes.Equal(data, payload) {
				t.Fatalf("echo = %q, error = %v", data, err)
			}
			if err := <-completed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func startTLSEnvoy(t *testing.T, binary, upstream string, certificate pki.IssuedCertificate, mode string) string {
	t.Helper()
	b := &resourceBuilder{}
	config := effectiveConfig{gateway: &configv1.EgressGateway{}}
	listeners, err := b.buildListeners(config, "cluster.local")
	if err != nil {
		t.Fatal(err)
	}
	var forward, internalListener *listener.Listener
	for _, candidate := range listeners {
		if candidate.GetName() == MainForward {
			forward = candidate
		} else if candidate.GetName() == MainInternal {
			internalListener = candidate
		}
	}
	// This stock-Envoy fixture tests forwarding; policy authorization is covered by the module smoke tests.
	for _, candidate := range listeners {
		for _, chain := range candidate.FilterChains {
			chain.Filters = slices.DeleteFunc(
				chain.Filters,
				func(f *listener.Filter) bool { return f.Name == "agentio.tcp_policy" },
			)
		}
	}
	manager := findHCM(t, forward)
	manager.RouteSpecifier = &hcm.HttpConnectionManager_RouteConfig{
		RouteConfig: b.buildForwardRoute(TLSConnectOriginate, config.gateway),
	}
	if strings.HasPrefix(mode, "connect_pinned") {
		// Model EPE's mutable host and read-only inner port before proxy target selection.
		manager.HttpFilters = append([]*hcm.HttpFilter{httpFilter("test.pinned_target", b.pack(&httpstate.Config{
			OnRequestHeaders: []*common.FilterStateValue{
				{
					Key:   &common.FilterStateValue_ObjectKey{ObjectKey: dynamicHostKey},
					Value: &common.FilterStateValue_FormatString{FormatString: formatString("127.0.0.1")},
				},
				{
					Key:      &common.FilterStateValue_ObjectKey{ObjectKey: dynamicPortKey},
					Value:    &common.FilterStateValue_FormatString{FormatString: formatString("443")},
					ReadOnly: true,
				},
			},
		}))}, manager.HttpFilters...)
	}
	findFilterChain(t, forward, forwardHTTPChain).Filters[0] = networkFilter(
		"envoy.filters.network.http_connection_manager",
		b.pack(manager),
	)
	chain := b.buildTLSTerminateChain(nil)
	chain.TransportSocket.ConfigType = &core.TransportSocket_TypedConfig{
		TypedConfig: b.pack(&tlsconfig.DownstreamTlsContext{
			CommonTlsContext: &tlsconfig.CommonTlsContext{
				AlpnProtocols: []string{"h2", "http/1.1"},
				TlsCertificates: []*tlsconfig.TlsCertificate{
					{
						CertificateChain: &core.DataSource{
							Specifier: &core.DataSource_InlineBytes{InlineBytes: certificate.CertificatePEM},
						},
						PrivateKey: &core.DataSource{
							Specifier: &core.DataSource_InlineBytes{InlineBytes: certificate.PrivateKeyPEM},
						},
					},
				},
			},
		}),
	}
	if strings.HasPrefix(mode, "passthrough") {
		chain = findFilterChain(t, internalListener, forwardTLSChain)
	}
	chain.Filters = append(
		[]*listener.Filter{networkFilter("envoy.filters.network.set_filter_state", b.pack(&state.Config{
			OnNewConnection: []*common.FilterStateValue{{
				Key:   &common.FilterStateValue_ObjectKey{ObjectKey: "envoy.filters.listener.original_dst.local_ip"},
				Value: &common.FilterStateValue_FormatString{FormatString: formatString(upstream)},
			}},
		}))},
		chain.Filters...)
	port, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := port.Addr().(*net.TCPAddr)
	if err := port.Close(); err != nil {
		t.Fatal(err)
	}
	bootstrapConfig := &bootstrap.Bootstrap{
		BootstrapExtensions: []*core.TypedExtensionConfig{
			{Name: "envoy.bootstrap.internal_listener", TypedConfig: b.pack(&internal.InternalListener{})},
		},
		StaticResources: &bootstrap.Bootstrap_StaticResources{
			Listeners: []*listener.Listener{forward, {
				Name:            "outer",
				Address:         socketAddress("127.0.0.1", uint32(address.Port)),
				ListenerFilters: []*listener.ListenerFilter{tlsInspectorFilter},
				FilterChains:    []*listener.FilterChain{chain},
				FilterChainMatcher: b.sniHostnameMatcher(exactMatcher(transportProtocolInput,
					map[string]*xdsmatcher.Matcher_OnMatch{"tls": b.toChain(chain.Name)}, nil)),
			}},
			Clusters: []*cluster.Cluster{
				b.buildInternalCluster(MainForward),
				b.buildTLSProxyOriginateCluster(nil),
				b.buildDFPCluster(TLSConnectOriginate, false, true, nil),
				b.buildDFPCluster(TLSPassthrough, true, false, nil),
			},
		},
	}
	if b.err != nil {
		t.Fatal(b.err)
	}
	data, err := protojson.Marshal(bootstrapConfig)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "envoy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cmd := exec.Command(binary, "-c", path, "--concurrency", "1", "--disable-hot-restart", "--log-level", "warning")
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error(err)
		}
		if err := cmd.Wait(); err != nil {
			if exitErr, ok := errors.AsType[*exec.ExitError](err); !ok || exitErr.ExitCode() != -1 {
				t.Errorf("Envoy exited: %v", err)
			}
		}
		if t.Failed() {
			t.Logf("Envoy: %s", logs.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address.String(), 100*time.Millisecond)
		if err == nil {
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			return address.String()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Envoy did not start")
	return ""
}
