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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	external "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	extprocservice "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/dns"
)

// Exercises generated HTTP filters/routes against a real Envoy and the real
// EPE ext_proc adapter/authorizer. Only identity/original-destination capture
// is supplied by the harness instead of a full HBONE TLS connection.
func TestEnvoyServiceEntryAuthorization(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	testEnvoyServiceEntryAuthorization(t, binary, false)
}

func TestLegacyEnvoyServiceEntryAuthorization(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_LEGACY_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_LEGACY_ENVOY_BINARY")
	}
	testEnvoyServiceEntryAuthorization(t, binary, true)
}

func testEnvoyServiceEntryAuthorization(t *testing.T, binary string, legacy bool) {
	for _, mode := range []string{"authorization", "routing_only", "no_epe", "explicit_without_serviceentry"} {
		t.Run(mode, func(t *testing.T) {
			enabled := mode == "authorization" || mode == "explicit_without_serviceentry"
			var originCalls atomic.Int64
			var resolutionCalls atomic.Int64
			var processingCalls atomic.Int64
			dnsClient := dns.NewClient(serviceEntryDNS{}, time.Second)
			var noServiceCalls atomic.Int64
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originCalls.Add(1)
				if _, err := fmt.Fprintf(w, "%s %s", r.Context().Value(http.LocalAddrContextKey), r.Host); err != nil {
					t.Errorf("origin response: %v", err)
				}
			}))
			var err error
			if err := origin.Listener.Close(); err != nil {
				t.Fatal(err)
			}
			origin.Listener, err = net.Listen("tcp4", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			origin.Start()
			t.Cleanup(origin.Close)
			port := origin.Listener.Addr().(*net.TCPAddr).Port
			replacement := netip.MustParseAddrPort(net.JoinHostPort("127.0.0.3", strconv.Itoa(port)))
			regs, err := filter.Build(filter.Define(filter.Descriptor[bool]{
				Name:   "test-routing",
				Phases: filter.PhaseRequestHeaders,
				New:    func(filter.RuleConfig[bool]) filter.Filter { return &serviceEntryTestFilter{replacement: replacement} },
			}, func(json.RawMessage) (bool, error) { return true, nil }))
			if err != nil {
				t.Fatal(err)
			}
			deps := extproc.ServerDeps{
				Registrations:               regs,
				FailClosedOnMissingIdentity: true,
				Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
					resolutionCalls.Add(1)
					return engine.Resolution{Units: []engine.Unit{{Cfgs: []any{true}}}}, nil
				},
			}
			if enabled {
				deps.AuthorizeRequest = func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
					if stream.Request.Path == "/no-service" {
						noServiceCalls.Add(1)
						if stream.Upstream != nil {
							t.Error("candidate leaked across requests")
						}
					}
					cfg := egressauthz.Config{
						Policies: []egressauthz.Policy{{
							Name: "allowed",
							Rules: []egressauthz.Rule{
								{
									Action: egressauthz.Allow,
									CIDRs: []netip.Prefix{
										netip.MustParsePrefix("127.0.0.1/32"),
										netip.MustParsePrefix("127.0.0.3/32"),
									},
									Ports: []egressauthz.PortRange{{Start: uint16(port)}},
								},
							}}},
					}
					// Supply the restored address missing from this direct HTTP listener.
					stream.Request.OriginalDestination = replacement
					return egressauthz.NewAggregate(dnsClient, cfg).Authorize(ctx, stream)
				}
			}
			processor := grpc.NewServer(grpc.StreamInterceptor(func(
				srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler,
			) error {
				processingCalls.Add(1)
				return handler(srv, stream)
			}))
			extprocservice.RegisterExternalProcessorServer(processor, extproc.NewServer(deps))
			rpc, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				if err := processor.Serve(rpc); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
					t.Errorf("ext_proc server: %v", err)
				}
			}()
			t.Cleanup(processor.Stop)
			rpcPort := rpc.Addr().(*net.TCPAddr).Port
			gateway := &configv1.EgressGateway{ServiceEntries: []*configv1.EgressServiceEntry{
				{
					Hosts:     []string{"allowed.invalid"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "127.0.0.1"}},
				},
				{
					Hosts:     []string{"denied.invalid"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "127.0.0.2"}},
				},
				{
					Hosts:     []string{"mixed.invalid"},
					Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "127.0.0.1"}, {Address: "127.0.0.2"}},
				},
			}}
			if mode == "explicit_without_serviceentry" {
				gateway.ServiceEntries = nil
			}
			b := &resourceBuilder{legacyGateway: legacy}
			effective := effectiveConfig{
				gateway: gateway,
				extProc: &configv1.ExtProcProvider{
					Service:        "epe",
					Port:           uint32(rpcPort),
					MessageTimeout: "0.1s",
				},
			}
			if mode == "no_epe" {
				effective.extProc = nil
			}
			manager, err := b.buildForwardHCM(HTTPDynamicForwardProxy, effective, false)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "explicit_without_serviceentry" && !legacy {
				manager.HttpFilters = append([]*hcm.HttpFilter{
					httpFilter("test.route_upstream", b.staticEndpointCandidateConfig("127.0.0.3")),
				}, manager.HttpFilters...)
			}
			// The harness has no restored socket address; leave original destination
			// absent so non-ServiceEntry cases use the request authority.
			for _, f := range manager.HttpFilters {
				if f.Name == "envoy.filters.http.ext_proc" {
					cfg := &external.ExternalProcessor{}
					if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
						t.Fatal(err)
					}
					cfg.RequestAttributes = slices.DeleteFunc(cfg.RequestAttributes, func(a string) bool {
						return a == "destination.address" || a == "destination.port"
					})
					f.ConfigType = &hcm.HttpFilter_TypedConfig{TypedConfig: b.pack(cfg)}
				}
			}
			manager.RouteSpecifier = &hcm.HttpConnectionManager_RouteConfig{
				RouteConfig: b.buildForwardRoute(HTTPDynamicForwardProxy, gateway),
			}
			capture := &state.Config{}
			for _, field := range []struct {
				key     string
				value   string
				factory string
			}{
				{"envoy.filters.listener.original_dst.local_ip", replacement.String(), ""},
				{"agentio.workload.name", "demo", "envoy.string"},
				{"agentio.workload.namespace", "default", "envoy.string"},
			} {
				capture.OnNewConnection = append(capture.OnNewConnection, &common.FilterStateValue{
					Key:        &common.FilterStateValue_ObjectKey{ObjectKey: field.key},
					FactoryKey: field.factory,
					Value:      &common.FilterStateValue_FormatString{FormatString: formatString(field.value)},
				})
			}
			socket := func(port int) *core.Address {
				return &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
					Address:       "127.0.0.1",
					PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)},
				}}}
			}
			cfg := &bootstrap.Bootstrap{StaticResources: &bootstrap.Bootstrap_StaticResources{
				Listeners: []*listener.Listener{
					{
						Name:    "test",
						Address: socket(0),
						FilterChains: []*listener.FilterChain{{Filters: []*listener.Filter{
							{
								Name:       "envoy.filters.network.set_filter_state",
								ConfigType: &listener.Filter_TypedConfig{TypedConfig: b.pack(capture)},
							},
							{
								Name:       "envoy.filters.network.http_connection_manager",
								ConfigType: &listener.Filter_TypedConfig{TypedConfig: b.pack(manager)},
							},
						}}},
					},
				},
				Clusters: []*cluster.Cluster{
					b.buildDFPCluster(HTTPDynamicForwardProxy, true, false, nil),
					{
						Name:                 ExtProcCluster,
						ConnectTimeout:       durationpb.New(time.Second),
						Http2ProtocolOptions: &core.Http2ProtocolOptions{},
						LoadAssignment: &endpoint.ClusterLoadAssignment{
							ClusterName: ExtProcCluster,
							Endpoints: []*endpoint.LocalityLbEndpoints{{LbEndpoints: []*endpoint.LbEndpoint{
								{
									HostIdentifier: &endpoint.LbEndpoint_Endpoint{
										Endpoint: &endpoint.Endpoint{Address: socket(rpcPort)},
									},
								},
							}}},
						},
					},
				},
			},
				Admin: &bootstrap.Admin{Address: socket(0)},
			}
			if b.err != nil {
				t.Fatal(b.err)
			}
			dir := t.TempDir()
			configPath, adminPath := filepath.Join(dir, "envoy.json"), filepath.Join(dir, "admin.address")
			data, err := protojson.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "envoy.log")
			logFile, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(
				binary,
				"-c",
				configPath,
				"--concurrency",
				"1",
				"--base-id",
				strconv.Itoa(port),
				"--admin-address-path",
				adminPath,
				"--log-level",
				"warning",
			)
			cmd.Stdout, cmd.Stderr = logFile, logFile
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					t.Errorf("stop Envoy: %v", err)
				}
				if err := cmd.Wait(); err != nil {
					if exitErr, ok := errors.AsType[*exec.ExitError](err); !ok || exitErr.ExitCode() != -1 {
						t.Errorf("wait Envoy: %v", err)
					}
				}
				if err := logFile.Close(); err != nil {
					t.Error(err)
				}
				log, err := os.ReadFile(logPath)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(log), "FilterStateAccessViolation") {
					t.Error("DFP target override violated Envoy filter-state mutability")
				}
				if t.Failed() {
					t.Logf("Envoy: %s", log)
				}
			})
			client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{}}
			defer client.CloseIdleConnections()
			var proxyAddress string
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				admin, err := os.ReadFile(adminPath)
				if err == nil {
					response, err := client.Get("http://" + strings.TrimSpace(string(admin)) + "/listeners?format=json")
					if err == nil {
						var listing struct {
							Statuses []struct {
								Address struct {
									Socket struct {
										Address string `json:"address"`
										Port    int    `json:"port_value"`
									} `json:"socket_address"`
								} `json:"local_address"`
							} `json:"listener_statuses"`
						}
						err = json.NewDecoder(response.Body).Decode(&listing)
						if err := response.Body.Close(); err != nil {
							t.Error(err)
						}
						if err == nil && len(listing.Statuses) == 1 {
							s := listing.Statuses[0].Address.Socket
							proxyAddress = net.JoinHostPort(s.Address, strconv.Itoa(s.Port))
							break
						}
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			if proxyAddress == "" {
				t.Fatal("Envoy did not start")
			}
			check := func(host, path string, wantStatus int, wantIP string) {
				t.Helper()
				before := originCalls.Load()
				beforeResolution := resolutionCalls.Load()
				beforeProcessing := processingCalls.Load()
				request, err := http.NewRequest("GET", "http://"+proxyAddress+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Host = host
				if !strings.Contains(host, ":") {
					request.Host += ":443" // Use a different port from the original destination.
				}
				// This client header must never become the trusted ServiceEntry candidate.
				request.Header.Set("agentio.route.upstream", replacement.String())
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				if err := response.Body.Close(); err != nil {
					t.Error(err)
				}
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != wantStatus || (wantIP != "" && !strings.HasPrefix(string(body), wantIP+":")) {
					t.Fatalf(
						"%s%s: status=%d body=%s want status=%d IP=%s",
						host,
						path,
						response.StatusCode,
						body,
						wantStatus,
						wantIP,
					)
				}
				if wantStatus == 200 && !strings.HasSuffix(string(body), " "+request.Host) {
					t.Fatalf("routing changed HTTP Host: %s", body)
				}
				if mode != "no_epe" && wantStatus != 500 {
					wantCalls := int64(1)
					if processingCalls.Load()-beforeProcessing != wantCalls {
						t.Fatalf("ext_proc calls=%d want=%d", processingCalls.Load()-beforeProcessing, wantCalls)
					}
				}
				if mode != "no_epe" && wantStatus != 500 && resolutionCalls.Load() != beforeResolution+1 {
					t.Fatal("request repeated policy resolution")
				}
				if wantStatus != 200 && originCalls.Load() != before {
					t.Fatal("rejected request reached origin")
				}
			}
			if mode == "explicit_without_serviceentry" {
				if legacy {
					// Legacy graphs without ServiceEntries do not publish route candidates.
					// An explicit EPE target and normal DNS routing must still work.
					check("unmapped.invalid", "/explicit", 200, "127.0.0.3")
					check(net.JoinHostPort("localhost", strconv.Itoa(port)), "/rewrite", 200, "127.0.0.1")
					check("unmapped.invalid", "/", 500, "")
					return
				}
				check("unmapped.invalid", "/", 200, "127.0.0.3")
				check("unmapped.invalid", "/rewrite", 200, "127.0.0.3")
				return
			}
			check("allowed.invalid", "/", 200, "127.0.0.1")
			check("allowed.invalid", "/clear", 200, "127.0.0.1")
			if mode != "no_epe" {
				check("allowed.invalid", "/explicit", 200, "127.0.0.3")
			}
			if enabled {
				check("denied.invalid", "/", 403, "")
				check("denied.invalid", "/bypass", 403, "")
				check("allowed.invalid", "/rewrite", 200, "127.0.0.1")
				check("denied.invalid", "/rewrite", 403, "")
				check("denied.invalid", "/explicit", 200, "127.0.0.3")
				check("unmapped.invalid", "/no-service", 500, "")
				check(net.JoinHostPort("localhost", strconv.Itoa(port)), "/", 200, "127.0.0.1")
				check(net.JoinHostPort("multiple.invalid", strconv.Itoa(port)), "/", 200, "127.0.0.3")
				check(net.JoinHostPort("127.0.0.2", strconv.Itoa(port)), "/", 403, "")
				if noServiceCalls.Load() != 1 {
					t.Fatal("absent candidate rejected before normal authorization")
				}

			} else {
				check("denied.invalid", "/", 200, "127.0.0.2")
				if mode != "no_epe" {
					check("allowed.invalid", "/rewrite", 200, "127.0.0.1")
				}
			}
			if mode != "no_epe" {
				check(net.JoinHostPort("localhost", strconv.Itoa(port)), "/rewrite", 200, "127.0.0.1")
			}
			outcomes := map[int]int{}
			for range 80 {
				request, err := http.NewRequest("GET", "http://"+proxyAddress+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Host = "mixed.invalid"
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Error(err)
				}
				outcomes[response.StatusCode]++
				if enabled && response.StatusCode == 200 && !strings.HasPrefix(string(body), "127.0.0.1:") {
					t.Fatalf("wrong authorized endpoint: %s", body)
				}
				if response.StatusCode != 200 && !(enabled && response.StatusCode == 403) {
					t.Fatalf("mixed endpoint status=%d body=%s", response.StatusCode, body)
				}
			}
			if enabled && (outcomes[200] == 0 || outcomes[403] == 0) {
				t.Fatalf("weighted selection not exercised: %v", outcomes)
			}
			t.Logf("weighted endpoint outcomes: %v", outcomes)
			if mode == "no_epe" {
				return
			}
			check("allowed.invalid", "/timeout", 504, "")
			processor.Stop()
			check("allowed.invalid", "/", 500, "")
		})
	}
}

type serviceEntryTestFilter struct {
	filter.PassThrough
	replacement netip.AddrPort
}

func (f *serviceEntryTestFilter) OnRequestHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	switch st.Request.Path {
	case "/rewrite":
		return filter.Continue(filter.SetPath("/rewritten", true)), nil
	case "/clear":
		return filter.Continue(filter.Mutation{Route: &filter.RouteMutation{ClearCache: true}}), nil
	case "/explicit":
		return filter.Continue(
			filter.Mutation{
				Route: &filter.RouteMutation{
					Upstream:   &filter.UpstreamTarget{Address: &f.replacement},
					ClearCache: true,
				},
			},
		), nil
	case "/bypass":
		return filter.Bypass(), nil
	case "/timeout":
		<-ctx.Done()
		return filter.Action{}, ctx.Err()
	default:
		return filter.Continue(), nil
	}
}

type serviceEntryDNS struct{}

func (serviceEntryDNS) Lookup(_ context.Context, host string, _ dns.Family) (dns.LookupResult, error) {
	if host == "localhost" {
		return dns.LookupResult{Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, TTL: time.Minute}, nil
	}
	if host == "multiple.invalid" {
		return dns.LookupResult{
			Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.3")},
			TTL:       time.Minute,
		}, nil
	}
	return dns.LookupResult{}, fmt.Errorf("no test DNS record for %s", host)
}
