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
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	filelogv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	internalv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/bootstrap/internal_listener/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking/telemetry"
)

func TestEnvoyDirectTCPDeny(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	for _, tc := range []struct {
		name           string
		reason         string
		capturedReason string
		expression     string
		legacy         bool
		disabled       bool
		http           bool
		internal       bool
		logs           int
	}{
		{name: "SNI", reason: "sni_policy_denied", logs: 1},
		{name: "captured TCP reason", reason: "tcp_policy_denied", capturedReason: "tcp_policy_denied", logs: 1},
		{name: "captured policy error", reason: "connection_policy_missing", capturedReason: "connection_policy_missing", internal: true, logs: 1},
		{name: "internal listener", reason: "sni_policy_denied", internal: true, logs: 1},
		{name: "ServiceEntry", reason: "service_entry_denied", logs: 1},
		{name: "legacy", reason: "sni_policy_denied", legacy: true, logs: 1},
		{name: "filtered", reason: "sni_policy_denied", expression: "false"},
		{name: "disabled", reason: "sni_policy_denied", disabled: true},
		{name: "HTTP does not duplicate listener logs", http: true, logs: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := testGateway(nil)
			var policies []model.Telemetry
			if tc.expression != "" || tc.disabled {
				var expression *string
				if tc.expression != "" {
					expression = &tc.expression
				}
				policy, err := model.NewTelemetry(model.TelemetryMetadata{
					Namespace: gateway.Namespace,
					Name:      "logs",
					Source:    "test",
				}, []string{gateway.ResourceName()}, nil, nil, []model.TelemetryAccessLogging{{
					Mode:     model.TelemetryModeServer,
					Disabled: &tc.disabled,
					Filter:   expression,
				}})
				if err != nil {
					t.Fatal(err)
				}
				policies = append(policies, policy)
			}
			logs, err := telemetry.Build(telemetry.Inputs{
				Gateway:       gateway,
				LegacyGateway: tc.legacy,
				RootNamespace: gateway.Namespace,
				Telemetry:     policies,
			})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "access.log")
			for _, log := range append(logs.ListenerAccessLogs, logs.HTTPAccessLogs...) {
				file := &filelogv3.FileAccessLog{}
				if err := log.GetTypedConfig().UnmarshalTo(file); err != nil {
					t.Fatal(err)
				}
				file.Path = path
				log.ConfigType = &accesslogv3.AccessLog_TypedConfig{TypedConfig: mustPack(file)}
			}
			// Inspect the complete file after Envoy has stopped.
			t.Cleanup(func() {
				data, err := os.ReadFile(path)
				if errors.Is(err, os.ErrNotExist) && tc.logs == 0 {
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' })
				if len(lines) != tc.logs {
					t.Fatalf("access logs = %d, want %d: %s", len(lines), tc.logs, data)
				}
				if tc.logs == 0 {
					return
				}
				var record map[string]any
				if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
					t.Fatal(err)
				}
				if !tc.http &&
					(record["denial_reason"] != tc.reason || record["response_code_details"] != "direct_response") {
					t.Fatalf("denial lost its reason or used an upstream failure: %s", data)
				}
			})
			b := &resourceBuilder{legacyGateway: tc.legacy}
			chain := b.buildTCPDenyChain("deny", tc.reason)
			if tc.capturedReason != "" {
				chain = b.buildTCPDenyChain("deny", "sni_policy_denied")
				capture := b.buildTCPDenyChain("capture", tc.capturedReason).GetFilters()[0]
				chain.Filters = append([]*listenerv3.Filter{capture}, chain.Filters...)
			}
			if tc.http {
				manager := &hcmv3.HttpConnectionManager{
					StatPrefix: "http",
					AccessLog:  logs.HTTPAccessLogs,
					RouteSpecifier: &hcmv3.HttpConnectionManager_RouteConfig{RouteConfig: &routev3.RouteConfiguration{
						Name: "local",
						VirtualHosts: []*routev3.VirtualHost{
							{
								Name:    "all",
								Domains: []string{"*"},
								Routes: []*routev3.Route{
									{
										Match: &routev3.RouteMatch{
											PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
										},
										Action: &routev3.Route_DirectResponse{
											DirectResponse: &routev3.DirectResponseAction{Status: 200},
										},
									},
								},
							},
						},
					}},
					HttpFilters: []*hcmv3.HttpFilter{
						httpFilter("envoy.filters.http.router", b.pack(&routerv3.Router{})),
					},
				}
				chain = &listenerv3.FilterChain{Filters: []*listenerv3.Filter{
					networkFilter("envoy.filters.network.http_connection_manager", b.pack(manager)),
				}}
			}
			cfg := &bootstrapv3.Bootstrap{
				StaticResources: &bootstrapv3.Bootstrap_StaticResources{Listeners: []*listenerv3.Listener{{
					Name:         "test",
					Address:      socketAddress("127.0.0.1", 0),
					FilterChains: []*listenerv3.FilterChain{chain},
					AccessLog:    logs.ListenerAccessLogs,
				}}},
				Admin: &bootstrapv3.Admin{Address: socketAddress("127.0.0.1", 0)},
			}
			if tc.internal {
				internal := cfg.StaticResources.Listeners[0]
				internal.Name = MainInternal
				internal.Address = nil
				internal.ListenerSpecifier = &listenerv3.Listener_InternalListener{
					InternalListener: &listenerv3.Listener_InternalListenerConfig{},
				}
				cfg.StaticResources.Listeners = append(cfg.StaticResources.Listeners, &listenerv3.Listener{
					Name:    "outer",
					Address: socketAddress("127.0.0.1", 0),
					FilterChains: []*listenerv3.FilterChain{
						{Filters: b.applicationTCPFilters(effectiveConfig{}, nil, MainInternal, nil)},
					},
				})
				cfg.StaticResources.Clusters = []*clusterv3.Cluster{b.buildInternalCluster(MainInternal)}
				cfg.BootstrapExtensions = []*corev3.TypedExtensionConfig{{
					Name:        "envoy.bootstrap.internal_listener",
					TypedConfig: b.pack(&internalv3.InternalListener{}),
				}}
			}
			data, err := protojson.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			address, _ := runCompatibilityEnvoy(t, binary, string(data))
			// The harness flushes every 10ms; allow the final connection log to reach disk before shutdown.
			defer time.Sleep(100 * time.Millisecond)
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if tc.http {
				request, err := http.NewRequest(http.MethodGet, "http://"+address, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := request.Write(conn); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), request)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("HTTP response = %d", response.StatusCode)
				}
				return
			}
			var buffer [1]byte
			n, err := conn.Read(buffer[:])
			var networkError net.Error
			if n != 0 || err == nil || (errors.As(err, &networkError) && networkError.Timeout()) {
				t.Fatalf("deny must close without data or a client write: n=%d err=%v", n, err)
			}
		})
	}
}
