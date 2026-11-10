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

package networklimits

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

// Keep the byte limiter on CONNECT and the inspectors on an internal connection,
// as in the production gateway. A direct TCP origin misses the timeout conflict.
func TestEnvoyShapedProtocolInspection(t *testing.T) {
	origin := startOrigin(t, false)
	r := startEnvoyBootstrap(t, origin.port(), freePort(t), func(l object) {
		limit := nested(policy(filters(l)[1])["descriptors"].([]any)[0], "bandwidth_limit")
		limit["upload_bytes_per_second"] = 16 << 10
		limit["upload_burst_bytes"] = 4096
	}, false, func(b object) {
		resources := obj(b["static_resources"])
		clusters := resources["clusters"].([]any)
		for _, c := range clusters {
			cluster := obj(c)
			if cluster["name"] != "plain" {
				continue
			}
			upstream := clone(t, cluster)
			upstream["name"] = "origin"
			nested(upstream, "load_assignment")["cluster_name"] = "origin"
			clusters = append(clusters, upstream)
			ep := nested(cluster, "load_assignment")["endpoints"].([]any)[0]
			lb := obj(ep)["lb_endpoints"].([]any)[0]
			nested(lb, "endpoint")["address"] = object{
				"envoy_internal_address": object{"server_listener_name": "inspected"},
			}
			cluster["transport_socket"] = object{
				"name": "envoy.transport_sockets.internal_upstream",
				"typed_config": object{
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.internal_upstream.v3.InternalUpstreamTransport",
					"transport_socket": object{
						"name": "envoy.transport_sockets.raw_buffer",
						"typed_config": object{
							"@type": "type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer",
						},
					},
				},
			}
		}
		resources["clusters"] = clusters
		module := "/usr/local/lib/libenvoy_agentio_network_limits.so"
		if value := os.Getenv("AGENTIO_TEST_NETWORK_LIMITS_MODULE"); value != "" {
			module = value
		}
		resources["listeners"] = []any{object{
			"name":                     "inspected",
			"internal_listener":        object{},
			"listener_filters_timeout": "0s",
			"listener_filters": []any{
				object{
					"name": "envoy.filters.listener.dynamic_modules",
					"typed_config": object{
						"@type": "type.googleapis.com/envoy.extensions.filters.listener.dynamic_modules.v3.DynamicModuleListenerFilter",
						"dynamic_module_config": object{
							"name":         "envoy_agentio_network_limits",
							"do_not_close": true,
							"module":       object{"local": object{"filename": module}},
						},
						"filter_name": "envoy_agentio_inspection_deadline",
					},
				},
				object{
					"name": "envoy.filters.listener.http_inspector",
					"typed_config": object{
						"@type": "type.googleapis.com/envoy.extensions.filters.listener.http_inspector.v3.HttpInspector",
					},
				},
			},
			"filter_chains": []any{object{"filters": []any{object{
				"name": "envoy.filters.network.tcp_proxy",
				"typed_config": object{
					"@type":       "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
					"stat_prefix": "inspection",
					"cluster":     "origin",
				},
			}}}},
		}}
		b["bootstrap_extensions"] = []any{
			object{
				"name": "envoy.bootstrap.internal_listener",
				"typed_config": object{
					"@type": "type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener",
				},
			},
		}
		b["layered_runtime"] = object{"layers": []any{object{
			"name": "agentio",
			"static_layer": object{
				"envoy.reloadable_features.enable_send_rst_on_user_space_socket": false,
			},
		}}}
	})
	client := newClient(t, r.port)
	t.Run("queued_bytes_do_not_consume_inspection_time", func(t *testing.T) {
		// A first oversized batch is allowed, but its debt must survive reconnect.
		warm := client.open(t, "test", "same", "plain:80", 200)
		_, err := fmt.Fprintf(warm.writer, "U %d\n", 128<<10)
		must(t, err)
		_, err = warm.writer.Write(payload(128 << 10))
		must(t, err)
		must(t, warm.writer.Close())
		data, err := io.ReadAll(warm.response.Body)
		must(t, err)
		if string(data) != "OK" {
			t.Fatalf("warm response %q", data)
		}
		warm.close()
		started := time.Now()
		queued := client.open(t, "test", "same", "plain:80", 200)
		// Enough bytes for the native inspector to classify this non-HTTP protocol.
		_, err = io.WriteString(queued.writer, "D 00000032\n")
		must(t, err)
		data, err = io.ReadAll(queued.response.Body)
		must(t, err)
		if !bytes.Equal(data, payload(32)) {
			t.Fatalf("queued response %q", data)
		}
		elapsed := time.Since(started)
		if elapsed < 1250*time.Millisecond {
			t.Fatalf("shared upload debt was lost: %s", elapsed)
		}
		t.Logf("new connection survived %s of shared upload debt", elapsed)
	})
	t.Run("silent_client_still_times_out", func(t *testing.T) {
		s := client.open(t, "test", "silent", "plain:80", 200)
		started := time.Now()
		_, err := bufio.NewReader(s.response.Body).ReadByte()
		if err == nil {
			t.Fatal("silent connection was forwarded")
		}
		elapsed := time.Since(started)
		if elapsed < 700*time.Millisecond || elapsed > 2500*time.Millisecond {
			t.Fatalf("silent timeout %s, want 1s", elapsed)
		}
	})
}
