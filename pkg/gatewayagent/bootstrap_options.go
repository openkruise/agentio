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

package gatewayagent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/proxy_protocol/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

// customizeBootstrap applies explicit native settings before protobuf validation.
// The agent-owned xDS, SDS and health resources cannot be replaced by telemetry.
func customizeBootstrap(data []byte, c Config) ([]byte, error) {
	if err := c.validateAdvanced(); err != nil {
		return nil, err
	}
	var b map[string]any
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if c.StatsEvictionInterval != "" {
		d, err := time.ParseDuration(c.StatsEvictionInterval)
		if err != nil {
			return nil, err
		}
		b["stats_eviction_interval"] = fmt.Sprintf("%.9fs", d.Seconds())
	}
	if len(c.Locality) > 0 {
		b["node"].(map[string]any)["locality"] = c.Locality
	}
	if c.Legacy {
		extensions := []any{}
		for _, entry := range b["bootstrap_extensions"].([]any) {
			name := entry.(map[string]any)["name"]
			if name == "metadata_discovery" && !c.discoveryEnabled() ||
				name == "kruise.bootstrap.policy_store" && !c.policyEnabled() {
				continue
			}
			extensions = append(extensions, entry)
		}
		b["bootstrap_extensions"] = extensions
	}
	if err := configureStats(b, c); err != nil {
		return nil, err
	}
	configureRuntime(b, c)
	if err := configureTelemetry(b, c); err != nil {
		return nil, err
	}
	configureListeners(b, c)
	return json.Marshal(b)
}

func configureRuntime(b map[string]any, c Config) {
	if len(c.RuntimeValues) > 0 {
		runtime, ok := b["layered_runtime"].(map[string]any)
		if !ok {
			runtime = map[string]any{
				"layers": []any{
					map[string]any{"name": "agentio", "static_layer": map[string]any{}},
					map[string]any{"name": "admin", "admin_layer": map[string]any{}},
				},
			}
			b["layered_runtime"] = runtime
		}
		values := runtime["layers"].([]any)[0].(map[string]any)["static_layer"].(map[string]any)
		for key, value := range c.RuntimeValues {
			if value == nil || value == "" {
				delete(values, key)
			} else {
				if value == "true" {
					value = true
				}
				if value == "false" {
					value = false
				}
				values[key] = value
			}
		}
	}
	if c.MaxDownstreamConnections != nil {
		b["overload_manager"] = map[string]any{
			"resource_monitors": []any{
				map[string]any{
					"name": "envoy.resource_monitors.global_downstream_max_connections",
					"typed_config": map[string]any{
						"@type":                             "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig",
						"max_active_downstream_connections": *c.MaxDownstreamConnections,
					},
				},
			},
		}
	}
}

func configureTelemetry(b map[string]any, c Config) error {
	resources := b["static_resources"].(map[string]any)
	clusters := resources["clusters"].([]any)
	names := map[string]bool{}
	for _, entry := range clusters {
		cluster := entry.(map[string]any)
		names[cluster["name"].(string)] = true
		if cluster["name"] == "agent" {
			setClusterPort(cluster, portOption(c.StatusPort, 15020))
		}
	}
	for _, raw := range c.TelemetryClusters {
		var cluster map[string]any
		if err := json.Unmarshal(raw, &cluster); err != nil {
			return fmt.Errorf("telemetryClusters: %w", err)
		}
		name, _ := cluster["name"].(string)
		if name == "" || names[name] {
			return fmt.Errorf("empty, duplicate or agent-owned telemetry cluster %q", name)
		}
		names[name] = true
		clusters = append(clusters, cluster)
	}
	resources["clusters"] = clusters
	if len(c.StatsSinks) > 0 {
		b["stats_sinks"] = c.StatsSinks
	}
	if len(c.Tracing) > 0 {
		b["tracing"] = c.Tracing
	}
	if len(c.LoadStatsConfig) > 0 || c.OutlierEventLog != "" {
		manager := map[string]any{}
		if c.OutlierEventLog != "" {
			manager["outlier_detection"] = map[string]any{"event_log_path": c.OutlierEventLog}
		}
		if len(c.LoadStatsConfig) > 0 {
			manager["load_stats_config"] = c.LoadStatsConfig
		}
		b["cluster_manager"] = manager
	}
	return nil
}

func configureListeners(b map[string]any, c Config) {
	resources := b["static_resources"].(map[string]any)
	admin := b["admin"].(map[string]any)["address"].(map[string]any)["socket_address"].(map[string]any)
	admin["port_value"] = c.Proxy.AdminPort
	for _, entry := range resources["listeners"].([]any) {
		listener := entry.(map[string]any)
		port := portOption(c.EnvoyStatusPort, 15021)
		metrics := listener["name"] == "agentio_metrics"
		if metrics {
			port = portOption(c.PrometheusPort, 15090)
		}
		socket := listener["address"].(map[string]any)["socket_address"].(map[string]any)
		socket["port_value"] = port
		// Health and metrics must remain reachable when the connection limit is hit.
		listener["bypass_overload_manager"] = true
		localhost, wildcard := localAddresses(c.IP)
		address := wildcard
		if metrics && c.MetricsLocalhostOnly {
			address = localhost
		}
		socket["address"] = address
		addresses := map[string]bool{address: true}
		for _, ip := range c.nodeIPs() {
			local, wild := localAddresses(ip)
			address = wild
			if metrics && c.MetricsLocalhostOnly {
				address = local
			}
			if !addresses[address] {
				addresses[address] = true
				listener["additional_addresses"] = append(
					asList(listener["additional_addresses"]),
					map[string]any{
						"address": map[string]any{
							"socket_address": map[string]any{
								"address":     address,
								"port_value":  port,
								"ipv4_compat": false,
							},
						},
					},
				)
			}
		}
		if !metrics && c.StatusProxyProtocol {
			listener["listener_filters"] = []any{
				map[string]any{
					"name": "envoy.filters.listener.proxy_protocol",
					"typed_config": map[string]any{
						"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol",
					},
				},
			}
		}
	}
}

func asList(v any) []any {
	if v == nil {
		return nil
	}
	return v.([]any)
}
func setClusterPort(cluster map[string]any, port int) {
	endpoint := cluster["load_assignment"].(map[string]any)["endpoints"].([]any)[0].(map[string]any)["lb_endpoints"].([]any)[0].(map[string]any)["endpoint"].(map[string]any)
	endpoint["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = port
}

func configureStats(b map[string]any, c Config) error {
	stats, ok := b["stats_config"].(map[string]any)
	if !ok {
		stats = map[string]any{}
		b["stats_config"] = stats
	}
	if c.StatsMatcher != nil {
		if err := configureStatsMatcher(stats, c); err != nil {
			return err
		}
	}
	tags := asList(stats["stats_tags"])
	seen := map[string]bool{}
	for _, tag := range tags {
		seen[tag.(map[string]any)["tag_name"].(string)] = true
	}
	for _, name := range c.ExtraStatTags {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		tags = append(tags, map[string]any{"tag_name": name, "regex": "(" + regexp.QuoteMeta(name) + `=\.=(.*?);\.;)`})
	}
	if len(tags) > 0 {
		stats["stats_tags"] = tags
	}
	if len(c.HistogramBuckets) > 0 {
		keys := []string{}
		for prefix := range c.HistogramBuckets {
			keys = append(keys, prefix)
		}
		sort.Strings(keys)
		buckets := []any{}
		for _, prefix := range keys {
			values := c.HistogramBuckets[prefix]
			if len(values) == 0 {
				return fmt.Errorf("histogram buckets must not be empty")
			}
			for i, value := range values {
				if value < 0 || i > 0 && value <= values[i-1] {
					return fmt.Errorf("histogram buckets must be nonnegative and strictly increasing")
				}
			}
			buckets = append(buckets, map[string]any{"match": map[string]any{"prefix": prefix}, "buckets": values})
		}
		stats["histogram_bucket_settings"] = buckets
	}
	return nil
}

func configureStatsMatcher(stats map[string]any, c Config) error {
	patterns := []any{}
	// Retain lifecycle signals regardless of the user's selection.
	prefixes := append(
		[]string{"cluster_manager", "listener_manager", "server", "cluster.xds-grpc", "wasm"},
		c.StatsMatcher.InclusionPrefixes...)
	if c.Legacy {
		prefixes = append(prefixes, "reporter=", "component", "istio")
	}
	if c.discoveryEnabled() {
		prefixes = append(prefixes, "workload_discovery")
	}
	if c.policyEnabled() {
		prefixes = append(prefixes, "policy_store")
	}
	groups := map[string][]string{
		"prefix": prefixes,
		"suffix": append(
			[]string{"downstream_cx_active", "rbac.allowed", "rbac.denied", "shadow_allowed", "shadow_denied"},
			c.StatsMatcher.InclusionSuffixes...),
		"regex": append([]string{`vhost\..*\.route\..*`}, c.StatsMatcher.InclusionRegexps...),
	}
	for _, kind := range []string{"prefix", "suffix", "regex"} {
		values := groups[kind]
		for _, value := range values {
			expanded := []string{value}
			if strings.Contains(value, "{pod_ip}") {
				expanded = nil
				for _, ip := range c.nodeIPs() {
					expanded = append(expanded, strings.ReplaceAll(value, "{pod_ip}", ip))
				}
			}
			for _, pattern := range expanded {
				if kind == "regex" {
					if _, err := regexp.Compile(pattern); err != nil {
						return fmt.Errorf("statsMatcher: %w", err)
					}
					patterns = append(patterns, map[string]any{"safe_regex": map[string]any{"regex": pattern}})
				} else {
					patterns = append(patterns, map[string]any{kind: pattern})
				}
			}
		}
	}
	stats["stats_matcher"] = map[string]any{"inclusion_list": map[string]any{"patterns": patterns}}

	return nil
}
