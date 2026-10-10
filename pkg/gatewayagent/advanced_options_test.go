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
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestLegacyOptionPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "annotations")
	err := os.WriteFile(
		path,
		[]byte("sidecar.istio.io/statsFlushInterval=\"2s\"\nsidecar.istio.io/statsEvictionInterval=\"10s\"\n"),
		0600,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTIO_POD_ANNOTATIONS", path)
	t.Setenv("ENABLE_POLICY_STORE", "true")
	t.Setenv("AGENTIO_GATEWAY_CONFIG", `{"statsEvictionInterval":"20s","policyStore":false}`)
	c, err := LoadConfig([]string{"--legacy", "--stats-eviction-interval=30s"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.StatsFlushInterval != 2*time.Second || c.StatsEvictionInterval != "30s" || c.policyEnabled() {
		t.Fatal("annotation/JSON/flag precedence lost")
	}
	if c.Proxy.DrainDuration != 45*time.Second || c.Proxy.TerminationDrainDuration != 5*time.Second {
		t.Fatal("legacy drain defaults changed")
	}
	b, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.BootstrapExtensions) != 2 || b.Node.Metadata.Fields["ENABLE_POLICY_STORE"].GetStringValue() != "false" {
		t.Fatal("disabled policy store still loaded")
	}
	t.Setenv("AGENTIO_GATEWAY_CONFIG", `{"drainDuration":"12s","terminationDrainDuration":"8s"}`)
	c, err = LoadConfig([]string{"--legacy", "--termination-drain-duration=9s"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Proxy.DrainDuration != 12*time.Second || c.Proxy.TerminationDrainDuration != 9*time.Second {
		t.Fatal("explicit drain options lost")
	}
}

func TestPolicyReadinessWaitsForInitialSync(t *testing.T) {
	synced := false
	calls := 0
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		value := 0
		if synced {
			value = 1
		}
		if _, err := fmt.Fprintf(w, "policy_store.initial_sync_ready: %d\n", value); err != nil {
			t.Error(err)
		}
	}))
	defer admin.Close()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(admin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig(t)
	c.IP = host
	c.Proxy.AdminPort = int32(n)
	c.Legacy = true
	enabled := true
	c.PolicyStore = &enabled
	probe := &policyReadiness{}
	if err := probe.check(t.Context(), c); err == nil {
		t.Fatal("accepted unsynced policy store")
	}
	synced = true
	if err := probe.check(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	synced = false
	before := calls
	if err := probe.check(t.Context(), c); err != nil || before != calls {
		t.Fatal("initial sync was not latched")
	}
	enabled = false
	probe = &policyReadiness{}
	if err := probe.check(t.Context(), c); err != nil || before != calls {
		t.Fatal("disabled store was probed")
	}
}

func configuredBootstrap(t *testing.T, legacy bool) Config {
	t.Helper()
	c := testConfig(t)
	c.Legacy = legacy
	c.DNSDomain = "demo.svc.cluster.local"
	raw := `{
 "statsEvictionInterval":"30s",
 "statsMatcher":{"inclusionPrefixes":["http.{pod_ip}_","cluster.telemetry"],"inclusionSuffixes":["upstream_rq_total"],"inclusionRegexps":["http.*"]},
 "extraStatTags":["team"],"histogramBuckets":{"http.":[1,5,10]},
 "runtimeValues":{"envoy.reloadable_features.http_reject_path_with_fragment":true},
 "maxDownstreamConnections":1000,"adminPort":16000,"statusPort":16020,"envoyStatusPort":16021,"prometheusPort":16090,
 "metricsLocalhostOnly":true,"statusProxyProtocol":true,"instanceIPs":["10.0.0.1","2001:db8::1"],
 "locality":{"region":"test","zone":"a"},
 "telemetryClusters":[{"name":"telemetry","type":"STATIC","connect_timeout":"1s","http2_protocol_options":{},"load_assignment":{"cluster_name":"telemetry","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":4317}}}}]}]}}],
 "statsSinks":[{"name":"envoy.stat_sinks.statsd","typed_config":{"@type":"type.googleapis.com/envoy.config.metrics.v3.StatsdSink","address":{"socket_address":{"address":"127.0.0.1","port_value":8125,"protocol":"UDP"}}}}],
 "tracing":{"http":{"name":"envoy.tracers.zipkin","typed_config":{"@type":"type.googleapis.com/envoy.config.trace.v3.ZipkinConfig","collector_cluster":"telemetry","collector_endpoint":"/api/v2/spans","collector_endpoint_version":"HTTP_JSON"}}},
 "loadStatsConfig":{"api_type":"GRPC","transport_api_version":"V3","grpc_services":[{"envoy_grpc":{"cluster_name":"telemetry"}}]},
 "outlierEventLog":"/tmp/gateway-outlier-test.log"
 }`
	if err := json.Unmarshal([]byte(raw), &c.AdvancedOptions); err != nil {
		t.Fatal(err)
	}
	if legacy {
		enabled := true
		c.PolicyStore = &enabled
	}
	c.applyCredentialPaths()
	return c
}

func TestConfiguredBootstrap(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		c := configuredBootstrap(t, legacy)
		b, err := bootstrapConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		if b.GetStatsEvictionInterval().AsDuration() != 30*time.Second || b.Node.Locality.Zone != "a" ||
			len(b.StatsSinks) != 1 ||
			len(b.StaticResources.Clusters) != 4 {
			t.Fatal("missing configured native resource")
		}
		if len(b.StaticResources.Listeners[0].AdditionalAddresses) != 1 ||
			len(b.StaticResources.Listeners[0].ListenerFilters) != 1 ||
			!b.StaticResources.Listeners[0].BypassOverloadManager {
			t.Fatal("listener options not applied")
		}
		if b.StaticResources.Listeners[1].Address.GetSocketAddress().Address != "127.0.0.1" ||
			b.Admin.Address.GetSocketAddress().PortSpecifier == nil {
			t.Fatal("listener address/port ignored")
		}
		content, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{"downstream_cx_active", "histogram_bucket_settings", "global_downstream_max_connections", "outlier_detection", "load_stats_config", "team", "http.10.0.0.1_"} {
			if !strings.Contains(string(content), required) {
				t.Fatalf("missing %s", required)
			}
		}
	}
}

// Both pinned binaries must accept configured resources, not just defaults.
func TestEnvoyConfiguredBootstrap(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	legacy := os.Getenv("AGENTIO_TEST_LEGACY_ENVOY_BINARY") != ""
	c := configuredBootstrap(t, legacy)
	b, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	content, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), binary, "--mode", "validate", "-c", path, "--concurrency", "1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("configured bootstrap: %v\n%s", err, output)
	}
}

func TestAdvancedOptionValidation(t *testing.T) {
	for _, raw := range []string{`{"statsEvictionInterval":"11s"}`, `{"statsEvictionInterval":"0s"}`, `{"adminPort":15020}`, `{"policyStore":true}`, `{"rsaKeySize":1024}`, `{"eccCurve":"typo"}`, `{"rotationGraceRatio":1}`, `{"rotationJitter":0.6}`, `{"xdsHeaders":{"authorization":"forged"}}`, `{"instanceIPs":["not-ip"]}`} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("AGENTIO_GATEWAY_CONFIG", raw)
			if _, err := LoadConfig(nil, io.Discard); err == nil {
				t.Fatal("accepted invalid options")
			}
		})
	}
}

func TestWorkloadKeyOptions(t *testing.T) {
	for _, curve := range []string{"", "P256", "P384"} {
		for _, pkcs8 := range []bool{false, true} {
			c := testConfig(t)
			c.ECCCurve = curve
			c.PKCS8 = pkcs8
			_, encoded, err := generateWorkloadKey(c)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(encoded)
			if block == nil {
				t.Fatal("invalid PEM")
			}
			if pkcs8 {
				_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			} else if curve != "" {
				_, err = x509.ParseECPrivateKey(block.Bytes)
			} else {
				_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestLegacyReadinessEndpoint(t *testing.T) {
	var synced atomic.Bool
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := 0
		if synced.Load() {
			value = 1
		}
		if _, err := fmt.Fprintf(
			w,
			"cluster_manager.cds.update_success: 1\nlistener_manager.lds.update_success: 1\nserver.state: 0\nlistener_manager.workers_started: 1\npolicy_store.initial_sync_ready: %d\n",
			value,
		); err != nil {
			t.Error(err)
		}
	}))
	defer admin.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(admin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig(t)
	c.IP = "127.0.0.1"
	c.Proxy.AdminPort = int32(n)
	c.StatusPort = freePort(t)
	c.Legacy = true
	enabled := true
	c.PolicyStore = &enabled
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var draining atomic.Bool
	stop, _, err := startStatus(ctx, c, nil, cancel, &draining, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	client := &http.Client{Timeout: time.Second}
	for _, test := range []struct {
		sync bool
		want int
	}{{false, 503}, {true, 200}, {false, 200}} {
		synced.Store(test.sync)
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz/ready", c.StatusPort))
		if err != nil {
			t.Fatal(err)
		}
		closeResource(response.Body)
		if response.StatusCode != test.want {
			t.Fatalf("ready=%d want %d", response.StatusCode, test.want)
		}
	}
}
