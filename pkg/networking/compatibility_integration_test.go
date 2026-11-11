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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	prommodel "github.com/prometheus/common/model"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking/telemetry"
)

// Run this with a legacy Istio proxy that supplies the istio.stats extension.
func TestLegacyEnvoyHTTPMetrics(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_LEGACY_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_LEGACY_ENVOY_BINARY to an Istio Envoy binary")
	}
	output, err := telemetry.Build(telemetry.Inputs{
		Gateway:       model.Gateway{Namespace: "test", Name: "egress", Config: &configv1.EgressGateway{}},
		RootNamespace: "test",
		LegacyGateway: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	filter, err := protojson.Marshal(output.HTTPMetrics)
	if err != nil {
		t.Fatal(err)
	}
	business, admin := runCompatibilityEnvoy(t, binary, fmt.Sprintf(`{
      "stats_flush_on_admin":true,
      "static_resources":{"listeners":[{
        "name":"business","address":{"socket_address":{"address":"127.0.0.1","port_value":0}},
        "filter_chains":[{"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{
          "@type":"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
          "stat_prefix":"test","route_config":{"name":"test","virtual_hosts":[{"name":"all","domains":["*"],"routes":[
            {"match":{"path":"/ok"},"direct_response":{"status":200}},
            {"match":{"path":"/error"},"direct_response":{"status":503}}
          ]}]},"http_filters":[%s,{"name":"envoy.filters.http.router","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]
        }}]}]
      }]},"admin":{"address":{"socket_address":{"address":"127.0.0.1","port_value":0}}}
    }`, filter))
	client := &http.Client{Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		path   string
		status int
	}{{"/ok", 200}, {"/error", 503}, {"/missing", 404}} {
		for range 3 {
			r, err := client.Get("http://" + business + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if r.StatusCode != tc.status {
				t.Fatalf("%s: %d", tc.path, r.StatusCode)
			}
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := client.Get("http://" + admin + "/stats/prometheus")
		if err != nil {
			t.Fatal(err)
		}
		parser := expfmt.NewTextParser(prommodel.UTF8Validation)
		families, err := parser.TextToMetricFamilies(r.Body)
		if err := r.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]float64{}
		durations := map[string]uint64{}
		for name, family := range families {
			if !strings.HasPrefix(name, "istio_") || name == "istio_build" {
				continue
			}
			if name != "istio_requests_total" && name != "istio_request_duration_milliseconds" {
				t.Fatalf("unexpected metric family %s", name)
			}
			for _, metric := range family.Metric {
				labels := map[string]string{}
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				if len(labels) != 2 || labels["response_code"] == "" || labels["response_flags"] == "" {
					t.Fatalf("unexpected labels: %v", labels)
				}
				wantFlag := "-"
				if labels["response_code"] == "404" {
					wantFlag = "NR"
				}
				if labels["response_flags"] != wantFlag {
					t.Fatal(labels)
				}
				if name == "istio_requests_total" {
					counts[labels["response_code"]] += metric.GetCounter().GetValue()
				} else {
					durations[labels["response_code"]] += metric.GetHistogram().GetSampleCount()
					if len(metric.GetHistogram().GetBucket()) == 0 {
						t.Fatal("missing duration buckets")
					}
				}
			}
		}
		if counts["200"] == 3 && counts["503"] == 3 && counts["404"] == 3 && durations["200"] == 3 &&
			durations["503"] == 3 &&
			durations["404"] == 3 {
			t.Logf("legacy gateway metrics: requests=%v duration_counts=%v; exactly two dimensions", counts, durations)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("requests=%v durations=%v", counts, durations)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestEnvoyStaticSNIOverlap(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, "passthrough"); err != nil {
			t.Error(err)
		}
	}))
	defer origin.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(origin.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certJSON, err := json.Marshal(
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.TLS.Certificates[0].Certificate[0]})),
	)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})))
	if err != nil {
		t.Fatal(err)
	}
	b := &resourceBuilder{}
	matcher := b.staticSNIMatcher(&configv1.TlsTerminationConfig{
		IncludeHosts: []string{
			"same.test",
			"SAME.test",
			"*.overlap.test",
			"*.overlap.test",
			"include.test",
			"include.test",
			"specific.overlap.test",
		},
		ExcludeHosts: []string{"same.test", "same.test", "*.overlap.test", "*.overlap.test"},
	}, forwardTLSChain)
	if b.err != nil {
		t.Fatal(b.err)
	}
	matcherJSON, err := protojson.Marshal(matcher)
	if err != nil {
		t.Fatal(err)
	}
	business, _ := runCompatibilityEnvoy(t, binary, fmt.Sprintf(`{
      "static_resources":{
        "clusters":[{"name":"origin","connect_timeout":"1s","type":"STATIC","load_assignment":{"cluster_name":"origin","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":%s}}}}]}]}}],
        "listeners":[{"name":"business","address":{"socket_address":{"address":"127.0.0.1","port_value":0}},
          "listener_filters":[{"name":"envoy.filters.listener.tls_inspector","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector"}}],
          "filter_chain_matcher":%s,
          "filter_chains":[
            {"name":"forward-tls","filters":[{"name":"envoy.filters.network.tcp_proxy","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy","stat_prefix":"pass","cluster":"origin"}}]},
            {"name":"tls-terminate","transport_socket":{"name":"envoy.transport_sockets.tls","typed_config":{"@type":"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext","common_tls_context":{"tls_certificates":[{"certificate_chain":{"inline_string":%s},"private_key":{"inline_string":%s}}]}}},
              "filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager","stat_prefix":"terminate","route_config":{"name":"all","virtual_hosts":[{"name":"all","domains":["*"],"routes":[{"match":{"prefix":"/"},"direct_response":{"status":200,"body":{"inline_string":"terminated"}}}]}]},"http_filters":[{"name":"envoy.filters.http.router","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]}}]},
            {"name":"forward-http","filters":[{"name":"envoy.filters.network.tcp_proxy","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy","stat_prefix":"http-fallback","cluster":"origin"}}]}
          ]
        }]
      },"admin":{"address":{"socket_address":{"address":"127.0.0.1","port_value":0}}}
    }`, port, matcherJSON, certJSON, keyJSON))
	for _, tc := range []struct {
		host string
		want string
	}{
		{"same.test", "passthrough"}, {"SAME.test", "passthrough"},
		{"api.overlap.test", "passthrough"}, {"a.b.overlap.test", "passthrough"},
		{"include.test", "terminated"}, {"unmatched.test", "passthrough"},
		{"specific.overlap.test", "terminated"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			client := &http.Client{
				Timeout:   2 * time.Second,
				Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: tc.host}},
			}
			defer client.CloseIdleConnections()
			r, err := client.Get("https://" + business)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(r.Body)
			if err := r.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if err != nil || string(body) != tc.want {
				t.Fatalf("got %q, error %v; want %s", body, err, tc.want)
			}
		})
	}
}

// Both tests exercise production-generated extensions in a minimal real Envoy bootstrap.
func runCompatibilityEnvoy(t *testing.T, binary, config string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	path, adminPath := filepath.Join(directory, "envoy.json"), filepath.Join(directory, "admin.address")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var logs bytes.Buffer
	command := exec.CommandContext(
		ctx,
		binary,
		"-c",
		path,
		"--concurrency",
		"2",
		"--disable-hot-restart",
		"--admin-address-path",
		adminPath,
		"--log-level",
		"warning",
	)
	command.Stdout, command.Stderr = &logs, &logs
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		var exitError *exec.ExitError
		if err := command.Wait(); err != nil && !errors.As(err, &exitError) {
			t.Error(err)
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		address, err := os.ReadFile(adminPath)
		if err != nil {
			if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		admin := strings.TrimSpace(string(address))
		response, err := client.Get("http://" + admin + "/listeners?format=json")
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
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
			t.Fatal(err)
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range listing.Statuses {
			socket := status.Address.Socket
			if socket.Port > 0 {
				return net.JoinHostPort(socket.Address, strconv.Itoa(socket.Port)), admin
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Envoy listener did not start")
	return "", ""
}
