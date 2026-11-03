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
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	agentiomodel "github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking/telemetry"
)

//go:embed testdata/dynamic-metrics.json
var dynamicMetricsFixture []byte

func TestCommunityEnvoyDynamicMetrics(t *testing.T) { testCommunityEnvoyMetrics(t, true) }

func TestCommunityEnvoyHTTPMetrics(t *testing.T) { testCommunityEnvoyMetrics(t, false) }

func testCommunityEnvoyMetrics(t *testing.T, legacy bool) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	module := os.Getenv("AGENTIO_TEST_METRICS_MODULE")
	if module == "" {
		module = "/usr/local/lib/libagentio_gateway_metrics.so"
	}
	if _, err := os.Stat(module); err != nil {
		t.Fatal(err)
	}
	c := testConfig(t)
	c.IP = "127.0.0.1"
	c.metrics = newAgentMetrics()
	ports, releasePorts := reservePorts(t, 5)
	c.Proxy.AdminPort = int32(ports[0])
	metricsPort, statusPort, businessPort := ports[1], ports[2], ports[3]
	c.PrometheusPort, c.EnvoyStatusPort = metricsPort, statusPort
	agent := httptest.NewServer(proxyMetrics(c))
	defer agent.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(agent.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	agentPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c.StatusPort = agentPort
	bootstrap, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	data, err := protojson.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var config, fixture map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(dynamicMetricsFixture, &fixture); err != nil {
		t.Fatal(err)
	}
	delete(config, "dynamicResources")
	resources := config["staticResources"].(map[string]any)
	listener := fixture["static_resources"].(map[string]any)["listeners"].([]any)[0].(map[string]any)
	listener["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = businessPort
	hcm := listener["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
	arrived := make(chan struct{})
	slow := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(arrived)
			<-r.Context().Done()
		}),
	)
	defer slow.Close()
	_, slowPort, err := net.SplitHostPort(strings.TrimPrefix(slow.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var cluster map[string]any
	if err := json.Unmarshal(
		[]byte(
			fmt.Sprintf(
				`{"name":"slow","connect_timeout":"1s","type":"STATIC","load_assignment":{"cluster_name":"slow","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":%s}}}}]}]}}`,
				slowPort,
			),
		),
		&cluster,
	); err != nil {
		t.Fatal(err)
	}
	resources["clusters"] = append(resources["clusters"].([]any), cluster)
	virtualHost := hcm["route_config"].(map[string]any)["virtual_hosts"].([]any)[0].(map[string]any)
	virtualHost["routes"] = append(
		[]any{map[string]any{"match": map[string]any{"path": "/abort"}, "route": map[string]any{"cluster": "slow"}}},
		virtualHost["routes"].([]any)...)
	accessLog := hcm["access_log"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
	accessLog["dynamic_module_config"].(map[string]any)["module"].(map[string]any)["local"].(map[string]any)["filename"] = module
	resources["listeners"] = append(resources["listeners"].([]any), listener)
	if !legacy {
		delete(hcm, "access_log")
		// Exercise the controller's configuration, including the packaged module path.
		output, err := telemetry.Build(telemetry.Inputs{
			Gateway: agentiomodel.Gateway{Namespace: "test", Name: "egress", Config: &configv1.EgressGateway{}},
		})
		if err != nil {
			t.Fatal(err)
		}
		data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(output.HTTPMetrics)
		if err != nil {
			t.Fatal(err)
		}
		var metricsFilter map[string]any
		if err := json.Unmarshal(data, &metricsFilter); err != nil {
			t.Fatal(err)
		}
		if os.Getenv("AGENTIO_TEST_METRICS_MODULE") != "" {
			moduleConfig := metricsFilter["typed_config"].(map[string]any)["dynamic_module_config"].(map[string]any)
			moduleConfig["module"].(map[string]any)["local"].(map[string]any)["filename"] = module
		}
		hcm["http_filters"] = append([]any{metricsFilter}, hcm["http_filters"].([]any)...)
		// Remove the catch-all direct response so missing routes exercise NR.
		routes := virtualHost["routes"].([]any)
		virtualHost["routes"] = append([]any{map[string]any{
			"match": map[string]any{"path": "/unreachable"},
			"route": map[string]any{
				"cluster":      "unreachable",
				"retry_policy": map[string]any{"retry_on": "connect-failure", "num_retries": 1},
			},
		}}, routes[:len(routes)-1]...)
		// The reserved port is released immediately before Envoy starts; no server listens there.
		var unreachable map[string]any
		if err := json.Unmarshal(
			[]byte(
				fmt.Sprintf(
					`{"name":"unreachable","connect_timeout":"1s","type":"STATIC","load_assignment":{"cluster_name":"unreachable","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":%d}}}}]}]}}`,
					ports[4],
				),
			),
			&unreachable,
		); err != nil {
			t.Fatal(err)
		}
		resources["clusters"] = append(resources["clusters"].([]any), unreachable)
	}

	config["stats_flush_on_admin"] = true
	delete(config, "statsFlushInterval")
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "envoy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	command := exec.CommandContext(
		ctx,
		binary,
		"-c",
		path,
		"--concurrency",
		"2",
		"--disable-hot-restart",
		"--log-level",
		"warning",
	)
	command.Stdout, command.Stderr = &logs, &logs
	releasePorts()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		var exitError *exec.ExitError
		if err := command.Wait(); err != nil && !errors.As(err, &exitError) {
			t.Error(err)
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", c.Proxy.AdminPort))
		if err == nil {
			closeResource(response.Body)
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Envoy did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	codes := []int{200, 201, 204, 302, 403, 404, 418, 429, 500, 503, 504}
	// Do not follow redirects: each response is one downstream request.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, code := range codes {
		for range 3 {
			response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/%d", businessPort, code))
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, response.Body)
			closeResource(response.Body)
			if err != nil || response.StatusCode != code {
				t.Fatalf("status %d: response %d, error %v", code, response.StatusCode, err)
			}
		}
	}

	if !legacy {
		// Envoy creates the HTTP filter only after receiving complete headers. The
		// duration must still include time spent receiving the partial request.
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", businessPort))
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			closeResource(conn)
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, "GET /201 HTTP/1.1\r\nHost: test\r\nX-Slow: "); err != nil {
			closeResource(conn)
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if _, err := io.WriteString(conn, "done\r\nConnection: close\r\n\r\n"); err != nil {
			closeResource(conn)
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			closeResource(conn)
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		closeResource(response.Body)
		closeResource(conn)
		if err != nil || response.StatusCode != 201 {
			t.Fatalf("partial headers: status %d, error %v", response.StatusCode, err)
		}
	}

	connection, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", businessPort))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(connection, "GET /abort HTTP/1.1\r\nHost: test\r\n\r\n"); err != nil {
		closeResource(connection)
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		closeResource(connection)
		t.Fatal("upstream never received abort request")
	}
	closeResource(connection)
	if !legacy {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/missing", businessPort))
		if err != nil {
			t.Fatal(err)
		}
		closeResource(response.Body)
		if response.StatusCode != 404 {
			t.Fatalf("missing route status = %d", response.StatusCode)
		}
		response, err = client.Get(fmt.Sprintf("http://127.0.0.1:%d/unreachable", businessPort))
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		closeResource(response.Body)
		if err != nil || response.StatusCode != 503 {
			t.Fatalf("refused upstream: status %d, error %v", response.StatusCode, err)
		}
	}

	// Agent endpoints translate and merge; the Envoy port remains usable without the Agent.
	for _, endpoint := range []struct {
		url    string
		prefix string
	}{
		{url: agent.URL + "/stats/prometheus"},
		{url: agent.URL + "/metrics"},
		{url: fmt.Sprintf("http://127.0.0.1:%d/stats/prometheus", metricsPort), prefix: "envoy_agentio_gateway_"},
	} {
		url := endpoint.url
		extraRequests := 0
		if endpoint.prefix != "" {
			agent.Close()
			if !legacy {
				// Eight concurrent clients distribute new connections across both Envoy workers.
				// No gateway-agent scrape server exists while these observations are recorded.
				loadClient := &http.Client{
					Timeout:   3 * time.Second,
					Transport: &http.Transport{DisableKeepAlives: true},
				}
				failures := make(chan error, 8)
				var workers sync.WaitGroup
				for range 8 {
					workers.Go(func() {
						for range 100 {
							response, err := loadClient.Get(fmt.Sprintf("http://127.0.0.1:%d/200", businessPort))
							if err != nil {
								failures <- err
								return
							}
							_, err = io.Copy(io.Discard, response.Body)
							closeResource(response.Body)
							if err != nil || response.StatusCode != 200 {
								failures <- errors.Join(fmt.Errorf("concurrent request: status %d", response.StatusCode), err)
								return
							}
						}
					})
				}
				workers.Wait()
				close(failures)
				for err := range failures {
					t.Fatal(err)
				}
				extraRequests = 800
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			response, err := client.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			parser := expfmt.NewTextParser(model.UTF8Validation)
			families, err := parser.TextToMetricFamilies(response.Body)
			closeResource(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]float64{}
			flagCounts := map[string]float64{}
			for _, metric := range families[endpoint.prefix+"istio_requests_total"].GetMetric() {
				if endpoint.prefix == "" && metric.GetCounter().GetValue() == 0 {
					t.Fatalf("unused response code exported at %s: %v", url, metric)
				}
				if !legacy {
					if len(metric.Label) != 2 {
						t.Fatalf("unexpected labels: %v", metric.Label)
					}
					for _, label := range metric.Label {
						if label.GetName() == "response_flags" {
							flagCounts[label.GetValue()] += metric.GetCounter().GetValue()
						}
					}
				}

				for _, label := range metric.GetLabel() {
					if label.GetName() == "response_code" {
						counts[label.GetValue()] += metric.GetCounter().GetValue()
					}
				}
			}
			duration := families[endpoint.prefix+"istio_request_duration_milliseconds"]
			if duration == nil || len(duration.Metric) == 0 {
				t.Fatal("missing duration histogram")
			}
			var total uint64
			var slowDuration float64
			for _, metric := range duration.Metric {
				total += metric.GetHistogram().GetSampleCount()
				if !legacy {
					if len(metric.Label) != 2 {
						t.Fatalf("unexpected histogram labels: %v", metric.Label)
					}
					labels := map[string]string{}
					for _, label := range metric.Label {
						labels[label.GetName()] = label.GetValue()
					}
					if labels["response_code"] == "201" {
						slowDuration += metric.GetHistogram().GetSampleSum()
					}
					if labels["response_code"] == "" || labels["response_flags"] == "" {
						t.Fatalf("missing histogram labels: %v", metric.Label)
					}
				}
			}
			histogram := duration.Metric[0].GetHistogram()
			// Admin-triggered histogram merging finishes asynchronously on worker threads.
			wantTotal := uint64(len(codes)*3 + 1)
			if !legacy {
				wantTotal += uint64(3 + extraRequests)
			}
			if total != wantTotal || counts["0"] != 1 {
				if time.Now().After(deadline) {
					t.Fatalf("histogram count %d, aborted count %v", total, counts["0"])
				}
				time.Sleep(20 * time.Millisecond)
				continue
			}
			if !legacy &&
				(flagCounts["-"] != float64(len(codes)*3+1+extraRequests) || flagCounts["NR"] != 1 || flagCounts["DC"] != 1 || flagCounts["UF,URX"] != 1) {
				t.Fatalf("response_flags counts = %v", flagCounts)
			}

			if !legacy && slowDuration < 150 {
				t.Fatalf("partial header receipt missing from duration: %v ms", slowDuration)
			}
			for _, code := range codes {
				want := float64(3)
				if !legacy && (code == 404 || code == 201 || code == 503) {
					want++
				}
				if code == 200 {
					want += float64(extraRequests)
				}
				if counts[strconv.Itoa(code)] != want {
					t.Fatalf("%s: code %d count %v", url, code, counts[strconv.Itoa(code)])
				}
			}
			wantBuckets := []float64{
				0.5,
				1,
				5,
				10,
				25,
				50,
				100,
				250,
				500,
				1000,
				2500,
				5000,
				10000,
				30000,
				60000,
				300000,
				600000,
				1800000,
				3600000,
				math.Inf(1),
			}
			if len(histogram.Bucket) != len(wantBuckets) {
				t.Fatalf("buckets = %v", histogram.Bucket)
			}
			for i, bucket := range histogram.Bucket {
				if bucket.GetUpperBound() != wantBuckets[i] {
					t.Fatalf("bucket %d = %v", i, bucket)
				}
			}
			if endpoint.prefix == "" {
				if families["agentio_gateway_agent_scrapes_total"] == nil {
					t.Fatal("missing Agent metrics on Agent endpoint")
				}
				for name := range families {
					if strings.HasPrefix(name, "envoy_agentio_gateway_istio_") {
						t.Fatalf("untranslated metric %s", name)
					}
				}
			} else {
				if _, ok := counts["299"]; legacy && (!ok || counts["299"] != 0) {
					t.Fatal("raw endpoint must preserve unused response-code counters")
				}
				for name := range families {
					if strings.HasPrefix(name, "agentio_gateway_agent_") || strings.HasPrefix(name, "istio_") {
						t.Fatalf("Agent-processed metric on raw endpoint: %s", name)
					}
				}
			}
			break
		}
	}
}
