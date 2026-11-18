// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package callout

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	extpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/bench/load"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	calloutfixture "github.com/openkruise/agentio/test/fixtures/httpcallout"
)

var (
	forwardHeaders = flag.Bool(
		"callout-forward-headers",
		false,
		"forward all headers and send 16 fixed 64-byte test headers",
	)
	loadStatus      = flag.Int("callout-status", 200, "expected HTTP status during load")
	envoyImage      = flag.String("envoy-image", "", "opt in to Linux Docker host-network e2e with this Envoy image")
	loadRequests    = flag.Int("callout-requests", 10000, "requests per load round")
	loadConcurrency = flag.Int("callout-concurrency", 32, "concurrent HTTP requests")
	loadRate        = flag.Int("callout-rate", 0, "offered requests/second; zero is closed loop")
	loadBody        = flag.Int("callout-body", 1024, "request body bytes (0..1048576)")
	loadRounds      = flag.Int("callout-rounds", 1, "consecutive load rounds sharing EPE and connection pools")
	loadPath        = flag.String(
		"callout-path",
		"/request/continue/closed",
		"fixture policy route; /baseline disables callouts",
	)
)

type fixture struct {
	url          string
	handler      *calloutfixture.Handler
	upstream     atomic.Int64
	recover      atomic.Bool
	client       *http.Client
	statsURL     string
	transportURL string
	epePID       int
	endpointPID  int
}

func newFixture(t *testing.T) *fixture {
	return newFixtureWithEndpoints(t, "", "")
}

func newFixtureWithEndpoints(t *testing.T, endpointURL, upstreamURL string) *fixture {
	t.Helper()
	if *envoyImage == "" {
		t.Skip("set -envoy-image to run real Envoy e2e on Linux Docker")
	}
	f := &fixture{handler: &calloutfixture.Handler{}, client: &http.Client{Timeout: 10 * time.Second}}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns, tr.MaxIdleConnsPerHost = 512, 256
	f.client.Transport = tr
	t.Cleanup(tr.CloseIdleConnections)
	if endpointURL == "" {
		endpoint := newCalloutEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if f.recover.Load() {
				r.URL.Path = "/continue"
			}
			f.handler.ServeHTTP(w, r)
		}))
		t.Cleanup(endpoint.Close)
		endpointURL = endpoint.URL
	} else {
		f.statsURL = endpointURL + "/stats"
	}
	f.transportURL = endpointURL + "/transport-stats"
	if upstreamURL == "" {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.upstream.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			w.Header().Set("x-upstream", "reached")
			if v := r.Header.Get("x-callout-verdict"); v != "" {
				w.Header().Set("x-request-verdict", v)
			}
			if _, err := w.Write(body); err != nil {
				t.Logf("upstream response interrupted: %v", err)
			}
		}))
		t.Cleanup(upstream.Close)
		upstreamURL = upstream.URL
	}
	providers := &extensionprovider.Registry{}
	t.Cleanup(providers.Close)
	config := &configv1.AgentioConfig{}
	modes := []string{"continue", "mutate", "respond", "status", "malformed", "oversize", "delay", "reset"}
	for _, mode := range modes {
		suffix := "/" + mode
		timeout := *calloutTimeout
		if mode == "continue" && *calloutResponseDelay > 0 {
			suffix = "/delay?duration=" + calloutResponseDelay.String()
		}
		if mode == "delay" {
			suffix += "?duration=500ms"
			timeout = "50ms"
		}
		config.ExtensionProviders = append(
			config.ExtensionProviders,
			&configv1.ExtensionProvider{
				Name: mode,
				Provider: &configv1.ExtensionProvider_HttpCallout{
					HttpCallout: benchmarkProvider(endpointURL+suffix, timeout),
				},
			},
		)
	}
	if err := providers.Apply(config, nil); err != nil {
		t.Fatal(err)
	}
	regs, err := filter.Build(httpcallout.NewDefinition(httpcallout.Deps{Client: httpcallout.NewHTTPClient(providers)}))
	if err != nil {
		t.Fatal(err)
	}
	headerMode := "none"
	if *forwardHeaders {
		headerMode = "all"
	}
	policies := map[string][]any{}
	for _, phase := range []string{"request", "response", "headers"} {
		for _, mode := range modes {
			for _, policy := range []string{"open", "closed"} {
				direction := phase
				if phase == "headers" {
					direction = "request"
				}
				payload := fmt.Sprintf(
					`{"provider":%q,%q:{"body":%t,"headers":{"mode":%q}},"maxBodyBytes":2097152,"failOpen":%t}`,
					mode,
					direction,
					phase != "headers",
					headerMode,
					policy == "open",
				)
				cfgs, errs := filter.Project(regs, map[string]json.RawMessage{regs[0].Name: json.RawMessage(payload)})
				if errs[0] != nil {
					t.Fatal(errs[0])
				}
				policies["/"+phase+"/"+mode+"/"+policy] = cfgs
			}
		}
	}
	server := extproc.NewServer(extproc.ServerDeps{Registrations: regs,
		FailClosedOnMissingIdentity: true,
		Resolve: func(_ context.Context, pod subject.Subject, req *httpreq.HTTPRequest) (engine.Resolution, error) {
			if req.Path == "/baseline" {
				return engine.Resolution{}, nil
			}
			cfgs, ok := policies[req.Path]
			if !ok {
				return engine.Resolution{}, fmt.Errorf("unknown test policy %s", req.Path)
			}
			scope := inputs.NewScope(
				inputs.RequestFrom(*req),
				inputs.WorkloadFromSubject(pod),
				inputs.Profile{Name: "test", Namespace: "default"},
				inputs.Rule{Name: "callout"},
				nil,
			)
			return engine.Resolution{
				Units: []engine.Unit{
					{ID: filter.UnitID{Scope: "default/test", Name: "callout"}, Scope: scope, Cfgs: cfgs},
				},
			}, nil
		},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	extpb.RegisterExternalProcessorServer(grpcServer, server)
	t.Cleanup(grpcServer.Stop)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Errorf("gRPC Serve: %v", err)
		}
	}()
	// Docker host networking requires a host port; reserve an ephemeral one until config is written.
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := proxy.Addr().(*net.TCPAddr).Port
	f.url = fmt.Sprintf("http://127.0.0.1:%d", port)
	dir := t.TempDir()
	cfg := fmt.Sprintf(
		envoyConfig,
		port,
		listener.Addr().(*net.TCPAddr).Port,
		strings.TrimPrefix(upstreamURL, "http://127.0.0.1:"),
	)
	configPath := filepath.Join(dir, "envoy.yaml")
	if err := os.WriteFile(configPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("callout-test-%d-%d", os.Getpid(), port)
	out, err := exec.Command("docker", "run", "-d", "--rm", "--network", "host", "--name", name, "-v", configPath+":/etc/envoy/envoy.yaml:ro", *envoyImage, "-c", "/etc/envoy/envoy.yaml", "--concurrency", "2", "--log-level", "error").
		CombinedOutput()
	if err != nil {
		t.Fatalf("start Envoy: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, err := exec.Command("docker", "logs", name).CombinedOutput()
			t.Logf("Envoy logs (error=%v): %s", err, out)
		}
		if out, err := exec.Command("docker", "rm", "-f", name).CombinedOutput(); err != nil {
			t.Errorf("remove Envoy: %v: %s", err, out)
		}
	})
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		resp, err := f.client.Get(f.url + "/baseline")
		if err == nil {
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			closeBody(t, resp.Body)
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Envoy did not become ready")
	}
	return f
}

func TestEnvoyE2E(t *testing.T) {
	f := newFixture(t)
	for _, phase := range []string{"request", "response"} {
		for _, mode := range []string{"continue", "mutate", "respond", "status", "malformed", "oversize", "delay", "reset"} {
			for _, policy := range []string{"open", "closed"} {
				t.Run(phase+"/"+mode+"/"+policy, func(t *testing.T) {
					fault := mode == "status" || mode == "malformed" || mode == "oversize" || mode == "delay" ||
						mode == "reset"
					want := 200
					if mode == "respond" {
						want = 403
					} else if fault && policy == "closed" {
						want = 500
					}
					path := "/" + phase + "/" + mode + "/" + policy
					original := strings.Repeat("original", 128)
					beforeCalls, beforeUpstream := f.handler.Calls.Load(), f.upstream.Load()
					resp, err := f.client.Post(f.url+path, "text/plain", strings.NewReader(original))
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(resp.Body)
					closeBody(t, resp.Body)
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != want {
						t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, want, body)
					}
					if delta := f.handler.Calls.Load() - beforeCalls; delta != 1 {
						t.Fatalf("callout attempts=%d, want exactly one (no bypass/retry)", delta)
					}
					upstreamCalls := int64(1)
					if phase == "request" && want != 200 {
						upstreamCalls = 0
					}
					if delta := f.upstream.Load() - beforeUpstream; delta != upstreamCalls {
						t.Fatalf("upstream calls=%d want=%d", delta, upstreamCalls)
					}
					if mode == "mutate" {
						if string(body) != "changed by callout" {
							t.Fatalf("mutation body=%q", body)
						}
						header := "x-request-verdict"
						if phase == "response" {
							header = "x-callout-verdict"
						}
						if resp.Header.Get(header) != "clean" {
							t.Fatalf("missing %s", header)
						}
					} else if want == 200 && string(body) != original {
						t.Fatalf("body=%q", body)
					}
					if mode == "respond" && string(body) != "blocked by callout" {
						t.Fatalf("block body=%q", body)
					}
					if fault {
						// Recover the same endpoint/provider, without replacing its client or pool.
						f.recover.Store(true)
						defer f.recover.Store(false)
						resp, err := f.client.Post(f.url+path, "text/plain", strings.NewReader("recovered"))
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(resp.Body)
						closeBody(t, resp.Body)
						if err != nil {
							t.Fatal(err)
						}
						if resp.StatusCode != 200 || string(body) != "recovered" {
							t.Fatalf("recovery status=%d body=%q", resp.StatusCode, body)
						}
					}
				})
			}
		}
	}
	if f.handler.Canceled.Load() == 0 {
		t.Fatal("timeout did not cancel endpoint work")
	}
}

func TestEnvoyLoad(t *testing.T) {
	if *loadBody < 0 || *loadBody > 1<<20 || *loadRounds < 1 {
		t.Fatal("invalid body size or rounds")
	}
	var f *fixture
	if *isolatedLoad {
		f = newIsolatedFixture(t)
	} else {
		f = newFixture(t)
	}
	payload := strings.Repeat("x", *loadBody)
	for round := 0; round < *loadRounds; round++ {
		calls := f.callCount(t)
		cpuBefore, _ := f.epeResources(t)
		endpointCPUBefore, _ := processResources(t, f.endpointPID)
		result, err := load.Run(
			context.Background(),
			load.Config{
				Requests:    *loadRequests,
				Identities:  1,
				Concurrency: *loadConcurrency,
				Rate:        *loadRate,
				Duration:    10 * time.Minute,
			},
			func(ctx context.Context, _ int) error {
				req, err := http.NewRequestWithContext(ctx, "POST", f.url+*loadPath, strings.NewReader(payload))
				if err != nil {
					return err
				}
				if *forwardHeaders {
					for i := range 16 {
						req.Header.Set(fmt.Sprintf("x-bench-%02d", i), strings.Repeat("h", 64))
					}
				}
				resp, err := f.client.Do(req)
				if err != nil {
					return err
				}
				body, err := io.ReadAll(resp.Body)
				closeBody(t, resp.Body)
				if err != nil {
					return err
				}
				if resp.StatusCode != *loadStatus || (*loadStatus == 200 && string(body) != payload) {
					return fmt.Errorf("unexpected response: status=%d bytes=%d", resp.StatusCode, len(body))
				}
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		expectedCalls := int64(result.Operations)
		if *loadPath == "/baseline" {
			expectedCalls = 0
		}
		cpuAfter, rss := f.epeResources(t)
		endpointCPUAfter, endpointRSS := processResources(t, f.endpointPID)
		runtime.GC()
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		record := struct {
			Transport   transportStats `json:"transport"`
			EndpointCPU float64        `json:"endpoint_cpu_seconds"`
			EndpointRSS int            `json:"endpoint_rss_bytes"`
			EPECPU      float64        `json:"epe_cpu_seconds"`
			EPERSS      int            `json:"epe_rss_bytes"`
			Round       int            `json:"round"`
			Result      load.Result    `json:"result"`
			Heap        uint64         `json:"heap_alloc"`
			Goroutines  int            `json:"goroutines"`
			FDs         int            `json:"fds"`
			Active      int64          `json:"active_callouts"`
		}{f.transportStats(t), endpointCPUAfter - endpointCPUBefore, endpointRSS, cpuAfter - cpuBefore, rss, round, result, mem.HeapAlloc, runtime.NumGoroutine(), len(fds), f.activeCalls(t)}
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("RESULT %s", raw)
		if delta := f.callCount(t) - calls; delta != expectedCalls {
			t.Fatalf("callouts=%d expected=%d errors=%d first_error=%s transport=%+v",
				delta, expectedCalls, result.Errors, result.FirstError, f.transportStats(t))
		}
		if result.Errors != 0 || result.Operations != *loadRequests {
			t.Fatalf("errors=%d completed=%d: %s", result.Errors, result.Operations, result.FirstError)
		}
	}
}

const envoyConfig = `static_resources:
  listeners:
  - name: ingress
    address: {socket_address: {address: 127.0.0.1, port_value: %d}}
    per_connection_buffer_limit_bytes: 4194304
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: callout_test
          route_config:
            name: local
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: {prefix: /}
                route: {cluster: upstream, timeout: 10s}
          http_filters:
          - name: envoy.filters.http.set_filter_state
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
              on_request_headers:
              - object_key: agentio.workload.namespace
                factory_key: envoy.string
                format_string: {text_format_source: {inline_string: default}}
              - object_key: agentio.workload.name
                factory_key: envoy.string
                format_string: {text_format_source: {inline_string: bench}}
          - name: envoy.filters.http.ext_proc
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
              grpc_service: {envoy_grpc: {cluster_name: epe}}
              message_timeout: 5s
              allow_mode_override: true
              request_attributes: ["filter_state['agentio.workload.namespace']", "filter_state['agentio.workload.name']"]
              processing_mode: {request_header_mode: SEND, response_header_mode: SEND, request_body_mode: NONE, response_body_mode: NONE, request_trailer_mode: SKIP, response_trailer_mode: SKIP}
          - name: envoy.filters.http.router
            typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}
  clusters:
  - name: epe
    type: STATIC
    connect_timeout: 1s
    http2_protocol_options: {}
    # Keep ext_proc circuit breaking above the callout capacity under test.
    circuit_breakers:
      thresholds: [{max_requests: 8192, max_pending_requests: 8192}]
    load_assignment:
      cluster_name: epe
      endpoints:
      - lb_endpoints:
        - endpoint: {address: {socket_address: {address: 127.0.0.1, port_value: %d}}}
  - name: upstream
    type: STATIC
    connect_timeout: 1s
    load_assignment:
      cluster_name: upstream
      endpoints:
      - lb_endpoints:
        - endpoint: {address: {socket_address: {address: 127.0.0.1, port_value: %s}}}
`

func closeBody(t *testing.T, body io.Closer) {
	t.Helper()
	if err := body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}

func benchmarkProvider(url, timeout string) *configv1.HTTPCalloutProvider {
	p := &configv1.HTTPCalloutProvider{
		Url:     url,
		Timeout: timeout,
	}
	if *calloutMaxConnections != 0 || *calloutMaxIdle >= 0 {
		p.ConnectionPool = &configv1.HTTPCalloutConnectionPool{}
		if *calloutMaxConnections != 0 {
			connections := uint32(*calloutMaxConnections)
			p.ConnectionPool.MaxConnections = &connections
		}
		if *calloutMaxIdle >= 0 {
			idle := uint32(*calloutMaxIdle)
			p.ConnectionPool.MaxIdleConnections = &idle
		}
	}
	if *calloutHTTP2 {
		p.Protocol = configv1.HTTPCalloutProvider_HTTP2
		streams := uint32(*calloutClientStreams)
		p.Http2 = &configv1.HTTPCalloutHTTP2{MaxConcurrentStreams: &streams}
	}
	return p
}
