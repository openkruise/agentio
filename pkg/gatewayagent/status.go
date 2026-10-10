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
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/openkruise/agentio/pkg/gatewayagent/internal/envoy"
)

func startStatus(ctx context.Context, c Config, agent *envoy.Agent, cancel context.CancelFunc,
	draining *atomic.Bool, identityReady func() error,
) (func(), <-chan error, error) {
	localhost, _ := localAddresses(c.IP)
	probe := &envoy.Probe{
		LocalHostAddr: localhost,
		AdminPort:     uint16(c.Proxy.AdminPort),
		Context:       ctx,
	}
	var probeMu sync.Mutex
	policyProbe := &policyReadiness{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz/ready", func(w http.ResponseWriter, _ *http.Request) {
		if c.metrics != nil {
			c.metrics.ready.Set(0)
		}
		if draining.Load() || ctx.Err() != nil {
			http.Error(w, "gateway draining", http.StatusServiceUnavailable)
			return
		}
		if err := identityReady(); err != nil {
			http.Error(w, "gateway certificate not ready", http.StatusServiceUnavailable)
			return
		}
		probeMu.Lock()
		err := probe.Check()
		if err == nil {
			err = policyProbe.check(ctx, c)
		}
		probeMu.Unlock()
		if err != nil {
			http.Error(w, "gateway not ready", http.StatusServiceUnavailable)
			return
		}
		if c.metrics != nil {
			c.metrics.ready.Set(1)
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /quitquitquit", func(w http.ResponseWriter, r *http.Request) {
		if !loopbackRequest(r) {
			http.Error(w, "local requests only", http.StatusForbidden)
			return
		}
		draining.Store(true)
		if c.metrics != nil {
			c.metrics.draining.Set(1)
			c.metrics.ready.Set(0)
		}
		agent.DisableDraining()
		cancel()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /drain", func(w http.ResponseWriter, r *http.Request) {
		if !loopbackRequest(r) {
			http.Error(w, "local requests only", http.StatusForbidden)
			return
		}
		draining.Store(true)
		if c.metrics != nil {
			c.metrics.draining.Set(1)
			c.metrics.ready.Set(0)
		}
		agent.DrainNow()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /stats/prometheus", proxyMetrics(c))
	mux.HandleFunc("GET /metrics", proxyMetrics(c))
	if c.Profiling {
		local := func(handler http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if !loopbackRequest(r) {
					http.Error(w, "local requests only", http.StatusForbidden)
					return
				}
				handler(w, r)
			}
		}
		mux.HandleFunc("GET /debug/pprof/", local(pprof.Index))
		mux.HandleFunc("GET /debug/pprof/cmdline", local(pprof.Cmdline))
		mux.HandleFunc("GET /debug/pprof/profile", local(pprof.Profile))
		mux.HandleFunc("GET /debug/pprof/symbol", local(pprof.Symbol))
		mux.HandleFunc("GET /debug/pprof/trace", local(pprof.Trace))
	}
	return serveStatusOn(mux, portOption(c.StatusPort, 15020))
}

// Envoy owns 15021 and 15090; the agent is the readiness backend on 15020.
func serveStatus(status http.Handler) (func(), <-chan error, error) {
	return serveStatusOn(status, 15020)
}

func serveStatusOn(status http.Handler, port int) (func(), <-chan error, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{
		Handler:           status,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	return func() { closeResource(server) }, done, nil
}

func loopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	return err == nil && net.ParseIP(host).IsLoopback()
}

var adminClient = &http.Client{Timeout: 5 * time.Second}

func proxyMetrics(c Config) http.HandlerFunc {
	handler := proxyMetricsPlain(c)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		if boolOption(c.StatsCompression, true) && acceptsGzip(r.Header.Get("Accept-Encoding")) {
			w.Header().Set("Content-Encoding", "gzip")
			zipper := gzip.NewWriter(w)
			defer closeResource(zipper)
			handler(&compressedMetricsWriter{ResponseWriter: w, writer: zipper}, r)
			return
		}
		handler(w, r)
	}
}

func proxyMetricsPlain(c Config) http.HandlerFunc {
	localhost, _ := localAddresses(c.IP)
	target := "http://" + net.JoinHostPort(localhost, strconv.Itoa(int(c.Proxy.AdminPort))) + "/stats/prometheus"
	var agentHandler http.Handler
	if c.metrics != nil {
		agentHandler = promhttp.HandlerFor(c.metrics.registry, promhttp.HandlerOpts{})
	}
	return func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
		if err != nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		request.URL.RawQuery = r.URL.RawQuery
		// Use Prometheus text for both registries, with one uncompressed response.
		request.Header.Set("Accept", "text/plain; version=0.0.4")
		request.Header.Set("Accept-Encoding", "identity")
		// Emit agent health even if Envoy admin is temporarily unavailable.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if agentHandler != nil {
			agentRequest := r.Clone(r.Context())
			agentRequest.Header = r.Header.Clone()
			agentRequest.Header.Set("Accept", "text/plain; version=0.0.4")
			agentRequest.Header.Del("Accept-Encoding")
			agentHandler.ServeHTTP(w, agentRequest)
		}
		response, err := adminClient.Do(request)
		if err != nil {
			if agentHandler == nil {
				http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		defer closeResource(response.Body)
		if response.StatusCode != http.StatusOK {
			return
		}
		// Stream successful responses without buffering or truncating the metrics.
		if _, err := io.Copy(w, response.Body); err != nil {
			slog.Debug("metrics response interrupted", "error", err)
		}
	}
}

type compressedMetricsWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (w *compressedMetricsWriter) Write(p []byte) (int, error) { return w.writer.Write(p) }
func acceptsGzip(header string) bool {
	for part := range strings.SplitSeq(header, ",") {
		tokens := strings.Split(strings.TrimSpace(part), ";")
		if tokens[0] != "gzip" {
			continue
		}
		quality := 1.0
		for _, parameter := range tokens[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && key == "q" {
				parsed, err := strconv.ParseFloat(value, 64)
				if err != nil {
					return false
				}
				quality = parsed
			}
		}
		return quality > 0 && quality <= 1
	}
	return false
}
