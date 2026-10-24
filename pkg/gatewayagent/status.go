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
	"cmp"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"istio.io/istio/pkg/ptr"

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
	var lastReason string
	var checked bool
	var everReady bool
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz/ready", func(w http.ResponseWriter, _ *http.Request) {
		probeMu.Lock()
		defer probeMu.Unlock()
		reason := ""
		isDraining := draining.Load() || ctx.Err() != nil
		defer func() {
			if !checked || reason != lastReason {
				switch {
				case isDraining:
					statusLog.Info("gateway is draining")
				case reason == "":
					everReady = true
					statusLog.Info("gateway is ready")
				case !everReady:
					statusLog.Info("gateway is waiting for readiness", "reason", reason)
				default:
					statusLog.Warn("gateway is not ready", "reason", reason)
				}
			}
			checked, lastReason = true, reason
		}()
		if c.metrics != nil {
			c.metrics.ready.Set(0)
		}
		if isDraining {
			reason = "gateway draining"
			http.Error(w, reason, http.StatusServiceUnavailable)
			return
		}
		if err := identityReady(); err != nil {
			reason = err.Error()
			http.Error(w, "gateway certificate not ready", http.StatusServiceUnavailable)
			return
		}
		err := probe.Check()
		if err != nil {
			reason = err.Error()
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
	return serveStatusOn(mux, cmp.Or(c.StatusPort, 15020))
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
	statusLog.Info("gateway status server listening", "port", listener.Addr().(*net.TCPAddr).Port)
	server := &http.Server{
		Handler:           status,
		ReadHeaderTimeout: 5 * time.Second,
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

var adminClient = &http.Client{}

func proxyMetrics(c Config) http.HandlerFunc {
	handler := proxyMetricsPlain(c)
	return func(w http.ResponseWriter, r *http.Request) {
		if c.MetricsLocalhostOnly && !loopbackRequest(r) {
			http.Error(w, "metrics are restricted to localhost", http.StatusForbidden)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		if ptr.OrDefault(c.StatsCompression, true) && acceptsGzip(r.Header.Get("Accept-Encoding")) {
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
	return func(w http.ResponseWriter, r *http.Request) {
		if c.metrics != nil {
			c.metrics.scrapeTotals.Inc()
		}
		ctx := r.Context()
		if value := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); value != "" {
			seconds, err := strconv.ParseFloat(value, 64)
			if err != nil {
				statusLog.Warn("invalid Prometheus scrape timeout", "value", value, "error", err)
			} else {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(seconds*float64(time.Second)))
				defer cancel()
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		request.URL.RawQuery = r.URL.RawQuery
		for _, name := range []string{"User-Agent", "X-Prometheus-Scrape-Timeout-Seconds"} {
			request.Header.Set(name, r.Header.Get(name))
		}
		// Use Prometheus text for both registries, with one uncompressed response.
		request.Header.Set("Accept", "text/plain; version=0.0.4")
		request.Header.Set("Accept-Encoding", "identity")
		// Emit agent health even if Envoy admin is temporarily unavailable.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if c.metrics != nil {
			defer func() {
				if err := c.metrics.writeMetrics(w); err != nil {
					c.metrics.agentScrapeFailures.Inc()
					statusLog.Warn("Agent metrics export failed", "error", err)
				}
			}()
		}
		var scrapeErr error
		defer func() {
			if scrapeErr != nil {
				statusLog.Warn("Envoy metrics scrape failed", "error", scrapeErr)
				if c.metrics != nil {
					c.metrics.envoyScrapeFailures.Inc()
				}
			}
		}()
		response, err := adminClient.Do(request)
		if err != nil {
			scrapeErr = err
			if c.metrics == nil {
				http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		defer closeResource(response.Body)
		if response.StatusCode != http.StatusOK {
			scrapeErr = fmt.Errorf("Envoy admin returned HTTP %d", response.StatusCode)
			if c.metrics == nil {
				http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		// Stream successful responses without buffering or truncating the metrics.
		if err := copyGatewayMetrics(w, response.Body); err != nil {
			scrapeErr = err
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
