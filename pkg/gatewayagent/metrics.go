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
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// One registry per agent instance; no global collector registration or identity
// labels. These are agent health metrics, separate from Envoy traffic statistics.
type agentMetrics struct {
	registry            *prometheus.Registry
	certificateExpiry   atomic.Int64
	certificateRequests prometheus.Counter
	certificateFailures prometheus.Counter
	certificateLatency  prometheus.Histogram
	certificateSuccess  prometheus.Gauge
	rootReloadFailures  prometheus.Counter
	adsConnected        prometheus.Gauge
	adsAttempts         prometheus.Counter
	adsFailures         prometheus.Counter
	adsDisconnects      prometheus.Counter
	sdsNacks            prometheus.Counter
	ready               prometheus.Gauge
	draining            prometheus.Gauge
}

func newAgentMetrics() *agentMetrics {
	m := &agentMetrics{registry: prometheus.NewRegistry()}
	counter := func(name, help string) prometheus.Counter {
		c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: "agentio_gateway_agent", Name: name, Help: help})
		m.registry.MustRegister(c)
		return c
	}
	gauge := func(name, help string) prometheus.Gauge {
		g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "agentio_gateway_agent", Name: name, Help: help})
		m.registry.MustRegister(g)
		return g
	}
	m.certificateRequests = counter("certificate_requests_total", "Workload certificate signing attempts.")
	m.certificateFailures = counter("certificate_failures_total", "Failed workload certificate signing attempts.")
	m.certificateSuccess = gauge(
		"certificate_last_success_timestamp_seconds",
		"Unix time of the last successful certificate renewal.",
	)
	m.certificateLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "agentio_gateway_agent",
			Name:      "certificate_request_duration_seconds",
			Help:      "Workload certificate signing duration.",
			Buckets:   prometheus.DefBuckets,
		},
	)
	m.registry.MustRegister(m.certificateLatency)
	m.registry.MustRegister(
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "agentio_gateway_agent",
				Name:      "certificate_expiry_seconds",
				Help:      "Seconds until the workload certificate expires; zero before issuance.",
			},
			func() float64 {
				expiry := m.certificateExpiry.Load()
				if expiry == 0 {
					return 0
				}
				return time.Until(time.Unix(expiry, 0)).Seconds()
			},
		),
	)
	m.rootReloadFailures = counter("root_reload_failures_total", "Failed reads of the workload trust bundle.")
	m.adsConnected = gauge("ads_connected", "Upstream ADS streams that have delivered a response.")
	m.adsAttempts = counter("ads_connection_attempts_total", "Upstream ADS stream connection attempts.")
	m.adsFailures = counter("ads_connection_failures_total", "ADS sessions that failed before receiving a response.")
	m.adsDisconnects = counter(
		"ads_disconnections_total",
		"Established ADS streams closed while the downstream context was active.",
	)
	m.sdsNacks = counter("sds_nacks_total", "Current local SDS updates rejected by Envoy.")
	m.ready = gauge("ready", "Whether the latest gateway readiness check succeeded.")
	m.draining = gauge("draining", "Whether gateway shutdown or explicit draining has started.")
	return m
}

// The relay's send goroutine may finish after its handler returns. Serialize
// observation and cleanup so a late response cannot leak a connected gauge.
func observeADS(ctx context.Context, m *agentMetrics) (func(), func()) {
	if m == nil {
		return func() {}, func() {}
	}
	m.adsAttempts.Inc()
	var mu sync.Mutex
	received, closed := false, false
	return func() {
			mu.Lock()
			defer mu.Unlock()
			if !closed && !received {
				received = true
				m.adsConnected.Inc()
			}
		}, func() {
			mu.Lock()
			defer mu.Unlock()
			closed = true
			if received {
				m.adsConnected.Dec()
			}
			if ctx.Err() == nil {
				if received {
					m.adsDisconnects.Inc()
				} else {
					m.adsFailures.Inc()
				}
			}
		}
}
