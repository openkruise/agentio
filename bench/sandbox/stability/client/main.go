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

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/openkruise/agentio/bench/load"
	agentlog "github.com/openkruise/agentio/pkg/log"
)

const workers = 8

var log = agentlog.New("sandbox-stability-client")

type config struct {
	Rate         float64 `json:"rate"`
	DomainCount  int     `json:"domain_count"`
	ClientIndex  int     `json:"client_index"`
	Clients      int     `json:"clients"`
	ColdFraction float64 `json:"cold_fraction"`
	Scheme       string  `json:"scheme"`
	Port         int     `json:"port"`
	Fault        bool    `json:"fault"`
	Mixed        bool    `json:"mixed"`
	Deny         bool    `json:"deny"`
	Group        string  `json:"group,omitempty"`
	Duration     float64 `json:"duration"`
}

func (c config) validate() error {
	if c.DomainCount <= 0 || c.Clients <= 0 || c.ClientIndex < 0 || c.ClientIndex >= c.Clients {
		return errors.New("domain_count and clients must be positive and client_index must be in [0, clients)")
	}
	if c.ColdFraction < 0 || c.ColdFraction > 1 {
		return errors.New("cold_fraction must be between 0 and 1")
	}
	if (c.Scheme != "http" && c.Scheme != "https") || c.Port < 1 || c.Port > 65535 {
		return errors.New("scheme must be http or https and port must be between 1 and 65535")
	}
	if c.Duration < 1e-9 || c.Duration*float64(time.Second) >= float64(1<<63) {
		return errors.New("duration must be a positive, representable number of seconds")
	}
	return nil
}

type client struct {
	mu           sync.Mutex
	config       config
	runContext   context.Context
	cancel       context.CancelFunc
	stopped      bool
	rates        chan float64
	queue        *load.Queue
	roots        *x509.CertPool
	groups       map[string]*groupStats
	certificates map[string]certificate
	seen         map[string]struct{}
	coldSequence int
	samples      []map[string]any
	output       io.Writer
}

func newClient(roots *x509.CertPool, output io.Writer) *client {
	return &client{
		config: config{
			DomainCount:  500,
			Clients:      100,
			ColdFraction: 0.2,
			Scheme:       "https",
			Port:         8443,
			Deny:         true,
			Duration:     21600,
		},
		queue:        load.NewQueue(32),
		rates:        make(chan float64, 1),
		roots:        roots,
		groups:       make(map[string]*groupStats),
		certificates: make(map[string]certificate),
		seen:         make(map[string]struct{}),
		samples:      make([]map[string]any, 0, 100),
		output:       output,
	}
}

func (c *client) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, map[string]bool{"healthy": true})
	})
	mux.HandleFunc("GET /{$}", c.status)
	mux.HandleFunc("GET /status", c.status)
	mux.HandleFunc("POST /start", c.update)
	mux.HandleFunc("POST /config", c.update)
	mux.HandleFunc("POST /probe", c.probe)
	mux.HandleFunc("POST /stop", func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		c.stopped = true
		if c.cancel != nil {
			c.cancel()
		}
		c.mu.Unlock()
		respond(w, http.StatusOK, map[string]bool{"stopping": true})
	})
	return mux
}

func respond(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Error("write management response", "error", err)
	}
}

func readOptions(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return []byte("{}"), nil
	}
	return data, nil
}

func (c *client) update(w http.ResponseWriter, r *http.Request) {
	data, err := readOptions(w, r)
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	code, err := c.configure(data, r.URL.Path == "/start")
	if err != nil {
		respond(w, code, map[string]string{"error": err.Error()})
		return
	}
	respond(w, http.StatusOK, map[string]bool{"updated": true})
}

func (c *client) configure(data []byte, start bool) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if start && (c.runContext != nil || c.stopped) {
		return http.StatusConflict, errors.New("already started or stopped")
	}
	updated := c.config
	if err := json.Unmarshal(data, &updated); err != nil {
		return http.StatusBadRequest, err
	}
	if err := updated.validate(); err != nil {
		return http.StatusBadRequest, err
	}
	previousRate := c.config.Rate
	c.config = updated
	if start {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(updated.Duration*float64(time.Second)))
		c.runContext = ctx
		c.cancel = cancel
		go c.run(ctx, updated.Rate)
	} else if c.runContext != nil && updated.Rate != previousRate {
		// Keep only the latest pending rate if updates arrive faster than the scheduler reads them.
		select {
		case <-c.rates:
		default:
		}
		c.rates <- updated.Rate
	}
	return http.StatusOK, nil
}

func (c *client) run(ctx context.Context, rate float64) {
	var hot [workers]*connection
	c.queue.Run(ctx, workers, rate, c.rates, func(worker, sequence int, scheduled time.Time) {
		req, group, cold := c.nextRequest(worker, sequence)
		var fresh *connection
		slot := &hot[worker]
		if cold {
			slot = &fresh
		}
		start := time.Now()
		outcome := exchange(context.Background(), req, c.roots, slot)
		if outcome.err == nil {
			outcome.check(req)
		}
		if cold || outcome.err != nil {
			closeConnection(slot)
		}
		c.record(group, req.Host, time.Since(start), start.Sub(scheduled), outcome)
	}, func() {
		c.record("generator", "", 0, 0, observation{
			err:       errors.New("bounded generator queue full"),
			errorType: "RuntimeError",
		})
	})
	for i := range hot {
		closeConnection(&hot[i])
	}
	result := c.snapshot()
	if err := json.NewEncoder(c.output).Encode(map[string]any{
		"event": "run-complete",
		"time":  result.Time,
		"stats": result,
	}); err != nil {
		log.Error("write run result", "error", err)
	}
}

func (c *client) probe(w http.ResponseWriter, r *http.Request) {
	data, err := readOptions(w, r)
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req := request{Host: "hot-00.load.test", Scheme: "https", Port: 8443, Path: "/allow"}
	if err := json.Unmarshal(data, &req); err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := req.validate(); err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	start := time.Now()
	var conn *connection
	defer closeConnection(&conn)
	outcome := exchange(r.Context(), req, c.roots, &conn)
	result := map[string]any{"latency_ms": ms(time.Since(start))}
	if outcome.err != nil {
		result["error"] = outcome.err.Error()
		result["error_type"] = outcome.errorType
	} else {
		result["status"] = outcome.status
		result["body"] = string(outcome.body[:min(len(outcome.body), 4096)])
		if outcome.cert != nil {
			outcome.cert.NotBefore = ""
		}
		result["certificate"] = outcome.cert
	}
	respond(w, http.StatusOK, result)
}

func run(ca string, port int) error {
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("no certificates in %s", ca)
	}
	server := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           newClient(roots, os.Stdout).handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func main() {
	ca := flag.String("ca", "/trust/mitm.crt", "trusted MITM CA PEM bundle")
	port := flag.Int("port", 8088, "unauthenticated management HTTP port for an isolated test network")
	flag.Parse()
	if err := run(*ca, *port); err != nil {
		log.Error("serve stability client", "error", err)
		os.Exit(1)
	}
}
