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

// Test-only model of ztunnel SandboxManager: local waits never close ADS.
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/bench/xds/fakeclient"
	"github.com/openkruise/agentio/pkg/model"
)

type prepareCommand struct {
	Name       string `json:"name"`
	Retry      bool   `json:"retry"`
	ClearCache bool   `json:"clear_cache"`
}
type prepareClient struct {
	client        *fakeclient.Client
	workload      string
	sandbox       string
	workloadReady bool
	bound         bool
	subscribed    bool
	active        bool
	retry         bool
	prepared      bool
	started       time.Time
	deadline      time.Time
	retryAt       time.Time
	finished      time.Time
	attempts      int
	timeouts      int
}

type prepareController struct {
	mu         sync.Mutex
	clients    map[int]*prepareClient
	command    prepareCommand
	generation int
	sendErrors int
	optimized  bool
	watchStats *watchStats
}

func newPrepareController() *prepareController {
	return &prepareController{clients: map[int]*prepareClient{}}
}
func (p *prepareController) attach(i int, c *fakeclient.Client, workload, sandbox string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.clients[i]
	if s == nil {
		s = &prepareClient{workload: workload, sandbox: sandbox}
		p.clients[i] = s
	}
	s.client = c
}
func (p *prepareController) detach(i int, c *fakeclient.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.clients[i]; s.client == c {
		s.client = nil
	}
}
func (p *prepareController) subscribe(i int) error {
	p.mu.Lock()
	s := p.clients[i]
	c, name, subscribed := s.client, s.sandbox, s.subscribed
	p.mu.Unlock()
	if subscribed {
		return c.Subscribe(model.SandboxType, name)
	}
	return c.Send(
		&discovery.DeltaDiscoveryRequest{
			TypeUrl:                  model.SandboxType,
			ResourceNamesSubscribe:   []string{"*"},
			ResourceNamesUnsubscribe: []string{"*"},
		},
	)
}
func (p *prepareController) ready(s *prepareClient, now time.Time) {
	if s.active && s.bound && s.workloadReady {
		s.prepared = true
		s.active = false
		s.finished = now
		s.retryAt = time.Time{}
	}
}
func (p *prepareController) begin(s *prepareClient, now time.Time) *fakeclient.Client {
	s.active = true
	s.attempts++
	s.deadline = now.Add(30 * time.Second)
	s.retryAt = time.Time{}
	p.ready(s, now)
	if s.prepared {
		return nil
	}
	s.subscribed = true
	return s.client
}
func (p *prepareController) send(c *fakeclient.Client, name string) {
	if c == nil {
		return
	}
	go func() {
		if err := c.Subscribe(model.SandboxType, name); err != nil {
			p.mu.Lock()
			p.sendErrors++
			p.mu.Unlock()
		}
	}()
}
func (p *prepareController) start(command prepareCommand, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.clients {
		if s.active || !s.retryAt.IsZero() {
			return fmt.Errorf("previous preparation still pending")
		}
	}
	p.generation++
	p.command = command
	for _, s := range p.clients {
		if command.ClearCache {
			s.bound = false
			s.workloadReady = false
		}
		s.prepared = false
		s.retry = command.Retry
		s.started = now
		s.finished = time.Time{}
		s.attempts = 0
		s.timeouts = 0
		c := p.begin(s, now)
		p.send(c, s.sandbox)
		if command.ClearCache && s.client != nil {
			c := s.client
			go func() {
				if err := c.Subscribe(model.AddressType, "*"); err != nil {
					p.mu.Lock()
					p.sendErrors++
					p.mu.Unlock()
				}
			}()
		}
	}
	return nil
}
func (p *prepareController) tick(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.clients {
		if s.active && !now.Before(s.deadline) {
			s.active = false
			s.timeouts++
			if s.retry {
				delay := 5 * time.Second
				if p.optimized {
					delay = time.Duration(float64(delay) * (0.8 + 0.4*rand.Float64()))
				}
				s.retryAt = now.Add(delay)
			}
		}
		if !s.retryAt.IsZero() && !now.Before(s.retryAt) {
			p.send(p.begin(s, now), s.sandbox)
		}
	}
}
func (p *prepareController) accept(i int, r *discovery.DeltaDiscoveryResponse) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.clients[i]
	switch r.TypeUrl {
	case model.SandboxType:
		for _, name := range r.RemovedResources {
			if name == s.sandbox {
				s.bound = false
			}
		}
		for _, resource := range r.Resources {
			if resource.Name == s.sandbox {
				v := &sandboxv1.Sandbox{}
				if err := resource.Resource.UnmarshalTo(v); err != nil {
					return err
				}
				if v.Uid != s.sandbox {
					return fmt.Errorf("unexpected sandbox UID %q", v.Uid)
				}
				s.bound = v.GetAttester().GetWorkloadUid() == s.workload
			}
		}
	case model.AddressType:
		for _, name := range r.RemovedResources {
			if name == s.workload {
				s.workloadReady = false
			}
		}
		for _, resource := range r.Resources {
			v := &workloadv1.Address{}
			if err := resource.Resource.UnmarshalTo(v); err != nil {
				return err
			}
			if v.GetWorkload().GetUid() == s.workload {
				s.workloadReady = true
			}
		}
	}
	p.ready(s, time.Now())
	return nil
}
func (p *prepareController) snapshot() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	connected, bound, workloads, prepared, pending, attempts, timeouts, failed := 0, 0, 0, 0, 0, 0, 0, 0
	latencies := []float64{}
	for _, s := range p.clients {
		if s.client != nil {
			connected++
		}
		if s.bound {
			bound++
		}
		if s.workloadReady {
			workloads++
		}
		if s.prepared {
			prepared++
			latencies = append(latencies, s.finished.Sub(s.started).Seconds())
		}
		if s.active || !s.retryAt.IsZero() {
			pending++
		}
		attempts += s.attempts
		timeouts += s.timeouts
		if !s.started.IsZero() && !s.prepared && !s.active && s.retryAt.IsZero() {
			failed++
		}
	}
	sort.Float64s(latencies)
	quantile := func(q float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		return latencies[int(float64(len(latencies)-1)*q)]
	}
	return map[string]any{
		"generation":          p.generation,
		"name":                p.command.Name,
		"clients":             len(p.clients),
		"connected":           connected,
		"bound":               bound,
		"workloads":           workloads,
		"prepared":            prepared,
		"pending":             pending,
		"failed":              failed,
		"attempts":            attempts,
		"timeouts":            timeouts,
		"send_errors":         p.sendErrors,
		"latency_p50_seconds": quantile(.5),
		"latency_p99_seconds": quantile(.99),
		"latency_max_seconds": quantile(1),
	}
}
func (p *prepareController) serve(ctx context.Context) (func(), error) {
	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/retry", func(w http.ResponseWriter, r *http.Request) {
		var command struct {
			Optimized bool `json:"optimized"`
		}
		if err := json.NewDecoder(r.Body).Decode(&command); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		p.mu.Lock()
		p.optimized = command.Optimized
		p.mu.Unlock()
		if err := json.NewEncoder(w).Encode(command); err != nil {
			log.Print(err)
		}
	})
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		s := p.watchStats
		s.mu.Lock()
		defer s.mu.Unlock()
		ready := 0
		for _, types := range s.Resources {
			if len(types) == 3 {
				ready++
			}
		}
		if err := json.NewEncoder(w).
			Encode(map[string]any{"connected": s.Connected, "ready": ready, "responses": s.Responses, "reconnects": s.Reconnects, "last_error": s.LastError}); err != nil {
			log.Print(err)
		}
	})
	mux.HandleFunc("/details", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		rows := make(map[int]any, len(p.clients))
		for id, s := range p.clients {
			rows[id] = map[string]any{
				"prepared": s.prepared,
				"seconds":  s.finished.Sub(s.started).Seconds(),
				"attempts": s.attempts,
				"timeouts": s.timeouts,
			}
		}
		if err := json.NewEncoder(w).Encode(rows); err != nil {
			panic(err)
		}
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(p.snapshot()); err != nil {
			panic(err)
		}
	})
	mux.HandleFunc("/prepare", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		var command prepareCommand
		if err := json.NewDecoder(r.Body).Decode(&command); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := p.start(command, time.Now()); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		if err := json.NewEncoder(w).Encode(p.snapshot()); err != nil {
			panic(err)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	child, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-child.Done():
				return
			case now := <-t.C:
				p.tick(now)
			}
		}
	}()
	return func() {
		cancel()
		if err := server.Close(); err != nil {
			panic(err)
		}
	}, nil
}
