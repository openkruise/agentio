// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package envoy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleProxy struct {
	started chan struct{}
	drained atomic.Bool
	reaped  atomic.Bool
}

func (p *lifecycleProxy) Run(abort <-chan error) error {
	close(p.started)
	return <-abort
}
func (p *lifecycleProxy) Drain(bool) error {
	p.drained.Store(true)
	return nil
}
func (p *lifecycleProxy) Cleanup()                { p.reaped.Store(true) }
func (*lifecycleProxy) UpdateConfig([]byte) error { return nil }

func TestShutdownWaitsForChild(t *testing.T) {
	for _, skip := range []bool{false, true} {
		for _, activeCheck := range []bool{false, true} {
			p := &lifecycleProxy{started: make(chan struct{})}
			a := NewAgent(p, 20*time.Millisecond, time.Hour, "127.0.0.1", 0, 15021, 15090, activeCheck)
			if skip {
				a.DisableDraining()
			}
			ctx, cancel := context.WithCancel(t.Context())
			finished := make(chan struct{})
			go func() {
				a.Run(ctx)
				close(finished)
			}()
			<-p.started
			cancel()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("shutdown exceeded termination deadline")
			}
			if !p.reaped.Load() {
				t.Fatal("agent exited before child cleanup")
			}
			if p.drained.Load() == skip {
				t.Fatalf("drain=%v skip=%v", p.drained.Load(), skip)
			}
		}
	}
}

func TestReadinessRequiresInitialNativeXDSAndLiveWorkers(t *testing.T) {
	var initialized atomic.Bool
	var live atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("filter") == updateStatsRegex {
			if initialized.Load() {
				if _, err := w.Write(
					[]byte("cluster_manager.cds.update_success: 1\nlistener_manager.lds.update_success: 1\n"),
				); err != nil {
					t.Errorf("write admin fixture: %v", err)
				}
			}
		} else if live.Load() {
			if _, err := w.Write([]byte("server.state: 0\nlistener_manager.workers_started: 1\n")); err != nil {
				t.Errorf("write admin fixture: %v", err)
			}
		} else {
			if _, err := w.Write([]byte("server.state: 3\nlistener_manager.workers_started: 0\n")); err != nil {
				t.Errorf("write admin fixture: %v", err)
			}
		}
	}))
	defer server.Close()
	address := server.Listener.Addr().(*net.TCPAddr)
	port := address.Port
	p := &Probe{LocalHostAddr: address.IP.String(), AdminPort: uint16(port), Context: t.Context()}
	if p.Check() == nil {
		t.Fatal("ready without xDS")
	}
	initialized.Store(true)
	if p.Check() == nil {
		t.Fatal("ready while initializing")
	}
	live.Store(true)
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestDrainCountsForwardingAndExcludesProbes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(
			[]byte(
				"listener.agentio_status.downstream_cx_active: 10\nlistener.agentio_metrics.downstream_cx_active: 20\nlistener.admin.downstream_cx_active: 1\nlistener.0.0.0.0_15008.downstream_cx_active: 2\nlistener.internal_dispatch.downstream_cx_active: 3\nlistener.[::]_8080.downstream_cx_active: 4\nlistener.internal_dispatch.worker_0.downstream_cx_active: 3\nhttp.internal_dispatch.downstream_cx_active: 3\n",
			),
		); err != nil {
			t.Errorf("write admin fixture: %v", err)
		}
	}))
	defer server.Close()
	address := server.Listener.Addr().(*net.TCPAddr)
	port := address.Port
	agent := NewAgent(nil, time.Second, 0, address.IP.String(), port, 15021, 15090, true)
	if active, err := agent.activeProxyConnections(); err != nil || active != 9 {
		t.Fatalf("connections=%d err=%v", active, err)
	}
}

func TestSlowAdminCannotExtendTerminationDeadline(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }),
	)
	defer server.Close()
	address := server.Listener.Addr().(*net.TCPAddr)
	port := address.Port
	old := activeConnectionCheckDelay
	activeConnectionCheckDelay = time.Millisecond
	defer func() { activeConnectionCheckDelay = old }()
	p := &lifecycleProxy{started: make(chan struct{})}
	a := NewAgent(p, 30*time.Millisecond, 0, address.IP.String(), port, 15021, 15090, true)
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan struct{})
	go func() {
		a.Run(ctx)
		close(finished)
	}()
	<-p.started
	cancel()
	select {
	case <-finished:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("admin query exceeded drain deadline")
	}
}
