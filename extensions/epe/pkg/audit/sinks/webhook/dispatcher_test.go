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
package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// --- NewBuffered defaults ---

func TestNewBuffered_Sizing(t *testing.T) {
	tests := []struct {
		name        string
		buffer      int
		workers     int
		wantBuffer  int
		wantWorkers int
	}{
		{name: "zero values fall back to defaults", buffer: 0, workers: 0, wantBuffer: DefaultBufferSize, wantWorkers: DefaultWorkers},
		{name: "custom values kept", buffer: 100, workers: 4, wantBuffer: 100, wantWorkers: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := NewBuffered(logr.Discard(), tc.buffer, tc.workers, false)
			if d.d.Cap() != tc.wantBuffer {
				t.Errorf("buffer size: want %d, got %d", tc.wantBuffer, d.d.Cap())
			}
			if d.d.Workers() != tc.wantWorkers {
				t.Errorf("workers: want %d, got %d", tc.wantWorkers, d.d.Workers())
			}
			if d.client == nil {
				t.Error("client should not be nil")
			}
		})
	}
}

func TestNewBuffered_InsecureSkipVerify(t *testing.T) {
	tests := []struct {
		name               string
		insecureSkipVerify bool
		wantTLSConfig      bool
	}{
		{name: "insecure true sets TLS config", insecureSkipVerify: true, wantTLSConfig: true},
		{name: "insecure false leaves TLS config nil", insecureSkipVerify: false, wantTLSConfig: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := NewBuffered(logr.Discard(), 1, 1, tc.insecureSkipVerify)
			tr := d.client.Transport.(*http.Transport)
			if tc.wantTLSConfig && tr.TLSClientConfig == nil {
				t.Error("expected TLS config to be set")
			}
			if !tc.wantTLSConfig && tr.TLSClientConfig != nil {
				t.Error("expected TLS config to be nil")
			}
			if tc.wantTLSConfig && !tr.TLSClientConfig.InsecureSkipVerify {
				t.Error("expected InsecureSkipVerify to be true")
			}
		})
	}
}

func TestNewBuffered_CheckRedirectStops(t *testing.T) {
	d := NewBuffered(logr.Discard(), 1, 1, false)
	err := d.client.CheckRedirect(nil, nil)
	if err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect should return ErrUseLastResponse, got %v", err)
	}
}

// --- Enqueue ---

func TestBuffered_Enqueue_NilSafe(t *testing.T) {
	tests := []struct {
		name string
		d    *Buffered
	}{
		{name: "nil dispatcher", d: nil},
		{name: "zero value with nil channel", d: &Buffered{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic.
			tc.d.Enqueue(Delivery{URL: "http://example.com"})
		})
	}
}

// captureBuffered builds a Buffered whose internal dispatcher forwards every
// consumed Delivery to the returned channel instead of doing HTTP calls.
func captureBuffered(buffer int) (*Buffered, chan Delivery) {
	got := make(chan Delivery, buffer+1)
	d := &Buffered{logger: logr.Discard()}
	d.d = audit.NewDispatcher("test", buffer, 1,
		func(_ context.Context, evt Delivery) { got <- evt }, nil)
	return d, got
}

func TestBuffered_Enqueue_SendsToChannel(t *testing.T) {
	d, got := captureBuffered(1)
	evt := Delivery{URL: "http://example.com", Method: "POST"}
	d.Enqueue(evt)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Start(ctx) }()

	select {
	case g := <-got:
		if g.URL != evt.URL || g.Method != evt.Method {
			t.Errorf("event mismatch: %+v", g)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event on channel")
	}
}

func TestBuffered_Enqueue_BufferFullDrops(t *testing.T) {
	d := NewBuffered(logr.Discard(), 1, 1, false)
	before := counterValue(t, DroppedTotal, string(audit.DropBufferFull))

	// Fill the buffer (worker not started yet).
	d.Enqueue(Delivery{URL: "http://first"})
	// This should be dropped (non-blocking).
	d.Enqueue(Delivery{URL: "http://second"})

	if d.d.Len() != 1 {
		t.Errorf("buffer should have 1 event, got %d", d.d.Len())
	}
	if got := counterValue(t, DroppedTotal, string(audit.DropBufferFull)) - before; got != 1 {
		t.Errorf("DroppedTotal{reason=%q} delta = %v, want 1", audit.DropBufferFull, got)
	}
}

func TestBuffered_Enqueue_AfterStopReportsStopped(t *testing.T) {
	d := NewBuffered(logr.Discard(), 1, 1, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	before := counterValue(t, DroppedTotal, string(audit.DropStopped))
	d.Enqueue(Delivery{Method: "POST", URL: "http://late"})
	if got := counterValue(t, DroppedTotal, string(audit.DropStopped)) - before; got != 1 {
		t.Errorf("DroppedTotal{reason=%q} delta = %v, want 1", audit.DropStopped, got)
	}
}

func TestBuffered_ShutdownTimeoutReportsQueuedDeliveries(t *testing.T) {
	requestEntered := make(chan struct{})
	d := NewBuffered(logr.Discard(), 2, 1, false)
	d.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(requestEntered)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()

	// Hold the only worker in an HTTP call that cooperates with cancellation,
	// then place two more deliveries in the bounded queue. They cannot start
	// before the dispatcher's shutdown deadline expires.
	d.Enqueue(Delivery{Method: "POST", URL: "http://in-flight", Timeout: 30 * time.Second})
	select {
	case <-requestEntered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("worker did not enter the in-flight HTTP request")
	}
	d.Enqueue(Delivery{Method: "POST", URL: "http://queued-1", Timeout: 30 * time.Second})
	d.Enqueue(Delivery{Method: "POST", URL: "http://queued-2", Timeout: 30 * time.Second})
	if got := d.d.Len(); got != 2 {
		cancel()
		t.Fatalf("queued deliveries = %d, want 2", got)
	}

	before := counterValue(t, DroppedTotal, string(audit.DropShutdownTimeout))
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after bounded shutdown")
	}

	if got := counterValue(t, DroppedTotal, string(audit.DropShutdownTimeout)) - before; got != 2 {
		t.Errorf("DroppedTotal{reason=%q} delta = %v, want 2", audit.DropShutdownTimeout, got)
	}
}

// --- dispatchOne ---

func TestBuffered_DispatchOne_EmptyURLDrops(t *testing.T) {
	d := &Buffered{
		client: &http.Client{},
		logger: logr.Discard(),
	}
	// Must not panic or make any HTTP call.
	d.dispatchOne(context.Background(), Delivery{URL: ""})
}

func TestBuffered_DispatchOne_RequestShape(t *testing.T) {
	tests := []struct {
		name            string
		delivery        Delivery
		wantHeaders     map[string]string
		wantContentType string
		wantBody        string
	}{
		{
			name: "success with header, body and content type",
			delivery: Delivery{
				ProfileNN:   types.NamespacedName{Namespace: "ns", Name: "p1"},
				RuleName:    "r1",
				EntryName:   "e1",
				Method:      "POST",
				Headers:     [][2]string{{"X-Custom", "val1"}},
				Body:        []byte(`{"key":"value"}`),
				ContentType: "application/json; charset=utf-8",
			},
			wantHeaders:     map[string]string{"X-Custom": "val1"},
			wantContentType: "application/json; charset=utf-8",
			wantBody:        `{"key":"value"}`,
		},
		{
			name: "nil body sets no content type",
			delivery: Delivery{
				Method: "GET",
				Body:   nil,
			},
			wantContentType: "",
			wantBody:        "",
		},
		{
			name: "multiple headers all forwarded",
			delivery: Delivery{
				Method: "POST",
				Headers: [][2]string{
					{"X-A", "a1"},
					{"X-B", "b1"},
					{"Authorization", "Bearer tok"},
				},
				Body: []byte("test"),
			},
			wantHeaders: map[string]string{
				"X-A":           "a1",
				"X-B":           "b1",
				"Authorization": "Bearer tok",
			},
			wantBody: "test",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var called atomic.Int32
			var receivedBody string
			var receivedHeaders http.Header

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Add(1)
				receivedHeaders = r.Header.Clone()
				body, _ := io.ReadAll(r.Body)
				receivedBody = string(body)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			d := &Buffered{
				client: srv.Client(),
				logger: logr.Discard(),
			}

			delivery := tc.delivery
			delivery.URL = srv.URL
			d.dispatchOne(context.Background(), delivery)

			if called.Load() != 1 {
				t.Fatalf("expected 1 HTTP call, got %d", called.Load())
			}
			for name, want := range tc.wantHeaders {
				if got := receivedHeaders.Get(name); got != want {
					t.Errorf("header %s: want %q, got %q", name, want, got)
				}
			}
			if got := receivedHeaders.Get("Content-Type"); got != tc.wantContentType {
				t.Errorf("content type: want %q, got %q", tc.wantContentType, got)
			}
			if receivedBody != tc.wantBody {
				t.Errorf("body: want %q, got %q", tc.wantBody, receivedBody)
			}
		})
	}
}

func TestBuffered_DispatchOne_HTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{name: "400 bad request", statusCode: 400},
		{name: "500 internal server error", statusCode: 500},
		{name: "503 service unavailable", statusCode: 503},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			d := &Buffered{
				client: srv.Client(),
				logger: logr.Discard(),
			}
			// Should not panic; http_error metric incremented.
			d.dispatchOne(context.Background(), Delivery{
				Method: "POST",
				URL:    srv.URL,
				Body:   []byte("test"),
			})
		})
	}
}

func TestBuffered_DispatchOne_CustomTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := &Buffered{
		client: srv.Client(),
		logger: logr.Discard(),
	}

	// Use a very short event timeout.
	d.dispatchOne(context.Background(), Delivery{
		Method:  "POST",
		URL:     srv.URL,
		Body:    []byte("test"),
		Timeout: 1 * time.Millisecond,
	})
	// timeout metric incremented; just verify no panic.
}

func TestBuffered_DispatchOne_UsesDefaultTimeout(t *testing.T) {
	var requestReceived atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestReceived.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := &Buffered{
		client: srv.Client(),
		logger: logr.Discard(),
	}

	// Event has zero Timeout → defaultTimeout should be used.
	d.dispatchOne(context.Background(), Delivery{
		Method: "POST",
		URL:    srv.URL,
		Body:   []byte("test"),
	})
	if !requestReceived.Load() {
		t.Error("request should have been received")
	}
}

// --- Start lifecycle ---

func TestBuffered_Start_CancelsOnContextDone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewBuffered(logr.Discard(), 10, 2, false)
	// Swap client to use test server.
	d.client = srv.Client()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- d.Start(ctx)
	}()

	// Enqueue an event that should be processed.
	d.Enqueue(Delivery{Method: "POST", URL: srv.URL, Body: []byte("ok")})

	// Deterministic barrier: wait until the worker finished the delivery.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer drainCancel()
	if err := d.Drain(drainCtx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start should return nil, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// TestBuffered_EnqueueDuringShutdownDoesNotPanic pins the shutdown contract
// the production wiring actually depends on: runnable.Group hands one ctx to
// every member at once, so the dispatcher stops while the ext-proc server is
// still in GracefulStop draining in-flight streams. Those streams finish under
// context.WithoutCancel and enqueue their audit events afterwards, so Enqueue
// must stay safe for an unbounded period after Start has returned. A dispatcher
// that closes its queue on stop turns that ordering into a process-killing
// "send on closed channel" panic.
func TestBuffered_EnqueueDuringShutdownDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewBuffered(logr.Discard(), 64, 4, false)
	d.client = srv.Client()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start should return nil, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	// Start has returned; the dispatcher is stopped. Streams held open by
	// GracefulStop reach finishStream only now, so these enqueues land
	// strictly after shutdown — the exact ordering that used to panic.
	const producers = 32
	var wg sync.WaitGroup
	panics := make(chan any, producers)
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics <- r
				}
			}()
			for j := 0; j < 16; j++ {
				d.Enqueue(Delivery{Method: "POST", URL: srv.URL, Body: []byte("late")})
			}
		}()
	}
	wg.Wait()
	close(panics)

	if n := len(panics); n > 0 {
		t.Fatalf("%d of %d producers panicked enqueuing after shutdown; first: %v",
			n, producers, <-panics)
	}
}

// --- Nop dispatcher ---

func TestNop_EnqueueDoesNotPanic(t *testing.T) {
	d := Nop()
	d.Enqueue(Delivery{URL: "http://example.com"})
	d.Enqueue(Delivery{})
}
