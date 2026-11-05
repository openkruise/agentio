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
package audit

import (
	"sync"
	"testing"
)

type recordingSink struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingSink) Enqueue(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingSink) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

func TestMetricsRegistered(t *testing.T) {
	if EvalDroppedTotal == nil {
		t.Fatal("EvalDroppedTotal nil")
	}
}

func TestNopSink_EnqueueDoesNotPanic(t *testing.T) {
	s := NopSink()
	// Must not panic even with a zero-value event.
	s.Enqueue(Event{})
	s.Enqueue(Event{Audit: &Audit{Name: "x"}})
}

// TestRouter_Enqueue_Drops covers events the router must drop silently
// (no panic, no delivery to any registered sink).
func TestRouter_Enqueue_Drops(t *testing.T) {
	tests := []struct {
		name  string
		audit *Audit
	}{
		{name: "nil audit", audit: nil},
		{name: "unknown kind", audit: &Audit{Kind: "unknown_kind"}},
		{name: "unregistered kind kafka", audit: &Audit{Kind: "kafka"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter()
			sink := &recordingSink{}
			r.Register(SinkKindWebhook, sink)

			r.Enqueue(Event{Audit: tc.audit})
			if got := len(sink.snapshot()); got != 0 {
				t.Errorf("expected 0 events, got %d", got)
			}
		})
	}
}

func TestRouter_Enqueue_RoutesToCorrectSink(t *testing.T) {
	tests := []struct {
		name        string
		kind        string
		enqueues    int
		wantWebhook int
		wantOther   int
	}{
		{name: "webhook routes to webhook sink", kind: "webhook", enqueues: 1, wantWebhook: 1, wantOther: 0},
		{name: "custom routes to custom sink", kind: "custom", enqueues: 1, wantWebhook: 0, wantOther: 1},
		{name: "kind constant delivers every event", kind: SinkKindWebhook, enqueues: 2, wantWebhook: 2, wantOther: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter()
			webhookSink := &recordingSink{}
			otherSink := &recordingSink{}
			r.Register(SinkKindWebhook, webhookSink)
			r.Register("custom", otherSink)

			for i := 0; i < tc.enqueues; i++ {
				r.Enqueue(Event{Audit: &Audit{Kind: tc.kind}})
			}

			if got := len(webhookSink.snapshot()); got != tc.wantWebhook {
				t.Errorf("webhook sink: want %d, got %d", tc.wantWebhook, got)
			}
			if got := len(otherSink.snapshot()); got != tc.wantOther {
				t.Errorf("other sink: want %d, got %d", tc.wantOther, got)
			}
		})
	}
}

func TestRouter_Register_OverwritesPrevious(t *testing.T) {
	r := NewRouter()
	first := &recordingSink{}
	second := &recordingSink{}
	r.Register("webhook", first)
	r.Register("webhook", second)

	r.Enqueue(Event{Audit: &Audit{Kind: "webhook"}})

	if got := len(first.snapshot()); got != 0 {
		t.Errorf("first sink should not receive events after overwrite, got %d", got)
	}
	if got := len(second.snapshot()); got != 1 {
		t.Errorf("second sink should receive 1 event, got %d", got)
	}
}

func TestRouter_Enqueue_EmptyRouterIsSafe(t *testing.T) {
	r := NewRouter()
	// No sinks registered; must drop silently.
	r.Enqueue(Event{Audit: &Audit{Kind: "webhook"}})
}

func TestRouter_ConcurrentEnqueue(t *testing.T) {
	r := NewRouter()
	sink := &recordingSink{}
	r.Register("webhook", sink)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			r.Enqueue(Event{Audit: &Audit{Kind: "webhook"}})
		}()
	}
	wg.Wait()

	if got := len(sink.snapshot()); got != goroutines {
		t.Errorf("expected %d events from concurrent enqueue, got %d", goroutines, got)
	}
}
