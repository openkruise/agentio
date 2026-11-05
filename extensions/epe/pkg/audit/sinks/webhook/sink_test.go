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
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// counterValue reads one labelled child of a CounterVec via the official
// testutil helper so tests can assert pre/post deltas.
func counterValue(t *testing.T, v *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	return testutil.ToFloat64(v.WithLabelValues(labels...))
}

// recordingDispatcher captures events enqueued by the Sink.
type recordingDispatcher struct {
	mu     sync.Mutex
	events []Delivery
}

func (r *recordingDispatcher) Enqueue(evt Delivery) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, evt)
}

func (r *recordingDispatcher) snapshot() []Delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Delivery, len(r.events))
	copy(out, r.events)
	return out
}

// newTestSink wires the recording dispatcher directly into the Sink. The
// Sink calls Dispatcher.Enqueue synchronously, so assertions need no
// waiting.
func newTestSink(d Dispatcher) *Sink {
	return NewSink(d, logr.Discard())
}

func TestSink_Enqueue_NilSafe(t *testing.T) {
	tests := []struct {
		name string
		s    *Sink
	}{
		{name: "nil sink", s: nil},
		{name: "nil dispatcher", s: NewSink(nil, logr.Discard())},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic.
			tc.s.Enqueue(audit.Event{
				Audit: &audit.Audit{
					Webhook: &audit.Webhook{
						URL: template.Must(template.New("url").Parse("http://x")),
					},
				},
			})
		})
	}
}

// TestSink_Enqueue_DropsInvalid covers every event shape the Sink must drop
// without dispatching: missing config, bad URL schemes, and templates that
// fail to render.
func TestSink_Enqueue_DropsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		audit *audit.Audit
	}{
		{name: "nil audit", audit: nil},
		{name: "nil webhook", audit: &audit.Audit{Webhook: nil}},
		{
			name: "invalid url scheme",
			audit: &audit.Audit{
				Webhook: &audit.Webhook{
					URL: template.Must(template.New("url").Parse("ftp://example.com")),
				},
			},
		},
		{
			name: "bad header template",
			audit: &audit.Audit{
				Webhook: &audit.Webhook{
					URL:    template.Must(template.New("url").Parse("http://example.com")),
					Method: "POST",
					Headers: []audit.Header{
						{Name: "X-Bad", Value: template.Must(template.New("h").Parse("{{.NonExistent.Deep}}"))},
					},
				},
			},
		},
		{
			name: "bad body template",
			audit: &audit.Audit{
				Webhook: &audit.Webhook{
					URL:    template.Must(template.New("url").Parse("http://example.com")),
					Method: "POST",
					Body: audit.Body{
						HasBody:  true,
						TextTmpl: template.Must(template.New("body").Parse("{{.NonExistent.Deep}}")),
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingDispatcher{}
			s := newTestSink(rec)

			s.Enqueue(audit.Event{Audit: tc.audit})
			if got := len(rec.snapshot()); got != 0 {
				t.Errorf("expected 0 events, got %d", got)
			}
		})
	}
}

// A body that renders past the cap is dropped whole rather than sliced: a
// truncated JSON payload is unparseable at the receiver, and delivering one
// while counting it as a success is worse than delivering nothing.
func TestSink_Enqueue_OversizedBodyDrops(t *testing.T) {
	rec := &recordingDispatcher{}
	s := newTestSink(rec)

	before := counterValue(t, DroppedTotal, "body_too_large")
	s.Enqueue(audit.Event{
		Audit: &audit.Audit{Webhook: &audit.Webhook{
			URL: template.Must(template.New("url").Parse("http://hook.example.com/a")),
			Body: audit.Body{
				HasBody:  true,
				IsJSON:   true,
				JSONRoot: map[string]any{"payload": strings.Repeat("x", MaxRenderedBodyBytes+1000)},
			},
		}},
	})

	if got := len(rec.snapshot()); got != 0 {
		t.Errorf("oversized body must not be dispatched, got %d deliveries", got)
	}
	if got := counterValue(t, DroppedTotal, "body_too_large") - before; got != 1 {
		t.Errorf("DroppedTotal{reason=body_too_large} delta = %v, want 1", got)
	}
}

func TestSink_Enqueue_SuccessDispatches(t *testing.T) {
	rec := &recordingDispatcher{}
	s := newTestSink(rec)

	s.Enqueue(audit.Event{
		ProfileNN:  types.NamespacedName{Namespace: "ns", Name: "p1"},
		RuleName:   "r1",
		ActionName: "audit-action",
		Audit: &audit.Audit{
			Webhook: &audit.Webhook{
				URL:     template.Must(template.New("url").Parse("http://webhook.example.com/{{.Profile.Name}}")),
				Method:  "POST",
				Timeout: 3 * time.Second,
				Headers: []audit.Header{
					{Name: "X-Result", Value: template.Must(template.New("h").Parse("{{.Result}}"))},
				},
			},
		},
		Scope: &audit.Scope{
			Scope:  *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{Name: "p1"}, inputs.Rule{}, nil),
			Result: "blocked",
		},
	})

	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	evt := events[0]
	if evt.URL != "http://webhook.example.com/p1" {
		t.Errorf("URL: %q", evt.URL)
	}
	if evt.Method != "POST" {
		t.Errorf("Method: %q", evt.Method)
	}
	if evt.Timeout != 3*time.Second {
		t.Errorf("Timeout: %v", evt.Timeout)
	}
	if evt.ProfileNN != (types.NamespacedName{Namespace: "ns", Name: "p1"}) {
		t.Errorf("ProfileNN: %v", evt.ProfileNN)
	}
	if evt.RuleName != "r1" {
		t.Errorf("RuleName: %q", evt.RuleName)
	}
	if evt.EntryName != "audit-action" {
		t.Errorf("EntryName: %q", evt.EntryName)
	}
	if len(evt.Headers) != 1 || evt.Headers[0] != [2]string{"X-Result", "blocked"} {
		t.Errorf("Headers: %v", evt.Headers)
	}
}

func TestSink_Enqueue_WithTextBody(t *testing.T) {
	rec := &recordingDispatcher{}
	s := newTestSink(rec)

	s.Enqueue(audit.Event{
		Audit: &audit.Audit{
			Webhook: &audit.Webhook{
				URL:    template.Must(template.New("url").Parse("http://example.com")),
				Method: "POST",
				Body: audit.Body{
					HasBody:  true,
					TextTmpl: template.Must(template.New("body").Parse("result={{.Result}}")),
				},
			},
		},
		Scope: &audit.Scope{Result: "blocked"},
	})

	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if string(events[0].Body) != "result=blocked" {
		t.Errorf("Body: %q", events[0].Body)
	}
	if events[0].ContentType != contentTypeText {
		t.Errorf("ContentType: %q", events[0].ContentType)
	}
}
