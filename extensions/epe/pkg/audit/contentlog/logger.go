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
// Package contentlog writes captured content independently of access logs and webhook delivery.
package contentlog

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
)

// DefaultBufferSize bounds queued content records across streams.
const DefaultBufferSize = 4096

var droppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "epe_content_log_dropped_total",
	Help: "Total number of content log records dropped during queue admission or shutdown.",
}, []string{"reason"})

func init() { metrics.Registry.MustRegister(droppedTotal) }

type entry struct {
	requestID string
	unit      string
	direction string
	method    string
	host      string
	path      string
	record    filter.ContentRecord
}

// Logger emits one entry per captured direction and matched unit at stream end.
type Logger struct{ d *audit.Dispatcher[entry] }

var _ filter.StreamLogger = (*Logger)(nil)

// New constructs a bounded asynchronous logger; the caller must run Start.
func New(logger logr.Logger, bufferSize int) *Logger {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	return &Logger{d: audit.NewDispatcher("contentlog", bufferSize, 1,
		func(_ context.Context, e entry) {
			logger.Info("content captured", "requestID", e.requestID, "unit", e.unit,
				"direction", e.direction, "method", e.method, "host", e.host, "path", e.path,
				"status", e.record.Status, "bytesSeen", e.record.BytesSeen,
				"capturedBytes", e.record.CapturedBytes, "content", e.record.Content)
		},
		func(reason audit.DropReason) { droppedTotal.WithLabelValues(string(reason)).Inc() },
	)}
}

// Log queues immutable capture records without blocking the request path.
func (l *Logger) Log(_ context.Context, st *filter.Stream, info *filter.StreamInfo) {
	e := entry{
		requestID: st.RequestID,
		method:    st.Request.Method,
		host:      st.Request.Host,
		path:      st.Request.Path,
	}
	for _, unit := range info.Matched {
		e.unit = unit.ID.String()
		if record, ok := info.Content(unit.ID); ok {
			e.direction, e.record = "request", record
			l.d.Enqueue(e)
		}
		if record, ok := info.ResponseContent(unit.ID); ok {
			e.direction, e.record = "response", record
			l.d.Enqueue(e)
		}
	}
}

// Start drains queued entries and flushes accepted work on shutdown.
func (l *Logger) Start(ctx context.Context) error { return l.d.Start(ctx) }
