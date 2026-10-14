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
// Package auditlog emits separate access and content records through a shared
// bounded, non-blocking INFO-level logging queue.
package auditlog

import (
	"context"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
)

// DefaultBufferSize is the channel capacity used when the caller does not
// configure --audit-log-buffer-size.
const DefaultBufferSize = 4096

// Entry is the per-request audit payload assembled by the request handler.
//
// Outcome takes one of: "passthrough", "mutated", "blocked", "bypassed",
// "error", and is derived from what EPE actually sent Envoy — see
// extproc/outcome.go. An explicit bypass is visible only in Actions, never in
// Outcome.
//
// Actions and Skipped share the element format
// "<filter>:<kind>:<ns>/<profile>/<rule>#<ordinal>", and the kind decides which
// field an element lands in:
//
//	Actions — the filter acted:  block (it denied), bypass (it exempted),
//	          mutate (it changed the message), error-closed (it broke and the
//	          rule's FailClosed policy denied on its behalf).
//	Skipped — the rule went unenforced:  error-open (the filter broke and the
//	          rule's FailOpen policy admitted the request), need-body (the filter
//	          asked for a body that never arrived, so its verdict never ran).
//
// A filter that ran and simply allowed the request records nothing in either.
// Units counts matched policy units (rules), not profiles.
type Entry struct {
	RequestID string
	Pod       types.NamespacedName
	Method    string
	Host      string
	Path      string
	Units     int
	Outcome   string
	Actions   []string
	Skipped   []string
	Error     string
}

// Record is an access or content log entry. Submitted records and their nested
// values are immutable until emission completes.
type Record interface {
	emit(logr.Logger)
}

// Logger accepts records at stream finalization. Implementations MUST be safe
// for concurrent use and MUST NOT block the caller.
type Logger interface {
	Submit(entry Record)
}

// Nop returns a Logger whose Submit is a no-op. Used as a default when the
// handler is constructed without an audit logger (e.g. unit tests) so the
// dispatch path can call Submit unconditionally.
func Nop() Logger { return nopLogger{} }

type nopLogger struct{}

func (nopLogger) Submit(Record) {}

// BufferedLogger is the default Logger implementation. Submit performs a
// non-blocking channel send; a single worker goroutine started by Start
// consumes the channel and writes one logr Info record per entry.
//
// BufferedLogger satisfies the runnable.Runnable contract so it can be
// wired into the runnable group alongside the ext-proc server.
type BufferedLogger struct {
	d *audit.Dispatcher[Record]
}

// NewBufferedLogger constructs a BufferedLogger backed by the given
// logr.Logger and channel capacity. bufferSize <= 0 falls back to
// DefaultBufferSize.
func NewBufferedLogger(logger logr.Logger, bufferSize int) *BufferedLogger {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	l := &BufferedLogger{}
	// The dispatcher flushes buffered entries on ctx cancellation without
	// closing the channel, so a late Submit remains safe.
	l.d = audit.NewDispatcher("auditlog", bufferSize, 1,
		func(_ context.Context, e Record) { e.emit(logger) },
		func(audit.DropReason) { AuditLogDroppedTotal.Inc() })
	return l
}

// Submit enqueues entry for asynchronous emission. The call is
// non-blocking: when the buffer is full the entry is dropped and
// AuditLogDroppedTotal is incremented. A nil receiver is a no-op so
// uninitialised Loggers do not panic from inside the request path.
func (l *BufferedLogger) Submit(entry Record) {
	if l == nil {
		return
	}
	l.d.Enqueue(entry)
}

// Start drains the entry channel until ctx is cancelled, then flushes any
// remaining entries and returns. It implements runnable.Runnable.
func (l *BufferedLogger) Start(ctx context.Context) error {
	return l.d.Start(ctx)
}

// emit converts an Entry into structured key-value pairs and writes one
// logr Info record. Error is only emitted when non-empty to keep the
// happy-path line short.
func (e Entry) emit(logger logr.Logger) {
	kvs := []any{
		"type", "access",
		"requestID", e.RequestID,
		"pod", e.Pod.String(),
		"method", e.Method,
		"host", e.Host,
		"path", e.Path,
		"units", e.Units,
		"outcome", e.Outcome,
		"actions", e.Actions,
		"skipped", e.Skipped,
	}
	if e.Error != "" {
		kvs = append(kvs, "error", e.Error)
	}
	logger.Info("egress request handled", kvs...)
}
