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
package auditlog

import (
	"context"
	"testing"

	"github.com/go-logr/zapr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

func TestCapturedDirectionsAndAttribution(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := NewBufferedLogger(zapr.NewLogger(zap.New(core).Named("audit")), 8)
	first := filter.UnitID{Scope: "ns/p", Name: "first"}
	second := filter.UnitID{Scope: "ns/p", Name: "second"}
	info := filter.NewStreamInfo()
	st := &filter.Stream{
		RequestID: "id",
		Request:   httpreq.HTTPRequest{Method: "POST", Host: "llm.example", Path: "/v1/messages"},
	}
	NewStreamLog(logger).Log(context.Background(), st, info)
	info.Matched = []filter.UnitRecord{{ID: first}, {ID: second}}
	info.RecordContent(
		first,
		filter.ContentRecord{Status: "complete", Content: "prompt", BytesSeen: 6, CapturedBytes: 6},
	)
	info.RecordResponseContent(first, filter.ContentRecord{Status: "partial", Content: map[string]any{"model": "m"}})
	info.RecordContent(second, filter.ContentRecord{Status: "invalid_json"})
	NewStreamLog(logger).Log(context.Background(), st, info)
	info.RecordContent(first, filter.ContentRecord{Status: "incomplete"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := logger.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 5 {
		t.Fatalf("records=%d", logs.Len())
	}
	for _, entry := range logs.All()[:2] {
		if fields := entry.ContextMap(); fields["type"] != "access" || fields["content"] != nil {
			t.Fatalf("access record=%v", fields)
		}
	}
	for i, want := range []struct {
		unit      string
		direction string
		status    string
	}{
		{first.String(), "request", "complete"},
		{first.String(), "response", "partial"},
		{second.String(), "request", "invalid_json"},
	} {
		got := logs.All()[i+2]
		fields := got.ContextMap()
		if got.LoggerName != "audit" || fields["type"] != "content" || fields["requestID"] != "id" ||
			fields["unit"] != want.unit ||
			fields["direction"] != want.direction ||
			fields["status"] != want.status {
			t.Fatalf("record=%+v", got)
		}
	}
	fields := logs.All()[2].ContextMap()
	if fields["content"] != "prompt" || fields["method"] != "POST" || fields["bytesSeen"] != int64(6) {
		t.Fatalf("fields=%v", fields)
	}
}

// Access and content records compete for the same bounded queue.
func TestSharedQueueCountsDrops(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := NewBufferedLogger(zapr.NewLogger(zap.New(core)), 2)
	counter := AuditLogDroppedTotal
	before := testutil.ToFloat64(counter)
	logger.Submit(Entry{RequestID: "accepted-access"})
	logger.Submit(ContentEntry{RequestID: "accepted-content"})
	logger.Submit(ContentEntry{RequestID: "dropped-content"})
	logger.Submit(Entry{RequestID: "dropped-access"})
	if got := testutil.ToFloat64(counter) - before; got != 2 {
		t.Fatalf("drops=%v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := logger.Start(ctx); err != nil {
		t.Fatal(err)
	}
	records := logs.All()
	if len(records) != 2 {
		t.Fatalf("records=%d", len(records))
	}
	for i, kind := range []string{"access", "content"} {
		fields := records[i].ContextMap()
		if fields["type"] != kind || fields["requestID"] != "accepted-"+kind {
			t.Fatalf("record=%v", fields)
		}
	}
}
