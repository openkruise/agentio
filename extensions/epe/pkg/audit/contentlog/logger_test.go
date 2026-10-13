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
package contentlog

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
	logger := New(zapr.NewLogger(zap.New(core).Named("contentguard")), 8)
	first := filter.UnitID{Scope: "ns/p", Name: "first"}
	second := filter.UnitID{Scope: "ns/p", Name: "second"}
	info := filter.NewStreamInfo()
	st := &filter.Stream{
		RequestID: "id",
		Request:   httpreq.HTTPRequest{Method: "POST", Host: "llm.example", Path: "/v1/messages"},
	}
	logger.Log(context.Background(), st, info)
	info.Matched = []filter.UnitRecord{{ID: first}, {ID: second}}
	info.RecordContent(
		first,
		filter.ContentRecord{Status: "complete", Content: "prompt", BytesSeen: 6, CapturedBytes: 6},
	)
	info.RecordResponseContent(first, filter.ContentRecord{Status: "partial", Content: map[string]any{"model": "m"}})
	info.RecordContent(second, filter.ContentRecord{Status: "invalid_json"})
	logger.Log(context.Background(), st, info)
	info.RecordContent(first, filter.ContentRecord{Status: "incomplete"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := logger.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 3 {
		t.Fatalf("records=%d", logs.Len())
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
		got := logs.All()[i]
		fields := got.ContextMap()
		if got.LoggerName != "contentguard" || fields["requestID"] != "id" || fields["unit"] != want.unit ||
			fields["direction"] != want.direction ||
			fields["status"] != want.status {
			t.Fatalf("record=%+v", got)
		}
	}
	fields := logs.All()[0].ContextMap()
	if fields["content"] != "prompt" || fields["method"] != "POST" || fields["bytesSeen"] != int64(6) {
		t.Fatalf("fields=%v", fields)
	}
}

func TestFullQueueCountsDrops(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	logger := New(zapr.NewLogger(zap.New(core)), 1)
	info := filter.NewStreamInfo()
	unit := filter.UnitID{Name: "guard"}
	info.Matched = []filter.UnitRecord{{ID: unit}}
	info.RecordContent(unit, filter.ContentRecord{Status: "complete"})
	counter := droppedTotal.WithLabelValues("buffer_full")
	before := testutil.ToFloat64(counter)
	logger.Log(context.Background(), &filter.Stream{}, info)
	logger.Log(context.Background(), &filter.Stream{}, info)
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Fatalf("drops=%v", got)
	}
}
