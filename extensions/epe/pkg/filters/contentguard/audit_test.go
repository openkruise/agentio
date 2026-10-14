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
package contentguard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	auditlog "github.com/openkruise/agentio/extensions/epe/pkg/audit/log"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

func TestContentLoggingWithoutAuditConfiguration(t *testing.T) {
	for _, response := range []bool{false, true} {
		core, logs := observer.New(zap.InfoLevel)
		logger := auditlog.NewBufferedLogger(zapr.NewLogger(zap.New(core).Named("audit")), 8)
		regs, err := filter.Build(Definition())
		if err != nil {
			t.Fatal(err)
		}
		spec := `{"format":"json"}`
		if response {
			spec = `{"format":"json","response":{"enabled":true}}`
		}
		cfg, err := regs[0].Parse(json.RawMessage(spec))
		if err != nil {
			t.Fatal(err)
		}
		unit := filter.UnitID{Name: "guard"}
		g := regs[0].New(filter.ErasedRuleConfig{ID: unit, Cfg: cfg})
		st := &filter.Stream{
			RequestID: "id",
			Info:      filter.NewStreamInfo(),
			Request:   httpreq.HTTPRequest{Headers: map[string]string{"content-type": "application/json"}},
			Response:  httpreq.HTTPResponse{Headers: map[string]string{"content-type": "application/json"}},
		}
		st.Info.Matched = []filter.UnitRecord{{ID: unit}}
		ctx := context.Background()
		if _, err := g.OnRequestHeaders(ctx, st); err != nil {
			t.Fatal(err)
		}
		if _, err := g.OnRequestBody(
			ctx,
			st,
			filter.Body{Bytes: []byte(`{"prompt":"hello"}`), Complete: true},
		); err != nil {
			t.Fatal(err)
		}
		if _, err := g.OnResponseHeaders(ctx, st); err != nil {
			t.Fatal(err)
		}
		if response {
			if _, err := g.OnResponseBody(
				ctx,
				st,
				filter.Body{Bytes: []byte(`{"answer":"hi"}`), Complete: true},
			); err != nil {
				t.Fatal(err)
			}
		}
		auditlog.NewStreamLog(logger).Log(ctx, st, st.Info)
		drainCtx, cancel := context.WithCancel(ctx)
		cancel()
		if err := logger.Start(drainCtx); err != nil {
			t.Fatal(err)
		}
		if count := logs.FilterField(zap.String("type", "access")).Len(); count != 1 {
			t.Fatalf("access records=%d", count)
		}
		logs = logs.FilterField(zap.String("type", "content"))
		want := 1
		if response {
			want = 2
		}
		if logs.Len() != want {
			t.Fatalf("response=%v records=%d", response, logs.Len())
		}
		if got := logs.All()[0].ContextMap(); got["direction"] != "request" ||
			got["content"].(map[string]any)["prompt"] != "hello" {
			t.Fatalf("request=%v", got)
		}
		if response {
			if got := logs.All()[1].ContextMap(); got["direction"] != "response" ||
				got["content"].(map[string]any)["answer"] != "hi" {
				t.Fatalf("response=%v", got)
			}
		}
	}
}

func TestFilterDoesNotConfigureAuditDestinations(t *testing.T) {
	for _, spec := range []string{`{"audit":{"log":true}}`, `{"audit":{"webhook":{"url":"https://audit.example/"}}}`} {
		if _, err := parse(json.RawMessage(spec)); err == nil {
			t.Fatalf("accepted filter-local audit: %s", spec)
		}
	}
}
