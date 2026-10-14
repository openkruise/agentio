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
package securityprofile

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/audit/sinks/webhook"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/contentguard"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

type contentAuditSink struct{ events []audit.Event }

func (s *contentAuditSink) Enqueue(e audit.Event) { s.events = append(s.events, e) }

func TestContentGuardToAuditSink(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		name := "json"
		if streamed {
			name = "sse"
		}
		t.Run(name, func(t *testing.T) { testContentGuardToAuditSink(t, streamed) })
	}
}

func testContentGuardToAuditSink(t *testing.T, streamed bool) {
	t.Helper()
	regs, err := filter.Build(contentguard.Definition())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := regs[0].Parse(
		json.RawMessage(
			`{"response":{"enabled":true,"format":"openai-chat-completions","transform":"{'answer': content.outputMessages[0].content[0].text, 'method': request.method}"}}`,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	when, err := eval.CompileBool(
		`content.status == "complete" && content.content.model == "qwen" && content.response.status == "complete" && content.response.content.answer == "hello"`,
	)
	if err != nil {
		t.Fatal(err)
	}
	bodyTemplate, err := eval.CompileTemplate("content", `{{ json .Content }}`)
	if err != nil {
		t.Fatal(err)
	}
	entry := &audit.Audit{
		Name:    "record",
		Kind:    audit.SinkKindWebhook,
		When:    when,
		Webhook: &audit.Webhook{Body: audit.Body{HasBody: true, TextTmpl: bodyTemplate}},
	}
	u := unit{
		Unit: engine.Unit{
			ID:   filter.UnitID{Scope: "ns/p", Name: "r"},
			Cfgs: []any{cfg},
			Scope: inputs.NewScope(
				inputs.RequestFrom(httpreq.HTTPRequest{Method: "POST"}),
				inputs.Pod{},
				inputs.Profile{},
				inputs.Rule{},
				nil,
			),
		},
		Profile:    &Profile{Meta: Meta{Name: "p", Namespace: "ns"}},
		Rule:       &Rule{Name: "r", Audits: []*audit.Audit{entry}},
		HasAudits:  true,
		MatchIndex: -1,
	}
	st := &filter.Stream{
		Info:    filter.NewStreamInfo(),
		Request: httpreq.HTTPRequest{Headers: map[string]string{"content-type": "application/json"}},
	}
	e := engine.NewEngine(regs, 0)
	prior, err := e.EvalRequestHeaders(context.Background(), st, []engine.Unit{u.Unit}, engine.WithRequestStreaming())
	if err != nil {
		t.Fatal(err)
	}
	for i, chunk := range []string{`{"model":"qwen",`, `"messages":[]}`} {
		if _, err := e.EvalRequestBodyChunk(
			context.Background(),
			st,
			prior,
			filter.Body{Bytes: []byte(chunk), Complete: i == 1},
		); err != nil {
			t.Fatal(err)
		}
	}
	media := "application/json"
	chunks := []string{`{"model":"qwen","choices":[{"index":0,"message":`, `{"role":"assistant","content":"hello"}}]}`}
	if streamed {
		media = "text/event-stream"
		chunks = []string{
			"data: {\"model\":\"qwen\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
			"data: {\"model\":\"qwen\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
		}
	}
	st.Response = httpreq.HTTPResponse{Headers: map[string]string{"content-type": media}}
	resp, err := e.EvalResponseHeaders(
		context.Background(),
		st,
		[]engine.Unit{u.Unit},
		prior.ResponseScope,
		engine.WithResponseStreaming(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for i, chunk := range chunks {
		if _, err := e.EvalResponseBodyChunk(
			context.Background(),
			st,
			resp,
			filter.Body{Bytes: []byte(chunk), Complete: i == 1},
		); err != nil {
			t.Fatal(err)
		}
	}
	sink := &contentAuditSink{}
	newStreamLogger(sink, []unit{u}).Log(context.Background(), st, st.Info)
	if len(sink.events) != 1 {
		t.Fatalf("events: %d", len(sink.events))
	}
	got, _, err := webhook.RenderBody(entry, sink.events[0].Scope)
	if err != nil {
		t.Fatalf("webhook body: %s %v", got, err)
	}
	var delivered map[string]any
	if err := json.Unmarshal(got, &delivered); err != nil {
		t.Fatal(err)
	}
	if delivered["status"] != "complete" || delivered["content"].(map[string]any)["model"] != "qwen" {
		t.Fatalf("delivered: %s", got)
	}
	response := delivered["response"].(map[string]any)
	data := response["content"].(map[string]any)
	if response["status"] != "complete" || data["answer"] != "hello" || data["method"] != "POST" {
		t.Fatalf("response delivered: %s", got)
	}
	other := u
	other.ID.Ordinal++
	if buildScope(&other, st, "passthrough").Content != nil {
		t.Fatal("content leaked across matched rules")
	}
}
