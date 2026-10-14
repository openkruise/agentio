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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

func testGuard(t *testing.T, payload string, headers map[string]string) (*guard, *filter.Stream) {
	t.Helper()
	cfg, err := parse(json.RawMessage(payload))
	if err != nil {
		t.Fatal(err)
	}
	st := &filter.Stream{Info: filter.NewStreamInfo(), Request: httpreq.HTTPRequest{Headers: headers}}
	g := &guard{rule: filter.RuleConfig[config]{Cfg: cfg}}
	if a, err := g.OnRequestHeaders(context.Background(), st); err != nil || a.Kind() != filter.KindNeedBody {
		t.Fatalf("headers: %v %v", a, err)
	}
	if _, ok := st.Info.Content(g.rule.ID); ok {
		t.Fatal("header preparation emitted an observation")
	}
	return g, st
}

func TestCaptureFailuresContinueUnchanged(t *testing.T) {
	for _, tt := range []struct {
		name     string
		spec     string
		media    string
		encoding string
		body     string
		status   string
	}{
		{"invalid", `{}`, "application/json", "", `{`, "invalid_json"},
		{"trailing", `{}`, "application/json", "", `{} {}`, "invalid_json"},
		{"oversize", `{"maxCaptureBytes":4}`, "application/json", "", `12345`, "too_large"},
		{"media", `{}`, "text/plain", "", `{}`, "unsupported_media_type"},
		{"compressed", `{}`, "application/json", "gzip", `{}`, "unsupported_encoding"},
		{"mapping", `{}`, "application/json", "", `{}`, "invalid_content"},
		{"key collision", `{"format":"json","transform":"{1: 'number', '1': 'string'}"}`, "application/json", "", `{}`, "transform_error"},
		{"output", `{"format":"json","maxRecordBytes":2}`, "application/json", "", `{"x":1}`, "record_too_large"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g, st := testGuard(t, tt.spec, map[string]string{"content-type": tt.media, "content-encoding": tt.encoding})
			act, err := g.OnRequestBody(context.Background(), st, filter.Body{Bytes: []byte(tt.body), Complete: true})
			if err != nil || act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
				t.Fatalf("capture changed forwarding: %v %v", act, err)
			}
			r, _ := st.Info.Content(g.rule.ID)
			if r.Status != tt.status || r.Content != nil || r.BytesSeen != int64(len(tt.body)) ||
				g.capture.adapter != nil {
				t.Fatalf("record: %+v", r)
			}
		})
	}
}

func TestBoundedChunksAndIncompleteObservation(t *testing.T) {
	g, st := testGuard(t, `{"maxCaptureBytes":7}`, map[string]string{"content-type": "application/json"})
	for _, chunk := range []string{"123", "456", strings.Repeat("x", 1024), "tail"} {
		if _, err := g.OnRequestBody(context.Background(), st, filter.Body{Bytes: []byte(chunk)}); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := st.Info.Content(g.rule.ID)
	if r.Status != "too_large" || r.BytesSeen != 1034 || r.CapturedBytes != 6 || g.capture.adapter != nil {
		t.Fatalf("record: %+v", r)
	}
	g, st = testGuard(t, `{}`, map[string]string{"content-type": "application/json"})
	if _, err := g.OnRequestBody(context.Background(), st, filter.Body{Bytes: []byte(`{"model":`)}); err != nil {
		t.Fatal(err)
	}
	r, _ = st.Info.Content(g.rule.ID)
	if r.Status != "incomplete" || r.Content != nil {
		t.Fatalf("partial JSON reported as complete: %+v", r)
	}
}

func TestEngineStreamsUnchangedAndBufferedViewMatches(t *testing.T) {
	regs, err := filter.Build(Definition())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := regs[0].Parse(
		json.RawMessage(
			`{"transform":"{\"model\": content.model, \"method\": request.method, \"messages\": content.inputMessages}"}`,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"model":"qwen","messages":[{"role":"user","content":"你好"}]}`)
	id := filter.UnitID{Scope: "ns/profile", Name: "capture"}
	scope := inputs.NewScope(
		inputs.RequestFrom(httpreq.HTTPRequest{Method: "POST"}),
		inputs.Pod{},
		inputs.Profile{},
		inputs.Rule{},
		nil,
	)
	unit := engine.Unit{ID: id, Scope: scope, Cfgs: []any{cfg}}
	var streamedRecord filter.ContentRecord
	for _, streamed := range []bool{true, false} {
		e := engine.NewEngine(regs, 0)
		st := &filter.Stream{
			Info:    filter.NewStreamInfo(),
			Request: httpreq.HTTPRequest{Headers: map[string]string{"content-type": "application/json"}},
		}
		var opts []engine.RequestOption
		if streamed {
			opts = append(opts, engine.WithRequestStreaming())
		}
		prior, err := e.EvalRequestHeaders(context.Background(), st, []engine.Unit{unit}, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if streamed {
			if prior.BodyMode() != filter.BodyStreamed {
				t.Fatalf("mode: %v", prior.BodyMode())
			}
			// Single-byte chunks include split UTF-8 and split JSON tokens.
			for i, b := range payload {
				chunk := []byte{b}
				out, err := e.EvalRequestBodyChunk(
					context.Background(),
					st,
					prior,
					filter.Body{Bytes: chunk, Complete: i == len(payload)-1},
				)
				if err != nil || out.Disposition != engine.DispositionPassthrough || string(out.Body) != string(chunk) {
					t.Fatalf("chunk %d: %+v %v", i, out, err)
				}
				chunk[0] = 'x' // The adapter may reuse its input after the callback.
			}
			streamedRecord, _ = st.Info.Content(id)
		} else {
			if prior.BodyMode() != filter.BodyBuffered {
				t.Fatalf("mode: %v", prior.BodyMode())
			}
			if _, err := e.EvalRequestBody(
				context.Background(),
				st,
				prior,
				filter.Body{Bytes: payload, Complete: true},
			); err != nil {
				t.Fatal(err)
			}
		}
		r, _ := st.Info.Content(id)
		if r.Status != "complete" || !reflect.DeepEqual(r, streamedRecord) {
			t.Fatalf("record: %+v; streaming: %+v", r, streamedRecord)
		}
		data := r.Content.(map[string]any)
		if data["model"] != "qwen" || data["method"] != "POST" {
			t.Fatalf("mapping: %+v", data)
		}
		if _, ok := scope.Activation().ResolveName("body"); ok {
			t.Fatal("transform mutated shared scope")
		}
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, raw := range []string{`{"format":"mcp"}`, `{"maxCaptureBytes":-1}`, `{"maxCaptureBytes":1048577}`, `{"maxRecordBytes":65537}`, `{"transform":"body."}`} {
		if _, err := parse(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestResponseCapture(t *testing.T) {
	fixtures := make(map[string]string)
	views := make(map[string]any)
	for _, fixture := range []struct {
		name string
		want string
	}{
		{"openai", "openai.json"},
		{"anthropic", "anthropic.json"},
		{"responses", "responses.json"},
		{"anthropic-empty-tool", "anthropic-empty-tool.want.json"},
		{"responses-tools", "responses-tools.want.json"},
		{"chat-empty-content", "chat-empty-content.want.json"},
		{"chat-annotations", "chat-annotations.want.json"},
	} {
		raw, err := os.ReadFile("../../content/protocol/testdata/" + fixture.name + ".sse")
		if err != nil {
			t.Fatal(err)
		}
		fixtures[fixture.name] = string(raw)
		raw, err = os.ReadFile("../../content/protocol/testdata/" + fixture.want)
		if err != nil {
			t.Fatal(err)
		}
		var view any
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatal(err)
		}
		views[fixture.name] = view
	}

	for _, streamed := range []bool{false, true} {
		for _, tt := range []struct {
			name     string
			response string
			media    string
			encoding string
			body     string
			status   string
			data     any
		}{
			{name: "default-off", response: `null`},
			{name: "anthropic-empty-tool", response: `{"enabled":true,"format":"anthropic-messages"}`, media: "text/event-stream", body: fixtures["anthropic-empty-tool"], status: "complete", data: views["anthropic-empty-tool"]},
			{name: "responses-tools", response: `{"enabled":true,"format":"openai-responses"}`, media: "text/event-stream", body: fixtures["responses-tools"], status: "complete", data: views["responses-tools"]},
			{name: "chat-empty-content", response: `{"enabled":true,"format":"openai-chat-completions"}`, media: "text/event-stream", body: fixtures["chat-empty-content"], status: "complete", data: views["chat-empty-content"]},
			{name: "chat-annotations", response: `{"enabled":true,"format":"openai-chat-completions"}`, media: "text/event-stream", body: fixtures["chat-annotations"], status: "partial", data: views["chat-annotations"]},
			{name: "responses-sse", response: `{"enabled":true,"format":"openai-responses"}`, media: "text/event-stream", body: fixtures["responses"], status: "complete", data: views["responses"]},
			{name: "openai-sse", response: `{"enabled":true,"format":"openai-chat-completions"}`, media: "text/event-stream", body: fixtures["openai"], status: "complete", data: views["openai"]},
			{name: "anthropic-sse", response: `{"enabled":true,"format":"anthropic-messages"}`, media: "text/event-stream", body: fixtures["anthropic"], status: "complete", data: views["anthropic"]},
			{name: "sse-partial", response: `{"enabled":true,"format":"openai-chat-completions"}`, media: "text/event-stream", body: strings.ReplaceAll(fixtures["openai"], `"content":`, `"future_delta":`), status: "partial", data: map[string]any{"format": "openai-chat-completions", "model": "test-model", "partial": true, "usage": map[string]any{"totalTokens": float64(8)}}},
			{name: "sse-truncated", response: `{"enabled":true,"format":"openai-chat-completions","maxRecordBytes":256}`, media: "text/event-stream", body: fixtures["openai"], status: "truncated", data: map[string]any{"format": "openai-chat-completions", "model": "test-model", "truncated": true, "usage": map[string]any{"totalTokens": float64(8)}}},
			{name: "sse-metadata", response: `{"enabled":true,"format":"openai-chat-completions","maxRecordBytes":64,"transform":"{'model':content.model,'tokens':content.usage.totalTokens}"}`, media: "text/event-stream", body: fixtures["openai"], status: "complete", data: map[string]any{"model": "test-model", "tokens": float64(8)}},
			{name: "sse-transformation", response: `{"enabled":true,"format":"openai-chat-completions","transform":"{'text': content.outputMessages[0].content[0].text}"}`, media: "text/event-stream", body: fixtures["openai"], status: "complete", data: map[string]any{"text": "你好"}},
			{name: "sse-budget", response: `{"enabled":true,"format":"anthropic-messages","maxCaptureBytes":16}`, media: "text/event-stream", body: fixtures["anthropic"], status: "too_large"},
			{name: "sse-record-limit", response: `{"enabled":true,"format":"openai-chat-completions","maxRecordBytes":2}`, media: "text/event-stream", body: fixtures["openai"], status: "record_too_large"},
			{name: "sse-incomplete", response: `{"enabled":true,"format":"openai-chat-completions"}`, media: "text/event-stream", body: strings.ReplaceAll(fixtures["openai"], "data: [DONE]", ": missing end"), status: "incomplete_stream"},
			{name: "anthropic", response: `{"enabled":true,"format":"anthropic-messages"}`, media: "application/json", body: `{"model":"claude","content":[],"usage":{"output_tokens":2}}`, status: "complete", data: map[string]any{"format": "anthropic-messages", "model": "claude", "outputMessages": []any{map[string]any{"index": float64(0), "role": "assistant", "content": []any{}}}, "usage": map[string]any{"outputTokens": float64(2)}}},

			{name: "explicit-off", response: `{"enabled":false}`},
			{name: "text", response: `{"enabled":true,"format":"text"}`, media: "text/plain; charset=UTF-8", body: "你好\nresponse", status: "complete", data: "你好\nresponse"},
			{name: "chat", response: `{"enabled":true,"format":"openai-chat-completions"}`, media: "application/json", body: `{"model":"qwen","choices":[],"usage":{"total_tokens":3},"id":"omit"}`, status: "complete", data: map[string]any{"format": "openai-chat-completions", "model": "qwen", "outputMessages": []any{}, "usage": map[string]any{"totalTokens": float64(3)}}},
			{name: "chat-error", response: `{"enabled":true,"format":"openai-chat-completions"}`, media: "application/json", body: `{"error":{"message":"bad request"}}`, status: "complete", data: map[string]any{"format": "openai-chat-completions", "error": map[string]any{"message": "bad request"}}},
			{name: "chat-invalid", response: `{"enabled":true,"format":"openai-chat-completions"}`, media: "application/json", body: `{"model":"qwen","choices":"wrong type"}`, status: "invalid_content"},
			{name: "text-transformation", response: `{"enabled":true,"format":"text","transform":"{'answer': content}"}`, media: "text/plain", body: "hello", status: "complete", data: map[string]any{"answer": "hello"}},
			{name: "json", response: `{"enabled":true}`, media: "application/json", body: `{"answer":"你好"}`, status: "complete", data: map[string]any{"answer": "你好"}},
			{name: "transform", response: `{"enabled":true,"transform":"content.answer"}`, media: "application/problem+json; charset=utf-8", body: `{"answer":"你好"}`, status: "complete", data: "你好"},
			{name: "invalid", response: `{"enabled":true}`, media: "application/json", body: `{`, status: "invalid_json"},
			{name: "oversize", response: `{"enabled":true,"maxCaptureBytes":4}`, media: "application/json", body: `12345`, status: "too_large"},
			{name: "record-limit", response: `{"enabled":true,"maxRecordBytes":2}`, media: "application/json", body: `{"a":1}`, status: "record_too_large"},
			{name: "bad-transform", response: `{"enabled":true,"transform":"content.missing"}`, media: "application/json", body: `{}`, status: "transform_error"},
			{name: "sse", response: `{"enabled":true}`, media: "text/event-stream", body: "data: {}\n\n", status: "unsupported_media_type"},
			{name: "gzip", response: `{"enabled":true}`, media: "application/json", encoding: "gzip", body: `{}`, status: "unsupported_encoding"},
		} {
			t.Run(fmt.Sprintf("%s/streamed=%t", tt.name, streamed), func(t *testing.T) {
				regs, err := filter.Build(Definition())
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := regs[0].Parse(json.RawMessage(`{"format":"json","response":` + tt.response + `}`))
				if err != nil {
					t.Fatal(err)
				}
				id := filter.UnitID{Name: "capture"}
				units := []engine.Unit{{ID: id, Cfgs: []any{cfg}}}
				e := engine.NewEngine(regs, 0)
				st := &filter.Stream{
					Info:    filter.NewStreamInfo(),
					Request: httpreq.HTTPRequest{Headers: map[string]string{"content-type": "application/json"}},
					Response: httpreq.HTTPResponse{
						Headers: map[string]string{"content-type": tt.media, "content-encoding": tt.encoding},
					},
				}
				req, err := e.EvalRequestHeaders(context.Background(), st, units)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := e.EvalRequestBody(
					context.Background(),
					st,
					req,
					filter.Body{Bytes: []byte(`{"request":true}`), Complete: true},
				); err != nil {
					t.Fatal(err)
				}
				requestBefore, _ := st.Info.Content(id)
				var opts []engine.ResponseOption
				if streamed {
					opts = append(opts, engine.WithResponseStreaming())
				}
				resp, err := e.EvalResponseHeaders(context.Background(), st, units, req.ResponseScope, opts...)
				if err != nil {
					t.Fatal(err)
				}
				if tt.status == "" {
					subs, err := e.ValidateSubscriptions(units)
					if err != nil || subs != 0 || resp.NeedsBody() {
						t.Fatalf("disabled capture subscribed: %v %v", subs, err)
					}
					if _, ok := st.Info.ResponseContent(id); ok {
						t.Fatal("disabled capture recorded content")
					}
					return
				}
				if streamed {
					if resp.BodyMode() != filter.BodyStreamed {
						t.Fatalf("mode: %v", resp.BodyMode())
					}
					for i, b := range []byte(tt.body) {
						chunk := []byte{b}
						out, err := e.EvalResponseBodyChunk(context.Background(), st, resp, filter.Body{Bytes: chunk})
						if err != nil || out.Disposition != engine.DispositionPassthrough ||
							!bytes.Equal(out.Body, chunk) {
							t.Fatalf("chunk %d: %+v %v", i, out, err)
						}
						chunk[0] = 'x'
					}
					snapshot, _ := st.Info.ResponseContent(id)
					out, err := e.EvalResponseBodyChunk(context.Background(), st, resp, filter.Body{Complete: true})
					if err != nil || out.Disposition != engine.DispositionPassthrough || len(out.Body) != 0 {
						t.Fatalf("EOS: %+v %v", out, err)
					}
					if snapshot.Content != nil {
						t.Fatalf("partial snapshot mutated: %+v", snapshot)
					}
				} else {
					if resp.BodyMode() != filter.BodyBuffered {
						t.Fatalf("mode: %v", resp.BodyMode())
					}
					out, err := e.EvalResponseBody(
						context.Background(),
						st,
						resp,
						filter.Body{Bytes: []byte(tt.body), Complete: true},
					)
					if err != nil || out.Disposition != engine.DispositionPassthrough || out.Body != nil ||
						len(out.HeaderOps) != 0 {
						t.Fatalf("body: %+v %v", out, err)
					}
				}
				r, ok := st.Info.ResponseContent(id)
				if !ok || r.Status != tt.status || r.BytesSeen != int64(len(tt.body)) ||
					!reflect.DeepEqual(r.Content, tt.data) {
					t.Fatalf("response record: %+v", r)
				}
				requestAfter, _ := st.Info.Content(id)
				if requestAfter.Status != "complete" || !reflect.DeepEqual(requestBefore, requestAfter) {
					t.Fatalf("request overwritten: %+v", requestAfter)
				}
			})
		}
	}
}

func TestInvalidResponseConfiguration(t *testing.T) {
	for _, spec := range []string{`{"enabled":true,"format":"sse"}`, `{"enabled":"yes"}`, `{"enabled":true,"maxCaptureBytes":-1}`, `{"enabled":true,"maxCaptureBytes":1048577}`, `{"enabled":true,"maxRecordBytes":65537}`, `{"enabled":true,"transform":"body."}`} {
		if _, err := parse(json.RawMessage(`{"response":` + spec + `}`)); err == nil {
			t.Errorf("accepted %s", spec)
		}
	}
}

func TestRequestFormats(t *testing.T) {
	for _, tt := range []struct {
		name   string
		spec   string
		media  string
		body   string
		status string
		data   any
	}{
		{name: "responses-text", spec: `{"format":"openai-responses"}`, media: "application/json", body: `{"model":"m","input":"hello"}`, status: "complete", data: map[string]any{"format": "openai-responses", "model": "m", "inputMessages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "hello"}}}}}},
		{name: "responses-metadata", spec: `{"format":"openai-responses","transform":"content.model"}`, media: "application/json", body: `{"model":"m","input":"hello"}`, status: "complete", data: "m"},
		{name: "responses-invalid", spec: `{"format":"openai-responses"}`, media: "application/json", body: `{"model":"m","input":42}`, status: "invalid_content"},
		{name: "responses-invalid-block", spec: `{"format":"openai-responses"}`, media: "application/json", body: `{"model":"m","input":[{"role":"user","content":[{"type":"input_text","text":42}]}]}`, status: "invalid_content"},
		{name: "responses-request-sse", spec: `{"format":"openai-responses"}`, media: "text/event-stream", body: "data: {}\n\n", status: "unsupported_media_type"},
		{name: "chat-truncated", spec: `{"maxRecordBytes":128}`, media: "application/json", body: `{"model":"qwen","messages":[{"role":"user","content":"` + strings.Repeat("x", 256) + `"}]}`, status: "truncated", data: map[string]any{"format": "openai-chat-completions", "model": "qwen", "truncated": true}},
		{name: "anthropic", spec: `{"format":"anthropic-messages"}`, media: "application/json", body: `{"model":"claude","messages":[],"system":"instruction","tools":[],"stream":true}`, status: "complete", data: map[string]any{"format": "anthropic-messages", "model": "claude", "inputMessages": []any{map[string]any{"role": "system", "content": []any{map[string]any{"type": "text", "text": "instruction"}}}}, "tools": []any{}}},
		{name: "anthropic-invalid", spec: `{"format":"anthropic-messages"}`, media: "application/json", body: `{"model":"claude","messages":{}}`, status: "invalid_content"},
		{name: "anthropic-request-sse", spec: `{"format":"anthropic-messages"}`, media: "text/event-stream", body: "data: {}\n\n", status: "unsupported_media_type"},
		{name: "json-array", spec: `{"format":"json"}`, media: "application/json", body: `[1,"你好"]`, status: "complete", data: []any{float64(1), "你好"}},
		{name: "json-null", spec: `{"format":"json"}`, media: "application/json", body: `null`, status: "complete"},
		{name: "text", spec: `{"format":"text"}`, media: "text/plain; charset=utf-8", body: "hello\n你好", status: "complete", data: "hello\n你好"},
		{name: "empty-text", spec: `{"format":"text"}`, media: "text/plain", status: "complete", data: ""},
		{name: "invalid-text", spec: `{"format":"text"}`, media: "text/plain", body: string([]byte{0xff}), status: "invalid_text"},
		{name: "charset", spec: `{"format":"text"}`, media: "text/plain; charset=iso-8859-1", body: "hello", status: "unsupported_encoding"},
		{name: "not-text", spec: `{"format":"text"}`, media: "application/octet-stream", body: "hello", status: "unsupported_media_type"},
		{name: "sse-is-not-text", spec: `{"format":"text"}`, media: "text/event-stream", body: "data: {}\n\n", status: "unsupported_media_type"},
		{name: "text-limit", spec: `{"format":"text","maxCaptureBytes":3}`, media: "text/plain", body: "hello", status: "too_large"},
		{name: "text-record-limit", spec: `{"format":"text","maxRecordBytes":3}`, media: "text/plain", body: "hi", status: "record_too_large"},
		{name: "chat", spec: `{}`, media: "application/json", body: `{"model":"qwen","messages":[],"stream":true}`, status: "complete", data: map[string]any{"format": "openai-chat-completions", "model": "qwen", "inputMessages": []any{}}},
		{name: "chat-transformation", spec: `{"transform":"{'model': content.model, 'messageCount': size(content.inputMessages)}"}`, media: "application/json", body: `{"model":"qwen","messages":[],"stream":true}`, status: "complete", data: map[string]any{"model": "qwen", "messageCount": int64(0)}},
		{name: "chat-not-object", spec: `{}`, media: "application/json", body: `[]`, status: "invalid_content"},
		{name: "chat-not-messages", spec: `{}`, media: "application/json", body: `{"model":"qwen","messages":null}`, status: "invalid_content"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, split := range []bool{false, true} {
				g, st := testGuard(t, tt.spec, map[string]string{"content-type": tt.media})
				feed := func(chunk []byte, complete bool) {
					t.Helper()
					a, err := g.OnRequestBody(context.Background(), st, filter.Body{Bytes: chunk, Complete: complete})
					if err != nil || a.Kind() != filter.KindContinue || len(a.Mutations()) != 0 {
						t.Fatalf("forwarding changed: %v %v", a, err)
					}
				}
				if split {
					for _, b := range []byte(tt.body) {
						chunk := []byte{b}
						feed(chunk, false)
						chunk[0] = 'x'
					}
					partial, _ := st.Info.Content(g.rule.ID)
					if partial.Content != nil {
						t.Fatalf("published incomplete document: %+v", partial)
					}
					feed(nil, true)
				} else {
					feed([]byte(tt.body), true)
				}
				r, ok := st.Info.Content(g.rule.ID)
				if !ok || r.Status != tt.status || r.BytesSeen != int64(len(tt.body)) ||
					!reflect.DeepEqual(r.Content, tt.data) {
					t.Fatalf("split=%t record=%+v want status=%s data=%v", split, r, tt.status, tt.data)
				}
				if g.capture.adapter != nil {
					t.Fatal("retained body after completion")
				}
				feed([]byte("ignored after EOF"), true)
				after, _ := st.Info.Content(g.rule.ID)
				if !reflect.DeepEqual(r, after) {
					t.Fatal("completed observation changed")
				}
			}
		})
	}
}

func TestAmplifiedTransformationContinuesWithoutRecord(t *testing.T) {
	g, st := testGuard(
		t,
		`{"format":"json","transform":"content.map(item, {'item': item, 'context': content})"}`,
		map[string]string{"content-type": "application/json"},
	)
	body := make([]any, 200)
	for i := range body {
		body[i] = map[string]any{"text": strings.Repeat("x", 200)}
	}
	input, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	act, err := g.OnRequestBody(context.Background(), st, filter.Body{Bytes: input, Complete: true})
	if err != nil || act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
		t.Fatalf("forwarding changed: %v %v", act, err)
	}
	r, _ := st.Info.Content(g.rule.ID)
	if r.Status != "record_too_large" || r.Content != nil || g.capture.adapter != nil {
		t.Fatalf("record: %+v", r)
	}
}

func TestTransformedContentEnvelope(t *testing.T) {
	for _, tt := range []struct {
		name       string
		format     string
		media      string
		body       string
		expression string
		want       string
	}{
		{"text", "text", "text/plain", "hello", "", `"hello"`},
		{"json-array", "json", "application/json", `[1,"x"]`, "", `[1,"x"]`},
		{"json-bool", "json", "application/json", "false", "", "false"},
		{"json-null", "json", "application/json", "null", "", "null"},
		{"string", "json", "application/json", `{"answer":"hi"}`, "content.answer", `"hi"`},
		{"number", "text", "text/plain", "hello", "size(content)", "5"},
		{"null", "text", "text/plain", "hello", "null", "null"},
		{"array", "text", "text/plain", "hello", "[content]", `["hello"]`},
		{"object", "text", "text/plain", "hello", "{'answer':content}", `{"answer":"hello"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := json.Marshal(captureSpec{Format: tt.format, Transform: tt.expression})
			if err != nil {
				t.Fatal(err)
			}
			g, st := testGuard(t, string(spec), map[string]string{"content-type": tt.media})
			if _, err := g.OnRequestBody(
				context.Background(),
				st,
				filter.Body{Bytes: []byte(tt.body), Complete: true},
			); err != nil {
				t.Fatal(err)
			}
			record, _ := st.Info.Content(g.rule.ID)
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &envelope); err != nil {
				t.Fatal(err)
			}
			if record.Status != "complete" || string(envelope["content"]) != tt.want || envelope["data"] != nil {
				t.Fatalf("unexpected envelope: %s", encoded)
			}
		})
	}
}

func TestContentEnvelopeBudget(t *testing.T) {
	const envelope = `{"content":"hi"}`
	for _, limit := range []int{len(envelope) - 1, len(envelope)} {
		spec := fmt.Sprintf(`{"format":"text","maxRecordBytes":%d}`, limit)
		g, st := testGuard(t, spec, map[string]string{"content-type": "text/plain"})
		_, err := g.OnRequestBody(context.Background(), st, filter.Body{Bytes: []byte("hi"), Complete: true})
		if err != nil {
			t.Fatal(err)
		}
		record, _ := st.Info.Content(g.rule.ID)
		if limit < len(envelope) {
			if record.Status != "record_too_large" || record.Content != nil {
				t.Fatal(record)
			}
		} else if record.Status != "complete" || record.Content != "hi" {
			t.Fatal(record)
		}
	}
}

func TestTransformKeepsCaptureStatus(t *testing.T) {
	g, st := testGuard(
		t,
		`{"maxRecordBytes":128,"transform":"has(content.truncated)"}`,
		map[string]string{"content-type": "application/json"},
	)
	body := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("x", 256) + `"}]}`
	if _, err := g.OnRequestBody(
		context.Background(),
		st,
		filter.Body{Bytes: []byte(body), Complete: true},
	); err != nil {
		t.Fatal(err)
	}
	record, _ := st.Info.Content(g.rule.ID)
	if record.Status != "truncated" || record.Content != true {
		t.Fatal(record)
	}
}

func TestTransformRejectsOldOrUnknownInputs(t *testing.T) {
	for _, raw := range []string{
		`{"normalize":"content"}`,
		`{"response":{"enabled":true,"normalize":"content"}}`,
		`{"transform":"body"}`,
		`{"transform":"body.messages"}`,
		`{} {}`,
	} {
		if _, err := parse(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted: %s", raw)
		}
	}
}

func TestAbsentTransformSkipsCEL(t *testing.T) {
	cfg, err := parse(json.RawMessage(`{"format":"json","response":{"enabled":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.request.transform != nil || cfg.response.transform != nil ||
		!cfg.request.fields.InputMessages || !cfg.request.fields.OutputMessages || !cfg.request.fields.Tools {
		t.Fatal("absent transform must have no program and retain all fields")
	}
	capture := newCapture(cfg.request, map[string]string{"content-type": "application/json"})
	// A zero Scope cannot build an activation; the default path must not request one.
	capture.observe([]byte(`{"answer":42}`), true, &inputs.Scope{})
	if capture.record.Status != "complete" || capture.record.Content.(map[string]any)["answer"] != float64(42) {
		t.Fatal(capture.record)
	}
	cfg, err = parse(json.RawMessage(`{"transform":"content.model"}`))
	if err != nil || cfg.request.transform == nil || cfg.request.fields.InputMessages {
		t.Fatalf("explicit transform lost its program or field selection: %+v %v", cfg, err)
	}
}
