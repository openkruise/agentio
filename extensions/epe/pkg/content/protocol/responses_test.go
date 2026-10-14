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
package protocol

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

func responsesEvent(kind string, fields map[string]any) string {
	fields["type"] = kind
	raw, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return "data: " + string(raw) + "\n\n"
}

func TestResponsesRequest(t *testing.T) {
	input := `{"model":"m","instructions":"be concise","input":[{"role":"user","content":[{"type":"input_text","text":"hello"},{"type":"input_image","image_url":"data:image/png;base64,AA=="}]},{"type":"function_call","call_id":"c","name":"lookup","arguments":"{\"x\":1}"},{"type":"function_call_output","call_id":"c","output":"result"},{"type":"item_reference","id":"prior"}],"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}},{"type":"web_search","search_context_size":"low"}]}`
	for _, size := range []int{1, len(input)} {
		a, _ := New(
			Config{Format: responsesFormat, MaxCaptureBytes: 8192},
			map[string]string{"content-type": "application/json"},
		)
		count := 0
		for at := 0; at < len(input); at += size {
			p := a.Feed([]byte(input[at:min(at+size, len(input))]), at+size >= len(input), func(obs Observation) {
				count++
				v := obs.Content.(*LLMView)
				if len(v.InputMessages) != 5 || v.InputMessages[0].Role != "system" ||
					v.InputMessages[1].Role != "user" {
					t.Fatalf("messages: %+v", v)
				}
				if v.InputMessages[1].Content[0].(TextBlock).Text != "hello" {
					t.Fatal("lost text")
				}
				if v.InputMessages[1].Content[1].(ProviderBlock).Data.(map[string]any)["image_url"] != "data:image/png;base64,AA==" {
					t.Fatal("lost image")
				}
				call := v.InputMessages[2].Content[0].(ToolCallBlock)
				if *call.ID != "c" || call.Arguments.(map[string]any)["x"] != float64(1) {
					t.Fatalf("call=%+v", call)
				}
				result := v.InputMessages[3].Content[0].(ToolResultBlock)
				if *result.ToolCallID != "c" || result.Content[0].(TextBlock).Text != "result" {
					t.Fatalf("result=%+v", result)
				}
				if v.InputMessages[4].Content[0].(ProviderBlock).Data.(map[string]any)["id"] != "prior" {
					t.Fatal("lost reference")
				}
				tools := *v.Tools
				if len(tools) != 2 || *tools[0].Name != "lookup" ||
					tools[1].Provider.Data.(map[string]any)["type"] != "web_search" {
					t.Fatalf("tools=%+v", tools)
				}
			})
			if p.Status != capturestatus.Incomplete && p.Status != capturestatus.Complete {
				t.Fatal(p)
			}
		}
		if count != 1 {
			t.Fatal(count)
		}
	}
}

func TestResponsesStreamFallbackAndBudgets(t *testing.T) {
	data, err := os.ReadFile("testdata/responses.sse")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("testdata/responses.response.json")
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal(doc, &response); err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(string(data), "event: response.completed")
	response["output"] = nil
	input := prefix + responsesEvent("response.completed", map[string]any{"response": response})
	golden, err := os.ReadFile("testdata/responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var want any
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		limit     int
		fields    *CaptureFields
		truncated bool
	}{
		{"fallback", 8192, nil, false},
		{"retention-limit", 64, nil, true},
		{"metadata-only", 64, &CaptureFields{}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := New(
				Config{
					Format:          responsesFormat,
					Response:        true,
					MaxCaptureBytes: 8192,
					MaxContentBytes: tt.limit,
					Fields:          tt.fields,
				},
				map[string]string{"content-type": "text/event-stream"},
			)
			count := 0
			p := a.Feed([]byte(input), true, func(obs Observation) {
				count++
				v := obs.Content.(*LLMView)
				if obs.Truncated != tt.truncated || *v.Usage.TotalTokens != 8 || *v.Status != "completed" {
					t.Fatalf("view=%+v", v)
				}
				if tt.name == "fallback" {
					if !reflect.DeepEqual(jsonValue(t, v), want) {
						t.Fatalf("got=%+v want=%+v", jsonValue(t, v), want)
					}
				} else if v.OutputMessages != nil {
					t.Fatal("retained unwanted messages")
				}
			})
			if p.Status != capturestatus.Complete || count != 1 {
				t.Fatalf("%+v count=%d", p, count)
			}
		})
	}
}

func TestResponsesTermination(t *testing.T) {
	for _, status := range []string{"completed", "incomplete", "failed"} {
		t.Run(status, func(t *testing.T) {
			response := map[string]any{
				"model":  "m",
				"status": status,
				"output": []any{},
				"usage":  map[string]any{"output_tokens": float64(0)},
			}
			if status == "incomplete" {
				response["incomplete_details"] = map[string]any{"reason": "max_output_tokens"}
			}
			if status == "failed" {
				response["error"] = map[string]any{"message": "failed"}
			}
			a, _ := New(
				Config{Format: responsesFormat, Response: true, MaxCaptureBytes: 4096},
				map[string]string{"content-type": "text/event-stream"},
			)
			count := 0
			p := a.Feed(
				[]byte(responsesEvent("response."+status, map[string]any{"response": response})),
				true,
				func(obs Observation) {
					count++
					v := obs.Content.(*LLMView)
					if *v.Status != status || *v.Usage.OutputTokens != 0 {
						t.Fatalf("view=%+v", v)
					}
					if status == "incomplete" &&
						(v.IncompleteReason == nil || *v.IncompleteReason != "max_output_tokens") {
						t.Fatal("lost reason")
					}
					if status == "failed" && v.Error == nil {
						t.Fatal("lost API error")
					}
				},
			)
			if p.Status != capturestatus.Complete || count != 1 {
				t.Fatalf("%+v count=%d", p, count)
			}
		})
	}
}

func TestResponsesStreamFailures(t *testing.T) {
	created := responsesEvent(
		"response.created",
		map[string]any{"response": map[string]any{"model": "m", "status": "in_progress", "output": []any{}}},
	)
	done := responsesEvent(
		"response.completed",
		map[string]any{"response": map[string]any{"model": "m", "status": "completed", "output": []any{}}},
	)
	for _, tt := range []struct {
		name   string
		input  string
		limit  int
		status capturestatus.Code
	}{
		{"eof", created, 4096, capturestatus.IncompleteStream},
		{"unfinished-item-empty-output", created + responsesEvent("response.output_item.added", map[string]any{"output_index": 0, "item": map[string]any{"id": "pending", "type": "message"}}) + done, 4096, capturestatus.IncompleteStream},
		{"done-only", "data: [DONE]\n\n", 4096, capturestatus.InvalidJSON},
		{"after-terminal", done + created, 4096, capturestatus.InvalidContent},
		{"invalid-json", "data: {\n\n", 4096, capturestatus.InvalidJSON},
		{"event-limit", done, 16, capturestatus.TooLarge},
		{"delta-without-item", created + responsesEvent("response.output_text.delta", map[string]any{"output_index": 0, "item_id": "x", "delta": "hi"}), 4096, capturestatus.InvalidContent},
		{"bad-terminal", responsesEvent("response.completed", map[string]any{"response": map[string]any{"model": "m", "status": "in_progress", "output": []any{}}}), 4096, capturestatus.InvalidContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, size := range []int{1, len(tt.input)} {
				a, _ := New(
					Config{Format: responsesFormat, Response: true, MaxCaptureBytes: tt.limit},
					map[string]string{"content-type": "text/event-stream"},
				)
				var status capturestatus.Code
				for at := 0; at < len(tt.input); at += size {
					p := a.Feed(
						[]byte(tt.input[at:min(at+size, len(tt.input))]),
						at+size >= len(tt.input),
						func(Observation) { t.Fatal("emitted invalid stream") },
					)
					status = p.Status
					if status != capturestatus.Incomplete {
						break
					}
				}
				if status != tt.status {
					t.Fatalf("got=%s want=%s", status, tt.status)
				}
			}
		})
	}
	for _, input := range []string{created + responsesEvent("response.output_item.added", map[string]any{"output_index": 0, "item": map[string]any{"id": "pending", "type": "message"}}) + responsesEvent("error", map[string]any{"message": "failed"}), created + responsesEvent("response.future", map[string]any{}) + done, responsesEvent("error", map[string]any{"code": "server_error", "message": "failed"}) + "data: [DONE]\n\n"} {
		a, _ := New(
			Config{Format: responsesFormat, Response: true, MaxCaptureBytes: 4096},
			map[string]string{"content-type": "text/event-stream"},
		)
		count := 0
		p := a.Feed([]byte(input), true, func(obs Observation) {
			count++
			v := obs.Content.(*LLMView)
			if !obs.Partial && v.Error == nil {
				t.Fatalf("lost partial/error: %+v", v)
			}
		})
		if p.Status != capturestatus.Complete || count != 1 {
			t.Fatalf("%+v count=%d", p, count)
		}
	}
}
