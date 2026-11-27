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
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

func TestJSONAndSSEAuditViews(t *testing.T) {
	for _, tt := range []struct {
		name   string
		format string
	}{{"openai", "openai-chat-completions"}, {"anthropic", "anthropic-messages"}, {"responses", "openai-responses"}} {
		t.Run(tt.name, func(t *testing.T) {
			golden, err := os.ReadFile("testdata/" + tt.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var want any
			if err := json.Unmarshal(golden, &want); err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{".response.json", ".sse"} {
				input, err := os.ReadFile("testdata/" + tt.name + suffix)
				if err != nil {
					t.Fatal(err)
				}
				media := "application/json"
				if suffix == ".sse" {
					media = "text/event-stream"
				}
				for _, size := range []int{1, 17, len(input)} {
					a, status := New(
						Config{Format: tt.format, Response: true, MaxCaptureBytes: 8192},
						map[string]string{"content-type": media},
					)
					if status != capturestatus.Incomplete {
						t.Fatal(status)
					}
					var got Observation
					emitted := 0
					for at := 0; at < len(input); at += size {
						p := a.Feed(
							input[at:min(at+size, len(input))],
							at+size >= len(input),
							func(v Observation) {
								got = v
								emitted++
							},
						)
						if at+size < len(input) && (p.Status != capturestatus.Incomplete || emitted != 0) {
							t.Fatalf("early completion: %+v", p)
						}
						status = p.Status
					}
					if status != capturestatus.Complete || emitted != 1 || got.Truncated ||
						!reflect.DeepEqual(jsonValue(t, got.Content), want) {
						t.Fatalf("%s size=%d status=%s got=%+v want=%+v", suffix, size, status, got, want)
					}
				}
			}
		})
	}
}

func longStream(format string) string {
	text := strings.Repeat("x", 1024)
	var s strings.Builder
	if format == "openai-chat-completions" {
		for range 128 {
			fmt.Fprintf(
				&s,
				"data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"%s\"}}]}\n\n",
				text,
			)
		}
		s.WriteString(
			"data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"total_tokens\":7}}\n\ndata: [DONE]\n\n",
		)
	} else {
		s.WriteString(
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"m\",\"content\":[],\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\n",
		)
		s.WriteString(
			"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		)
		for range 128 {
			fmt.Fprintf(
				&s,
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"%s\"}}\n\n",
				text,
			)
		}
		s.WriteString(
			"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		)
	}
	return s.String()
}

func TestSSECaptureBudgetAndMetadataOnly(t *testing.T) {
	for _, format := range []string{"openai-chat-completions", "anthropic-messages"} {
		input := longStream(format)
		for _, messages := range []bool{false, true} {
			for _, size := range []int{1, 4096, len(input)} {
				t.Run(fmt.Sprintf("%s/messages=%t/chunk=%d", format, messages, size), func(t *testing.T) {
					fields := CaptureFields{OutputMessages: messages}
					a, status := New(
						Config{
							Format:          format,
							Response:        true,
							MaxCaptureBytes: 2048,
							MaxContentBytes: 256,
							Fields:          &fields,
						},
						map[string]string{"content-type": "text/event-stream"},
					)
					if status != capturestatus.Incomplete {
						t.Fatal(status)
					}
					var obs Observation
					calls := 0
					for at := 0; at < len(input); at += size {
						p := a.Feed(
							[]byte(input[at:min(at+size, len(input))]),
							at+size >= len(input),
							func(v Observation) {
								obs = v
								calls++
							},
						)
						status = p.Status
						if status != capturestatus.Incomplete && status != capturestatus.Complete {
							t.Fatal(p)
						}
						if a.retention.used > 256 {
							t.Fatalf("retained beyond budget: %+v", a.retention)
						}
					}
					view, ok := obs.Content.(*LLMView)
					if !ok || status != capturestatus.Complete || calls != 1 || obs.Truncated != messages {
						t.Fatalf("status=%s obs=%+v", status, obs)
					}
					if view.OutputMessages != nil {
						t.Fatal("retained discarded or unrequested content")
					}
					if view.Usage == nil || view.Usage.TotalTokens == nil || *view.Usage.TotalTokens != 7 {
						t.Fatalf("lost final usage: %+v", view)
					}
					if !messages && a.retention.used != 0 {
						t.Fatal("metadata-only retained payload")
					}
					switch stream := a.stream.(type) {
					case *chatStream:
						if stream.choices[0].text.Len() != 0 {
							t.Fatal("retained text")
						}
					case *anthropicStream:
						if stream.blocks[0].source != nil || stream.blocks[0].text.Len() != 0 {
							t.Fatal("retained text")
						}
					}
				})
			}
		}
	}
}

func TestUsageAndToolSemantics(t *testing.T) {
	usage := anthropicUsage(
		decodeUsage(
			json.RawMessage(
				`{"input_tokens":5,"output_tokens":2,"cache_read_input_tokens":10,"cache_creation_input_tokens":3}`,
			),
			true,
			false,
		),
	)
	if usage.InputTokens == nil || *usage.InputTokens != 18 || usage.TotalTokens == nil || *usage.TotalTokens != 20 {
		t.Fatal(usage)
	}
	if decodeUsage(json.RawMessage(`{"output_tokens":2}`), true, false).InputTokens != nil {
		t.Fatal("invented unknown usage")
	}
	id, name := "id", "fn"
	call := newToolCall(&id, &name, `{"x":1}`)
	other := newToolCall(&id, &name, map[string]any{"x": float64(1)})
	if !reflect.DeepEqual(call, other) {
		t.Fatal("arguments differ by protocol")
	}
	if call := newToolCall(&id, &name, `{"x":`); call.Arguments != `{"x":` {
		t.Fatal("invalid arguments changed")
	}

}

func TestSSEStateLimit(t *testing.T) {
	a, _ := New(
		Config{Format: "openai-chat-completions", Response: true, MaxCaptureBytes: 1024, Fields: &CaptureFields{}},
		map[string]string{"content-type": "text/event-stream"},
	)
	for i := 0; i <= 1024; i++ {
		event := fmt.Sprintf("data: {\"model\":\"m\",\"choices\":[{\"index\":%d,\"delta\":{}}]}\n\n", i)
		p := a.Feed([]byte(event), false, func(Observation) { t.Fatal("premature record") })
		want := capturestatus.Incomplete
		if i == 1024 {
			want = capturestatus.TooLarge
		}
		if p.Status != want {
			t.Fatalf("index=%d progress=%+v", i, p)
		}
	}
	if len(a.stream.(*chatStream).choices) != 1024 {
		t.Fatal("unbounded choices")
	}
}

func TestToolInputDiscardContinuesUsage(t *testing.T) {
	for _, format := range []string{"openai-chat-completions", "anthropic-messages"} {
		name := "openai"
		if format == "anthropic-messages" {
			name = "anthropic"
		}
		input, err := os.ReadFile("testdata/" + name + ".sse")
		if err != nil {
			t.Fatal(err)
		}
		for _, capture := range []bool{false, true} {
			a, _ := New(
				Config{
					Format:          format,
					Response:        true,
					MaxCaptureBytes: 4096,
					MaxContentBytes: 4,
					Fields:          &CaptureFields{OutputMessages: capture},
				},
				map[string]string{"content-type": "text/event-stream"},
			)
			var obs Observation
			p := a.Feed(input, true, func(v Observation) { obs = v })
			if p.Status != capturestatus.Complete || obs.Truncated != capture {
				t.Fatalf("%s: %+v %+v", format, p, obs)
			}
			view := obs.Content.(*LLMView)
			if view.OutputMessages != nil {
				t.Fatal("retained tool input")
			}
			if view.Usage == nil {
				t.Fatal("lost usage")
			}
		}
	}
}

func TestRequestAgentContent(t *testing.T) {
	for _, tt := range []struct {
		format     string
		body       string
		resultRole string
	}{
		{
			format:     "openai-chat-completions",
			body:       `{"model":"m","messages":[{"role":"system","content":"instructions"},{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1}"}}]},{"role":"tool","tool_call_id":"c1","content":"result"}],"tools":[{"type":"function","function":{"name":"lookup","description":"lookup item","parameters":{"type":"object"}}}]}`,
			resultRole: "tool",
		},
		{
			format:     "anthropic-messages",
			body:       `{"model":"m","system":"instructions","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"c1","name":"lookup","input":{"x":1}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"c1","content":"result"}]}],"tools":[{"name":"lookup","description":"lookup item","input_schema":{"type":"object"}}]}`,
			resultRole: "user",
		},
	} {
		t.Run(tt.format, func(t *testing.T) {
			a, _ := New(
				Config{Format: tt.format, MaxCaptureBytes: 4096},
				map[string]string{"content-type": "application/json"},
			)
			var obs Observation
			p := a.Feed([]byte(tt.body), true, func(v Observation) { obs = v })
			if p.Status != capturestatus.Complete || obs.Truncated {
				t.Fatalf("%+v %+v", p, obs)
			}
			wantJSON := fmt.Sprintf(
				`{"format":%q,"model":"m","inputMessages":[{"role":"system","content":[{"type":"text","text":"instructions"}]},{"role":"assistant","content":[{"type":"tool_call","id":"c1","name":"lookup","arguments":{"x":1}}]},{"role":%q,"content":[{"type":"tool_result","toolCallId":"c1","content":[{"type":"text","text":"result"}],"isError":false}]}],"tools":[{"name":"lookup","description":"lookup item","parameters":{"type":"object"}}]}`,
				tt.format,
				tt.resultRole,
			)
			var want any
			if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(jsonValue(t, obs.Content), want) {
				t.Fatalf("got %+v want %+v", obs.Content, want)
			}
		})
	}
}

func TestRepeatedToolIdentityDoesNotConsumeBudget(t *testing.T) {
	c := &chatChoice{retained: &retention{limit: 128, enabled: true}}
	target := &chatToolState{}
	id, kind := "call", "function"
	tool := &toolWire{ID: &id, Type: &kind}
	if !c.keepToolIdentity(target, tool) {
		t.Fatal("valid identity rejected")
	}
	used := c.retained.used
	for range 100 {
		if !c.keepToolIdentity(target, tool) {
			t.Fatal("repeated identity rejected")
		}
	}
	if c.retained.truncated || c.retained.used != used {
		t.Fatal("charged repeated identity")
	}
	changed := "changed"
	tool.ID = &changed
	if c.keepToolIdentity(target, tool) {
		t.Fatal("accepted changing tool identity")
	}
}

func jsonValue(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestTypedViewExtensionsAndValidation(t *testing.T) {
	for _, tt := range []struct {
		name     string
		body     string
		response bool
		status   capturestatus.Code
	}{
		{"bad-tools", `{"model":"m","messages":[],"tools":{}}`, false, capturestatus.InvalidContent},
		{"bad-tool-name", `{"model":"m","messages":[],"tools":[{"function":{"name":1}}]}`, false, capturestatus.InvalidContent},
		{"bad-call-id", `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":1,"function":{"name":"f"}}]}]}`, false, capturestatus.InvalidContent},
		{"bad-finish-reason", `{"model":"m","choices":[{"index":0,"message":{"role":"assistant"},"finish_reason":1}]}`, true, capturestatus.InvalidContent},
		{"null-tools", `{"model":"m","messages":[],"tools":null}`, false, capturestatus.Complete},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := New(
				Config{Format: "openai-chat-completions", Response: tt.response, MaxCaptureBytes: 4096},
				map[string]string{"content-type": "application/json"},
			)
			var obs Observation
			p := a.Feed([]byte(tt.body), true, func(v Observation) { obs = v })
			if p.Status != tt.status {
				t.Fatal(p)
			}
			if tt.name == "null-tools" {
				v := jsonValue(t, obs.Content).(map[string]any)
				if tools, exists := v["tools"]; !exists || tools != nil {
					t.Fatalf("lost explicit null: %+v", v)
				}
			}
		})
	}
	raw := map[string]any{
		"type":          "text",
		"text":          "answer",
		"citations":     []any{},
		"cache_control": map[string]any{"type": "ephemeral"},
	}
	encoded, err := json.Marshal([]any{raw})
	if err != nil {
		t.Fatal(err)
	}
	content := blocks(encoded, "anthropic-messages")
	if _, ok := content[0].(TextBlock); !ok {
		t.Fatalf("untyped text: %T", content[0])
	}
	if got := jsonValue(t, content[0]); !reflect.DeepEqual(got, raw) {
		t.Fatalf("annotations changed: %+v", got)
	}
	unknown := map[string]any{"type": "custom", "name": "tool"}
	tools, status := toolDefinitions(json.RawMessage(`[{"type":"custom","name":"tool"}]`), "openai-chat-completions")
	if status != capturestatus.Complete || tools[0].Provider == nil ||
		!reflect.DeepEqual(tools[0].Provider.Data, unknown) {
		t.Fatalf("lost unsupported tool: %+v", tools)
	}
}

func TestAnthropicServerToolPreserved(t *testing.T) {
	const body = `{"model":"claude","messages":[],"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":5,"allowed_domains":["example.com"]},{"type":"custom","name":"lookup","input_schema":{"type":"object"}}]}`
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatal(err)
	}
	a, _ := New(
		Config{Format: "anthropic-messages", MaxCaptureBytes: 4096},
		map[string]string{"content-type": "application/json"},
	)
	count := 0
	p := a.Feed([]byte(body), true, func(obs Observation) {
		count++
		v := obs.Content.(*LLMView)
		if v.Tools == nil || len(*v.Tools) != 2 {
			t.Fatalf("lost tools: %+v", v)
		}
		tools := *v.Tools
		if tools[0].Provider == nil || !reflect.DeepEqual(tools[0].Provider.Data, raw["tools"].([]any)[0]) {
			t.Fatalf("server tool fields lost: %+v", tools[0])
		}
		if tools[1].Provider != nil || tools[1].Name == nil || *tools[1].Name != "lookup" {
			t.Fatalf("custom tool not normalized: %+v", tools[1])
		}
		encoded := jsonValue(t, tools[0]).(map[string]any)
		if !reflect.DeepEqual(encoded["data"], raw["tools"].([]any)[0]) {
			t.Fatalf("serialized server tool lost fields: %+v", encoded)
		}
	})
	if p.Status != capturestatus.Complete || count != 1 {
		t.Fatalf("%+v count=%d", p, count)
	}
}
