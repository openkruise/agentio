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
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/content/decoder"
	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

func TestTypedProtocolPresenceAndValidation(t *testing.T) {
	for _, index := range []string{"", "null", "-1", "0.5", "2147483648", `"0"`, "0", "0.0", "0e0"} {
		t.Run(index, func(t *testing.T) {
			field := ""
			if index != "" {
				field = `"index":` + index + `,`
			}
			input := `{"model":"m","choices":[{` + field + `"message":{"role":"assistant","content":"ok"}}]}`
			a, _ := New(
				Config{Format: "openai-chat-completions", Response: true, MaxCaptureBytes: 4096},
				map[string]string{"content-type": "application/json"},
			)
			count := 0
			p := a.Feed([]byte(input), true, func(obs Observation) {
				count++
				if *obs.Content.(*LLMView).OutputMessages[0].Index != 0 {
					t.Fatal("wrong index")
				}
			})
			valid := index == "0" || index == "0.0" || index == "0e0"
			if valid {
				if p.Status != capturestatus.Complete || count != 1 {
					t.Fatal(p)
				}
			} else if p.Status != capturestatus.InvalidContent || count != 0 {
				t.Fatal(p)
			}
		})
	}
	for _, tt := range []struct {
		name   string
		field  string
		exists bool
		null   bool
	}{
		{"absent", "", false, false}, {"null", `,"tools":null`, true, true}, {"empty", `,"tools":[]`, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := New(
				Config{Format: "openai-chat-completions", MaxCaptureBytes: 4096},
				map[string]string{"content-type": "application/json"},
			)
			p := a.Feed([]byte(`{"model":"m","messages":[]`+tt.field+`}`), true, func(obs Observation) {
				v := jsonValue(t, obs.Content).(map[string]any)
				tools, exists := v["tools"]
				if exists != tt.exists || exists && (tools == nil) != tt.null {
					t.Fatalf("view=%+v", v)
				}
			})
			if p.Status != capturestatus.Complete {
				t.Fatal(p)
			}
		})
	}
}

func TestTypedProtocolPreservesOpaqueFields(t *testing.T) {
	for _, tt := range []struct {
		format string
		body   string
		want   string
	}{
		{"openai-responses", `{"model":"m","input":[{"type":"future_item","arguments":{"nested":1},"name":42}]}`, `{"type":"future_item","arguments":{"nested":1},"name":42}`},
		{"anthropic-messages", `{"model":"m","messages":[{"role":"user","tool_call_id":42,"content":[{"type":"text","text":"hi","id":42,"cache_control":{"type":"ephemeral"}}]}]}`, `{"type":"text","text":"hi","id":42,"cache_control":{"type":"ephemeral"}}`},
		{"openai-chat-completions", `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":42,"custom":{"x":true}}]}]}`, `{"id":42,"custom":{"x":true}}`},
	} {
		t.Run(tt.format, func(t *testing.T) {
			a, _ := New(
				Config{Format: tt.format, MaxCaptureBytes: 4096},
				map[string]string{"content-type": "application/json"},
			)
			var got any
			p := a.Feed([]byte(tt.body), true, func(obs Observation) {
				block := obs.Content.(*LLMView).InputMessages[0].Content[0]
				if provider, ok := block.(ProviderBlock); ok {
					got = provider.Data
				} else {
					got = jsonValue(t, block)
				}
			})
			var want any
			if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatal(err)
			}
			if p.Status != capturestatus.Complete || !reflect.DeepEqual(got, want) {
				t.Fatalf("progress=%+v got=%+v want=%+v", p, got, want)
			}
		})
	}
}

func TestTypedUnknownSSEDoesNotValidateAnotherEventShape(t *testing.T) {
	for _, tt := range []struct {
		format string
		input  string
	}{
		{"openai-responses", responsesEvent("response.future", map[string]any{"output_index": "opaque", "delta": map[string]any{"future": true}})},
		{"anthropic-messages", "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"m\",\"content\":[]}}\n\nevent: future\ndata: {\"type\":\"future\",\"index\":\"opaque\"}\n\n"},
	} {
		t.Run(tt.format, func(t *testing.T) {
			a, _ := New(
				Config{Format: tt.format, Response: true, MaxCaptureBytes: 4096},
				map[string]string{"content-type": "text/event-stream"},
			)
			count := 0
			p := a.Feed([]byte(tt.input), true, func(obs Observation) {
				count++
				if !obs.Partial {
					t.Fatal("unknown event reported complete coverage")
				}
			})
			if p.Status != capturestatus.Complete || count != 1 {
				t.Fatalf("%+v count=%d", p, count)
			}
		})
	}
}

func TestTypedUsageRetainsMissingAndZero(t *testing.T) {
	usage := decodeUsage(
		json.RawMessage(
			`{"prompt_tokens":0,"completion_tokens":null,"total_tokens":"bad","prompt_tokens_details":{"cached_tokens":0},"extension":[1]}`,
		),
		false,
		false,
	)
	if usage.InputTokens == nil || *usage.InputTokens != 0 || usage.OutputTokens != nil || usage.TotalTokens != nil ||
		usage.CachedInputTokens == nil {
		t.Fatalf("usage=%+v", usage)
	}
	raw := json.RawMessage(`{"input_tokens":5,"output_tokens":2,"cache_read_input_tokens":10}`)
	base := decodeUsage(raw, true, false)
	for range 2 {
		view := anthropicUsage(base)
		if *view.InputTokens != 15 || *base.InputTokens != 5 {
			t.Fatal("normalization mutated counters")
		}
	}
}

func TestTypedDecoderKeepsJSONFailureClassification(t *testing.T) {
	for _, tt := range []struct {
		body   string
		status capturestatus.Code
	}{
		{`{`, capturestatus.InvalidJSON}, {`{} {}`, capturestatus.InvalidJSON}, {`null`, capturestatus.InvalidContent},
		{`[]`, capturestatus.InvalidContent}, {`{"model":4,"messages":[]}`, capturestatus.InvalidContent},
	} {
		for _, format := range []string{"openai-chat-completions", "anthropic-messages", "openai-responses"} {
			a, _ := New(
				Config{Format: format, MaxCaptureBytes: 4096},
				map[string]string{"content-type": "application/json"},
			)
			p := a.Feed([]byte(tt.body), true, func(Observation) { t.Fatal("invalid document emitted") })
			if p.Status != tt.status {
				t.Fatalf("%s %s: %s", format, tt.body, p.Status)
			}
		}
	}
	// An unknown non-null Chat delta still produces partial, including after known text.
	a, _ := New(
		Config{Format: "openai-chat-completions", Response: true, MaxCaptureBytes: 4096},
		map[string]string{"content-type": "text/event-stream"},
	)
	input := `{"model":"m","choices":[{"index":0,"delta":{"content":"hi","future":{}},"finish_reason":"stop"}]}`
	p := a.Feed([]byte("data: "+input+"\n\ndata: [DONE]\n\n"), true, func(obs Observation) {
		if !obs.Partial || !strings.Contains(string(mustJSON(t, obs.Content)), `"partial":true`) {
			t.Fatal(obs)
		}
	})
	if p.Status != capturestatus.Complete {
		t.Fatal(p)
	}
}
func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTypedStreamingPreservesErrorAndToolResult(t *testing.T) {
	chat := &chatStream{retained: &retention{enabled: true, limit: 4096}}
	code := chat.add(decoder.Event{Data: `{"error":{"message":"failed"},"model":42}`})
	view, finish := chat.finish()
	if code != capturestatus.Unset || finish != capturestatus.Complete || view.Error == nil {
		t.Fatalf("add=%s finish=%s view=%+v", code, finish, view)
	}
	raw := json.RawMessage(`{"type":"tool_result","tool_use_id":"c1","content":"result","is_error":true}`)
	block := &anthropicBlock{kind: "tool_result", source: raw}
	if got, want := jsonValue(
		t,
		block.content(),
	), jsonValue(
		t,
		normalizeBlock(raw, "anthropic-messages"),
	); !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
}
