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

func TestSSEAggregation(t *testing.T) {
	for _, tt := range []struct {
		name   string
		format string
	}{{"openai", "openai-chat-completions"}, {"anthropic", "anthropic-messages"}, {"responses", "openai-responses"}} {
		t.Run(tt.name, func(t *testing.T) {
			input, err := os.ReadFile("testdata/" + tt.name + ".sse")
			if err != nil {
				t.Fatal(err)
			}
			golden, err := os.ReadFile("testdata/" + tt.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var want any
			if err := json.Unmarshal(golden, &want); err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{1, 2, 7, 128, len(input)} {
				a, status := New(
					Config{Format: tt.format, Response: true, MaxCaptureBytes: len(input)},
					map[string]string{"content-type": "text/event-stream"},
				)
				if status != capturestatus.Incomplete {
					t.Fatal(status)
				}
				var observations []Observation
				emit := func(obs Observation) { observations = append(observations, obs) }
				for at := 0; at < len(input); at += size {
					p := a.Feed(input[at:min(at+size, len(input))], false, emit)
					if p.Status != capturestatus.Incomplete || len(observations) != 0 {
						t.Fatalf("size=%d at=%d premature: %+v", size, at, p)
					}
				}
				p := a.Feed(nil, true, emit)
				if p.Status != capturestatus.Complete || len(observations) != 1 {
					t.Fatalf("size=%d progress=%+v observations=%v", size, p, observations)
				}
				encoded, err := json.Marshal(observations[0].Content)
				if err != nil {
					t.Fatal(err)
				}
				var got any
				if err := json.Unmarshal(encoded, &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("size=%d got=%s want=%s", size, encoded, golden)
				}
			}
		})
	}
}

func TestSSEFailures(t *testing.T) {
	openai, err := os.ReadFile("testdata/openai.sse")
	if err != nil {
		t.Fatal(err)
	}
	anthropic, err := os.ReadFile("testdata/anthropic.sse")
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name   string
		format string
		body   string
		status capturestatus.Code
	}{
		{"openai-negative-index", "openai-chat-completions", strings.ReplaceAll(string(openai), `"index":0`, `"index":-1`), capturestatus.InvalidContent},
		{"openai-truncated-end", "openai-chat-completions", strings.TrimSuffix(string(openai), "\n\n"), capturestatus.IncompleteStream},
		{"anthropic-sparse-index", "anthropic-messages", strings.ReplaceAll(string(anthropic), `"index":0`, `"index":2147483647`), capturestatus.InvalidContent},
		{"anthropic-invalid-tool-json", "anthropic-messages", strings.ReplaceAll(string(anthropic), `"partial_json":"`, `"partial_json":"!`), capturestatus.InvalidContent},
		{"openai-eof", "openai-chat-completions", "data: {\"model\":\"x\",\"choices\":[]}\n\n", capturestatus.IncompleteStream},
		{"openai-invalid-json", "openai-chat-completions", "data: {\n\n", capturestatus.InvalidJSON},
		{"openai-unknown-then-malformed-choice", "openai-chat-completions", "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"future\":true}},{}]}\n\n", capturestatus.InvalidContent},
		{"openai-empty", "openai-chat-completions", "data: [DONE]\n\n", capturestatus.InvalidContent},
		{"anthropic-eof", "anthropic-messages", "event: ping\ndata: {\"type\":\"ping\"}\n\n", capturestatus.IncompleteStream},
		{"anthropic-wrong-event", "anthropic-messages", "event: ping\ndata: {\"type\":\"message_stop\"}\n\n", capturestatus.InvalidContent},
		{"anthropic-delta-before-start", "anthropic-messages", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0}\n\n", capturestatus.InvalidContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, size := range []int{1, len(tt.body)} {
				a, status := New(
					Config{Format: tt.format, Response: true, MaxCaptureBytes: 4096},
					map[string]string{"content-type": "text/event-stream"},
				)
				if status != capturestatus.Incomplete {
					t.Fatal(status)
				}
				for at := 0; at < len(tt.body); at += size {
					p := a.Feed(
						[]byte(tt.body[at:min(at+size, len(tt.body))]),
						at+size >= len(tt.body),
						func(Observation) { t.Fatal("emitted broken stream") },
					)
					status = p.Status
					if status != capturestatus.Incomplete {
						break
					}
				}
				if status != tt.status {
					t.Fatalf("got %s want %s", status, tt.status)
				}
			}
		})
	}
}

func TestStreamErrorsAndCaptureBudget(t *testing.T) {
	for _, format := range []string{"openai-chat-completions", "anthropic-messages"} {
		prefix := ""
		if format == "anthropic-messages" {
			prefix = "event: error\n"
		}
		data := prefix + "data: {\"type\":\"error\",\"error\":{\"message\":\"failed\"}}\n\n"
		a, _ := New(
			Config{Format: format, Response: true, MaxCaptureBytes: 4096},
			map[string]string{"content-type": "text/event-stream"},
		)
		var obs Observation
		p := a.Feed([]byte(data), true, func(v Observation) { obs = v })
		if p.Status != capturestatus.Complete || obs.Content.(*LLMView).Error == nil {
			t.Fatalf("%s: %+v", format, p)
		}
		a, _ = New(
			Config{Format: format, Response: true, MaxCaptureBytes: 8},
			map[string]string{"content-type": "text/event-stream"},
		)
		p = a.Feed([]byte(strings.Repeat(": ping", 100)), true, func(Observation) { t.Fatal("budget exceeded") })
		if p.Status != capturestatus.TooLarge {
			t.Fatal(p)
		}
	}
}

func TestSSEErrorThenDone(t *testing.T) {
	input := "data: {\"error\":{\"message\":\"failed\"}}\n\ndata: [DONE]\n\n"
	for _, size := range []int{1, len(input)} {
		a, _ := New(
			Config{Format: "openai-chat-completions", Response: true, MaxCaptureBytes: 4096},
			map[string]string{"content-type": "text/event-stream"},
		)
		count := 0
		for at := 0; at < len(input); at += size {
			p := a.Feed([]byte(input[at:min(at+size, len(input))]), at+size >= len(input), func(obs Observation) {
				count++
				view := obs.Content.(*LLMView)
				if view.Error == nil || !reflect.DeepEqual(*view.Error, map[string]any{"message": "failed"}) {
					t.Fatalf("lost error: %+v", view)
				}
			})
			want := capturestatus.Incomplete
			if at+size >= len(input) {
				want = capturestatus.Complete
			}
			if p.Status != want {
				t.Fatal(p)
			}
		}
		if count != 1 {
			t.Fatalf("observations=%d", count)
		}
	}
	a, _ := New(
		Config{Format: "openai-chat-completions", Response: true, MaxCaptureBytes: 4096},
		map[string]string{"content-type": "text/event-stream"},
	)
	p := a.Feed(
		[]byte(input+"data: {\"model\":\"m\",\"choices\":[]}\n\n"),
		true,
		func(Observation) { t.Fatal("accepted content after DONE") },
	)
	if p.Status != capturestatus.InvalidContent {
		t.Fatal(p)
	}
}

func TestSSEUnknownContentKeepsMetadata(t *testing.T) {
	openai, err := os.ReadFile("testdata/openai.sse")
	if err != nil {
		t.Fatal(err)
	}
	anthropic, err := os.ReadFile("testdata/anthropic.sse")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		format string
		input  string
		model  string
		tokens float64
	}{
		{"openai-delta", "openai-chat-completions", strings.ReplaceAll(string(openai), `"content":`, `"future_delta":`), "test-model", 8},
		{"openai-custom-tool", "openai-chat-completions", strings.ReplaceAll(string(openai), `"type":"function"`, `"type":"custom","custom":{"input":"ls"}`), "test-model", 8},
		{"openai-tool-field", "openai-chat-completions", strings.ReplaceAll(string(openai), `"type":"function"`, `"type":"function","future":true`), "test-model", 8},
		{"openai-function-field", "openai-chat-completions", strings.ReplaceAll(string(openai), `"name":"lookup"`, `"name":"lookup","future":true`), "test-model", 8},
		{"anthropic-delta", "anthropic-messages", strings.ReplaceAll(string(anthropic), `"text_delta"`, `"future_delta"`), "test-claude", 7},
		{"anthropic-event", "anthropic-messages", strings.ReplaceAll(string(anthropic), `ping`, `future_event`), "test-claude", 7},
		{"anthropic-metadata-delta", "anthropic-messages", strings.ReplaceAll(string(anthropic), `"stop_sequence":null`, `"stop_sequence":null,"future_field":true`), "test-claude", 7},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, captureMessages := range []bool{false, true} {
				for _, size := range []int{1, 17, len(tt.input)} {
					fields := CaptureFields{OutputMessages: captureMessages}
					a, _ := New(
						Config{Format: tt.format, Response: true, MaxCaptureBytes: 4096, Fields: &fields},
						map[string]string{"content-type": "text/event-stream"},
					)
					count := 0
					for at := 0; at < len(tt.input); at += size {
						p := a.Feed(
							[]byte(tt.input[at:min(at+size, len(tt.input))]),
							at+size >= len(tt.input),
							func(obs Observation) {
								count++
								v := obs.Content.(*LLMView)
								if !obs.Partial || !v.Partial || v.OutputMessages != nil || v.Model == nil ||
									*v.Model != tt.model ||
									v.Usage == nil {
									t.Fatalf("lost metadata or claimed full coverage: %+v", v)
								}
								tokens := v.Usage.OutputTokens
								if tt.format == "openai-chat-completions" {
									tokens = v.Usage.TotalTokens
								}
								if tokens == nil || *tokens != tt.tokens {
									t.Fatalf("lost final usage: %+v", v.Usage)
								}
							},
						)
						want := capturestatus.Incomplete
						if at+size >= len(tt.input) {
							want = capturestatus.Complete
						}
						if p.Status != want {
							t.Fatalf("size=%d progress=%+v", size, p)
						}
					}
					if count != 1 || a.retention.enabled || !a.contentDiscarded {
						t.Fatalf("count=%d retained=%+v", count, a.retention)
					}
				}
			}
		})
	}
}

func TestSSEPartialDoesNotHideMalformedData(t *testing.T) {
	prefix := "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"future\":true}}]}\n\n"
	for _, tail := range []string{"", "data: {\n\n"} {
		a, _ := New(
			Config{Format: "openai-chat-completions", Response: true, MaxCaptureBytes: 4096},
			map[string]string{"content-type": "text/event-stream"},
		)
		count := 0
		p := a.Feed([]byte(prefix+tail), true, func(obs Observation) {
			count++
			if !obs.Partial {
				t.Fatal("claimed full coverage without DONE")
			}
		})
		if tail == "" {
			if p.Status != capturestatus.Complete || count != 1 {
				t.Fatalf("%+v count=%d", p, count)
			}
		} else if p.Status != capturestatus.InvalidJSON || count != 0 {
			t.Fatalf("%+v count=%d", p, count)
		}
	}
}

func TestChatUnknownToolDoesNotHideInvalidFields(t *testing.T) {
	for _, delta := range []string{
		`{"tool_calls":[{"index":0,"future":true},{"index":-1}]}`,
		`{"tool_calls":[{"index":0,"future":true,"function":{"name":42}}]}`,
		`{"tool_calls":[{"index":0,"future":true}],"function_call":{"arguments":42}}`,
	} {
		for _, enabled := range []bool{false, true} {
			fields := CaptureFields{OutputMessages: enabled}
			a, _ := New(
				Config{Format: "openai-chat-completions", Response: true, MaxCaptureBytes: 4096, Fields: &fields},
				map[string]string{"content-type": "text/event-stream"},
			)
			input := `data: {"model":"m","choices":[{"index":0,"delta":` + delta + `}]}` + "\n\n"
			p := a.Feed([]byte(input), true, func(Observation) { t.Fatal("accepted malformed tool delta") })
			if p.Status != capturestatus.InvalidContent {
				t.Fatalf("enabled=%v delta=%s progress=%+v", enabled, delta, p)
			}
		}
	}
}
