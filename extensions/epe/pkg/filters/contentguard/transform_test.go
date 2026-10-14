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
	"reflect"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/content/protocol"
)

func TestTransformationCaptureRequirements(t *testing.T) {
	all := protocol.CaptureFields{InputMessages: true, OutputMessages: true, Tools: true}
	for _, tt := range []struct {
		expression string
		want       protocol.CaptureFields
	}{
		{"content", all},
		{"{'model':content.model, 'usage':has(content.usage) ? content.usage : null}", protocol.CaptureFields{}},
		{"content['model']", protocol.CaptureFields{}},
		{"has(content.partial)", all},
		{"has(content.truncated)", all},
		{"[content.status, content.incompleteReason]", protocol.CaptureFields{}},
		{"content[request.method]", all},
		{"[content][0]", all},
		{"cel.bind(view, content, view.model)", all},
		{"content.inputMessages.map(m, m.role)", protocol.CaptureFields{InputMessages: true}},
		{"has(content.outputMessages)", protocol.CaptureFields{OutputMessages: true}},
		{"content['tools']", protocol.CaptureFields{Tools: true}},
		{"{'input':content.inputMessages, 'output':content.outputMessages}", protocol.CaptureFields{InputMessages: true, OutputMessages: true}},
		{"{content.model:content.tools}", protocol.CaptureFields{Tools: true}},
	} {
		t.Run(tt.expression, func(t *testing.T) {
			_, got, err := compileTransformation(tt.expression)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %+v want %+v", got, tt.want)
			}
		})
	}
}

func TestTypedViewTransformationPresence(t *testing.T) {
	zero := float64(0)
	index := 0
	empty := ""
	var null any
	var nullTools []protocol.ToolDefinition
	emptyTools := []protocol.ToolDefinition{}
	for _, tt := range []struct {
		name       string
		view       *protocol.LLMView
		expression string
		want       any
	}{
		{
			name:       "missing-and-empty",
			view:       &protocol.LLMView{Format: "openai-chat-completions", Model: &empty, InputMessages: []protocol.Message{}, Tools: &emptyTools},
			expression: "has(content.inputMessages) && size(content.inputMessages) == 0 && !has(content.outputMessages) && has(content.tools) && size(content.tools) == 0 && has(content.model) && content.model == ''",
			want:       true,
		},
		{
			name:       "null-tools",
			view:       &protocol.LLMView{Tools: &nullTools},
			expression: "has(content.tools) && content.tools == null",
			want:       true,
		},
		{
			name:       "absent-tools",
			view:       &protocol.LLMView{},
			expression: "!has(content.tools) && !has(content.error) && !has(content.model)",
			want:       true,
		},
		{
			name:       "zero-usage",
			view:       &protocol.LLMView{Usage: &protocol.Usage{OutputTokens: &zero}},
			expression: "has(content.usage.outputTokens) && content.usage.outputTokens == 0.0 && !has(content.usage.inputTokens)",
			want:       true,
		},
		{
			name:       "null-error",
			view:       &protocol.LLMView{Error: &null},
			expression: "has(content.error) && content.error == null && !has(content.model)",
			want:       true,
		},
		{
			name:       "zero-index-and-false-tool-result",
			view:       &protocol.LLMView{OutputMessages: []protocol.Message{{Index: &index, Role: "assistant", FinishReason: &empty, Content: []protocol.ContentBlock{protocol.ToolResultBlock{Type: "tool_result", Content: []protocol.ContentBlock{}}}}}},
			expression: "cel.bind(m, content.outputMessages[0], has(m.index) && m.index == 0.0 && has(m.finishReason) && m.finishReason == '' && has(m.content[0].isError) && !m.content[0].isError && m.content[0].toolCallId == null && size(m.content[0].content) == 0)",
			want:       true,
		},
		{
			name:       "complete-view",
			view:       &protocol.LLMView{Format: "openai-chat-completions", InputMessages: []protocol.Message{}, Truncated: true},
			expression: "content",
			want:       map[string]any{"format": "openai-chat-completions", "inputMessages": []any{}, "truncated": true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			program, _, err := compileTransformation(tt.expression)
			if err != nil {
				t.Fatal(err)
			}
			got, err := transformContent(program, tt.view, nil, 16384)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got=%+v err=%v want=%+v", got, err, tt.want)
			}
		})
	}
}
