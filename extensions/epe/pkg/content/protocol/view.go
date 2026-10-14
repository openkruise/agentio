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
	"sort"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

// CaptureFields selects expensive content before normalization or aggregation.
type CaptureFields struct {
	InputMessages  bool
	OutputMessages bool
	Tools          bool
}

func allFields() CaptureFields { return CaptureFields{true, true, true} }

func llmView(raw []byte, format string, response bool, fields CaptureFields) (*LLMView, capturestatus.Code) {
	if format == responsesFormat {
		return responsesView(raw, response, fields)
	}
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if code := decodeObject(raw, &envelope); code != capturestatus.Complete {
		return nil, code
	}
	if response && envelope.Error != nil {
		value := rawValue(envelope.Error)
		return &LLMView{Format: format, Error: &value}, capturestatus.Complete
	}
	if format == "anthropic-messages" {
		return anthropicView(raw, response, fields)
	}
	var doc chatDocument
	if code := decodeObject(raw, &doc); code != capturestatus.Complete {
		return nil, code
	}
	if doc.Model == nil {
		return nil, capturestatus.InvalidContent
	}
	view := &LLMView{Format: format, Model: doc.Model}
	if !response {
		return requestView(view, doc.Messages, doc.System, doc.Tools, fields)
	}
	view.Usage = decodeUsage(doc.Usage, false, false)
	choices, ok := rawArray(doc.Choices)
	if !ok {
		return nil, capturestatus.InvalidContent
	}
	if fields.OutputMessages {
		view.OutputMessages = make([]Message, 0, len(choices))
		for _, raw := range choices {
			var choice chatChoiceWire
			if decodeObject(raw, &choice) != capturestatus.Complete || choice.Index == nil {
				return nil, capturestatus.InvalidContent
			}
			message, code := messageView(choice.Message, format)
			if code != capturestatus.Complete {
				return nil, code
			}
			index := int(*choice.Index)
			message.Index, message.FinishReason = &index, choice.FinishReason
			view.OutputMessages = append(view.OutputMessages, message)
		}
		sort.SliceStable(
			view.OutputMessages,
			func(i, j int) bool { return *view.OutputMessages[i].Index < *view.OutputMessages[j].Index },
		)
	}
	return view, capturestatus.Complete
}

func anthropicView(raw []byte, response bool, fields CaptureFields) (*LLMView, capturestatus.Code) {
	var doc anthropicDocument
	if code := decodeObject(raw, &doc); code != capturestatus.Complete {
		return nil, code
	}
	if doc.Model == nil {
		return nil, capturestatus.InvalidContent
	}
	view := &LLMView{Format: "anthropic-messages", Model: doc.Model}
	if !response {
		return requestView(view, doc.Messages, doc.System, doc.Tools, fields)
	}
	view.Usage = anthropicUsage(decodeUsage(doc.Usage, true, false))
	if _, ok := rawArray(doc.Content); !ok {
		return nil, capturestatus.InvalidContent
	}
	if fields.OutputMessages {
		index := 0
		view.OutputMessages = []Message{
			{Index: &index, Role: "assistant", Content: blocks(doc.Content, view.Format), FinishReason: doc.StopReason},
		}
	}
	return view, capturestatus.Complete
}

func requestView(
	view *LLMView,
	messages, system, tools json.RawMessage,
	fields CaptureFields,
) (*LLMView, capturestatus.Code) {
	values, ok := rawArray(messages)
	if !ok {
		return nil, capturestatus.InvalidContent
	}
	if fields.InputMessages {
		view.InputMessages = make([]Message, 0, len(values))
		if !isNull(system) {
			view.InputMessages = append(
				view.InputMessages,
				Message{Role: "system", Content: blocks(system, view.Format)},
			)
		}
		for _, value := range values {
			message, code := messageView(value, view.Format)
			if code != capturestatus.Complete {
				return nil, code
			}
			view.InputMessages = append(view.InputMessages, message)
		}
	}
	if fields.Tools && tools != nil {
		definitions, code := toolDefinitions(tools, view.Format)
		if code != capturestatus.Complete {
			return nil, code
		}
		view.Tools = &definitions
	}
	return view, capturestatus.Complete
}

func messageView(raw json.RawMessage, format string) (Message, capturestatus.Code) {
	if format == "anthropic-messages" {
		var wire struct {
			Role    *string         `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if decodeObject(raw, &wire) != capturestatus.Complete || wire.Role == nil {
			return Message{}, capturestatus.InvalidContent
		}
		return Message{Role: *wire.Role, Content: blocks(wire.Content, format)}, capturestatus.Complete
	}
	var wire chatMessage
	if decodeObject(raw, &wire) != capturestatus.Complete || wire.Role == nil {
		return Message{}, capturestatus.InvalidContent
	}
	content := blocks(wire.Content, format)
	if format == "openai-chat-completions" {
		if *wire.Role == "tool" {
			content = []ContentBlock{
				ToolResultBlock{Type: "tool_result", ToolCallID: wire.ToolCallID, Content: content},
			}
		}
		if calls, ok := rawArray(wire.ToolCalls); ok {
			for _, raw := range calls {
				var header struct {
					Function json.RawMessage `json:"function"`
				}
				if decodeObject(raw, &header) != capturestatus.Complete {
					return Message{}, capturestatus.InvalidContent
				}
				if !isObject(header.Function) {
					content = append(content, providerBlock(rawValue(raw), format))
					continue
				}
				var call toolWire
				if decodeObject(raw, &call) != capturestatus.Complete {
					return Message{}, capturestatus.InvalidContent
				}
				var fn functionWire
				if decodeObject(call.Function, &fn) != capturestatus.Complete {
					return Message{}, capturestatus.InvalidContent
				}
				content = append(content, newToolCall(call.ID, fn.Name, rawValue(fn.Arguments)))
			}
		}
		if isObject(wire.FunctionCall) {
			var fn functionWire
			if decodeObject(wire.FunctionCall, &fn) != capturestatus.Complete {
				return Message{}, capturestatus.InvalidContent
			}
			content = append(content, newToolCall(nil, fn.Name, rawValue(fn.Arguments)))
		}
		if refusal, ok := rawString(wire.Refusal); ok && refusal != nil && *refusal != "" {
			content = append(content, TextBlock{Type: "refusal", Text: *refusal})
		}
	}
	return Message{Role: *wire.Role, Content: content}, capturestatus.Complete
}

func blocks(raw json.RawMessage, format string) []ContentBlock {
	result := make([]ContentBlock, 0)
	if isNull(raw) {
		return result
	}
	if text, ok := rawString(raw); ok {
		if *text != "" {
			result = append(result, TextBlock{Type: "text", Text: *text})
		}
		return result
	}
	values, ok := rawArray(raw)
	if !ok {
		return append(result, providerBlock(rawValue(raw), format))
	}
	for _, raw := range values {
		result = append(result, normalizeBlock(raw, format)...)
	}
	return result
}

type toolUseWire struct {
	ID    *string         `json:"id"`
	Name  *string         `json:"name"`
	Input json.RawMessage `json:"input"`
}

func normalizeBlock(raw json.RawMessage, format string) []ContentBlock {
	var tag struct {
		Type *string `json:"type"`
	}
	if decodeObject(raw, &tag) == capturestatus.Complete && tag.Type != nil {
		switch *tag.Type {
		case "text":
			var b struct {
				Text *string `json:"text"`
			}
			if decodeObject(raw, &b) == capturestatus.Complete && b.Text != nil {
				if *b.Text == "" {
					return nil
				}
				return []ContentBlock{textBlock(raw, "text", *b.Text, "text")}
			}
		case "tool_use", "server_tool_use":
			var b toolUseWire
			if format == "anthropic-messages" && decodeObject(raw, &b) == capturestatus.Complete {
				call := newToolCall(b.ID, b.Name, rawValue(b.Input))
				call.Server = *tag.Type == "server_tool_use"
				return []ContentBlock{call}
			}
		case "tool_result":
			var b struct {
				ToolUseID *string         `json:"tool_use_id"`
				Content   json.RawMessage `json:"content"`
				IsError   json.RawMessage `json:"is_error"`
			}
			if decodeObject(raw, &b) == capturestatus.Complete {
				return []ContentBlock{
					ToolResultBlock{
						Type:       "tool_result",
						ToolCallID: b.ToolUseID,
						Content:    blocks(b.Content, format),
						IsError:    rawValue(b.IsError) == true,
					},
				}
			}
		}
	}
	return []ContentBlock{providerBlock(rawValue(raw), format)}
}
func textBlock(raw json.RawMessage, kind, text, key string) TextBlock {
	extensions, _ := rawValue(raw).(map[string]any)
	delete(extensions, "type")
	delete(extensions, key)
	return TextBlock{Type: kind, Text: text, Extensions: extensions}
}
func providerBlock(value any, format string) ProviderBlock {
	return ProviderBlock{Type: "provider_content", Format: format, Data: value}
}
func newToolCall(id, name *string, arguments any) ToolCallBlock {
	if raw, ok := arguments.(string); ok {
		var value any
		if json.Unmarshal([]byte(raw), &value) == nil {
			arguments = value
		}
	}
	return ToolCallBlock{Type: "tool_call", ID: id, Name: name, Arguments: arguments}
}

type toolDefinitionWire struct {
	Name        *string         `json:"name"`
	Description *string         `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
	InputSchema json.RawMessage `json:"input_schema"`
}

func toolDefinitions(raw json.RawMessage, format string) ([]ToolDefinition, capturestatus.Code) {
	if isNull(raw) {
		return nil, capturestatus.Complete
	}
	values, ok := rawArray(raw)
	if !ok {
		return nil, capturestatus.InvalidContent
	}
	result := make([]ToolDefinition, 0, len(values))
	for _, value := range values {
		var tag struct {
			Type     json.RawMessage `json:"type"`
			Function json.RawMessage `json:"function"`
		}
		source := value
		known := decodeObject(value, &tag) == capturestatus.Complete
		if format == "openai-chat-completions" {
			source = tag.Function
			known = known && isObject(source)
		}
		if format == "anthropic-messages" {
			known = known && (isNull(tag.Type) || rawValue(tag.Type) == "custom")
		}
		if format == responsesFormat {
			known = known && rawValue(tag.Type) == "function"
		}
		if !known {
			provider := providerBlock(rawValue(value), format)
			result = append(result, ToolDefinition{Provider: &provider})
			continue
		}
		var tool toolDefinitionWire
		if decodeObject(source, &tool) != capturestatus.Complete {
			return nil, capturestatus.InvalidContent
		}
		schema := tool.Parameters
		if format == "anthropic-messages" {
			schema = tool.InputSchema
		}
		result = append(
			result,
			ToolDefinition{Name: tool.Name, Description: tool.Description, Parameters: rawValue(schema)},
		)
	}
	return result, capturestatus.Complete
}
