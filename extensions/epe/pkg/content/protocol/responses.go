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

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

const responsesFormat = "openai-responses"

func responsesView(raw []byte, response bool, fields CaptureFields) (*LLMView, capturestatus.Code) {
	var doc responsesDocument
	if code := decodeObject(raw, &doc); code != capturestatus.Complete {
		return nil, code
	}
	if response {
		return responsesOutputView(&doc, fields)
	}
	view := &LLMView{Format: responsesFormat, Model: doc.Model}
	values, array := rawArray(doc.Input)
	text, stringOK := rawString(doc.Input)
	if !isNull(doc.Input) && !array && !stringOK {
		return nil, capturestatus.InvalidContent
	}
	if fields.InputMessages {
		view.InputMessages = make([]Message, 0)
		if doc.Instructions != nil {
			view.InputMessages = append(
				view.InputMessages,
				Message{Role: "system", Content: plainText(*doc.Instructions)},
			)
		}
		if text != nil {
			view.InputMessages = append(view.InputMessages, Message{Role: "user", Content: plainText(*text)})
		}
		if array {
			messages, code := responsesItems(values, false)
			if code != capturestatus.Complete {
				return nil, code
			}
			view.InputMessages = append(view.InputMessages, messages...)
		}
	}
	if fields.Tools && doc.Tools != nil {
		tools, code := toolDefinitions(doc.Tools, responsesFormat)
		if code != capturestatus.Complete {
			return nil, code
		}
		view.Tools = &tools
	}
	return view, capturestatus.Complete
}
func plainText(text string) []ContentBlock {
	content := make([]ContentBlock, 0)
	if text != "" {
		content = append(content, TextBlock{Type: "text", Text: text})
	}
	return content
}
func responsesMetadata(doc *responsesDocument) (*LLMView, capturestatus.Code) {
	view := &LLMView{
		Format: responsesFormat,
		Model:  doc.Model,
		Status: doc.Status,
		Usage:  decodeUsage(doc.Usage, false, true),
	}
	if !isNull(doc.Error) {
		value := rawValue(doc.Error)
		view.Error = &value
	}
	if doc.Model == nil && view.Error == nil {
		return nil, capturestatus.InvalidContent
	}
	if isObject(doc.IncompleteDetails) {
		var details struct {
			Reason *string `json:"reason"`
		}
		if decodeObject(doc.IncompleteDetails, &details) != capturestatus.Complete {
			return nil, capturestatus.InvalidContent
		}
		view.IncompleteReason = details.Reason
	}
	return view, capturestatus.Complete
}
func responsesOutputView(doc *responsesDocument, fields CaptureFields) (*LLMView, capturestatus.Code) {
	view, code := responsesMetadata(doc)
	if code != capturestatus.Complete {
		return nil, code
	}
	output, ok := rawArray(doc.Output)
	if !ok && view.Error == nil {
		return nil, capturestatus.InvalidContent
	}
	if fields.OutputMessages && ok {
		view.OutputMessages, code = responsesItems(output, true)
	}
	return view, code
}
func responsesItems(items []json.RawMessage, output bool) ([]Message, capturestatus.Code) {
	result := make([]Message, 0, len(items))
	for index, raw := range items {
		message, code := responsesItem(raw)
		if code != capturestatus.Complete {
			return nil, code
		}
		if output {
			message.Index = &index
		}
		result = append(result, message)
	}
	return result, capturestatus.Complete
}
func responsesItem(raw json.RawMessage) (Message, capturestatus.Code) {
	var tag struct {
		Type *string `json:"type"`
	}
	if decodeObject(raw, &tag) != capturestatus.Complete {
		return Message{}, capturestatus.InvalidContent
	}
	if tag.Type != nil && *tag.Type != "message" && *tag.Type != "function_call" &&
		*tag.Type != "function_call_output" {
		return Message{
			Role:    "assistant",
			Content: []ContentBlock{providerBlock(rawValue(raw), responsesFormat)},
		}, capturestatus.Complete
	}
	var item responsesItemWire
	if decodeObject(raw, &item) != capturestatus.Complete {
		return Message{}, capturestatus.InvalidContent
	}
	if item.Type == nil || *item.Type == "message" {
		if item.Role == nil {
			return Message{}, capturestatus.InvalidContent
		}
		content, code := responsesBlocks(item.Content)
		return Message{Role: *item.Role, Content: content}, code
	}
	switch *item.Type {
	case "function_call":
		if item.CallID == nil || item.Name == nil || item.Arguments == nil {
			return Message{}, capturestatus.InvalidContent
		}
		return Message{
			Role:    "assistant",
			Content: []ContentBlock{newToolCall(item.CallID, item.Name, *item.Arguments)},
		}, capturestatus.Complete
	case "function_call_output":
		if item.CallID == nil {
			return Message{}, capturestatus.InvalidContent
		}
		content, code := responsesBlocks(item.Output)
		return Message{
			Role:    "tool",
			Content: []ContentBlock{ToolResultBlock{Type: "tool_result", ToolCallID: item.CallID, Content: content}},
		}, code
	default:
		return Message{
			Role:    "assistant",
			Content: []ContentBlock{providerBlock(rawValue(raw), responsesFormat)},
		}, capturestatus.Complete
	}
}
func responsesBlocks(raw json.RawMessage) ([]ContentBlock, capturestatus.Code) {
	if text, ok := rawString(raw); ok && text != nil {
		return plainText(*text), capturestatus.Complete
	}
	values, ok := rawArray(raw)
	if !ok {
		return nil, capturestatus.InvalidContent
	}
	result := make([]ContentBlock, 0, len(values))
	for _, raw := range values {
		var tag struct {
			Type json.RawMessage `json:"type"`
		}
		if decodeObject(raw, &tag) != capturestatus.Complete {
			return nil, capturestatus.InvalidContent
		}
		switch rawValue(tag.Type) {
		case "input_text", "output_text", "refusal":
			var b struct {
				Text    *string `json:"text"`
				Refusal *string `json:"refusal"`
			}
			if decodeObject(raw, &b) != capturestatus.Complete {
				return nil, capturestatus.InvalidContent
			}
			text, kind, key := b.Text, "text", "text"
			if rawValue(tag.Type) == "refusal" {
				text, kind, key = b.Refusal, "refusal", "refusal"
			}
			if text == nil {
				return nil, capturestatus.InvalidContent
			}
			result = append(result, textBlock(raw, kind, *text, key))
		default:
			result = append(result, providerBlock(rawValue(raw), responsesFormat))
		}
	}
	return result, capturestatus.Complete
}
