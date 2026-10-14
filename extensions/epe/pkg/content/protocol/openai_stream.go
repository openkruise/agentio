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
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/content/decoder"
	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

type chatStream struct {
	retained *retention
	model    string
	choices  map[int]*chatChoice
	usage    *Usage
	apiError any
	done     bool
}
type chatChoice struct {
	retained     *retention
	role         string
	text         strings.Builder
	refusal      strings.Builder
	tools        map[int]*chatToolState
	legacy       *chatFunctionState
	finishReason *string
}
type chatFunctionState struct {
	name         strings.Builder
	arguments    strings.Builder
	nameSet      bool
	argumentsSet bool
}
type chatToolState struct {
	id       *string
	kind     *string
	function *chatFunctionState
}
type chatDelta struct {
	Role         *string         `json:"role"`
	Content      *string         `json:"content"`
	Refusal      *string         `json:"refusal"`
	ToolCalls    json.RawMessage `json:"tool_calls"`
	FunctionCall json.RawMessage `json:"function_call"`
}
type functionDelta struct {
	Name      json.RawMessage `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *chatStream) add(event decoder.Event) capturestatus.Code {
	if strings.TrimSpace(event.Data) == "[DONE]" && (!s.done || s.apiError != nil) {
		s.done = true
		return capturestatus.Unset
	}
	if s.done {
		return capturestatus.InvalidContent
	}
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if code := decodeEvent(event.Data, &envelope); code != capturestatus.Complete {
		return code
	}
	if envelope.Error != nil {
		s.apiError = rawValue(envelope.Error)
		s.done = true
		return capturestatus.Unset
	}
	var doc chatDocument
	if code := decodeEvent(event.Data, &doc); code != capturestatus.Complete {
		return code
	}
	if doc.Model == nil || s.model != "" && s.model != *doc.Model {
		return capturestatus.InvalidContent
	}
	s.model = *doc.Model
	if !isNull(doc.Usage) {
		s.usage = decodeUsage(doc.Usage, false, false)
		if s.usage == nil {
			s.usage = &Usage{}
		}
	}
	choices, ok := rawArray(doc.Choices)
	if !ok {
		return capturestatus.InvalidContent
	}
	if s.choices == nil {
		s.choices = make(map[int]*chatChoice)
	}
	status := capturestatus.Unset
	for _, raw := range choices {
		next := s.addChoice(raw)
		if next != capturestatus.Unset {
			if next != capturestatus.UnsupportedEvent {
				return next
			}
			status = next
		}
	}
	return status
}
func (s *chatStream) addChoice(raw json.RawMessage) capturestatus.Code {
	var choice chatChoiceWire
	if decodeObject(raw, &choice) != capturestatus.Complete || choice.Index == nil {
		return capturestatus.InvalidContent
	}
	index := int(*choice.Index)
	state := s.choices[index]
	if state == nil {
		if !s.retained.item() {
			return capturestatus.TooLarge
		}
		state = &chatChoice{retained: s.retained, role: "assistant", tools: make(map[int]*chatToolState)}
		s.choices[index] = state
	} else if state.finishReason != nil {
		return capturestatus.InvalidContent
	}
	status := state.addDelta(choice.Delta)
	if status != capturestatus.Unset && status != capturestatus.UnsupportedEvent {
		return status
	}
	if choice.FinishReason != nil {
		if len(*choice.FinishReason) > 256 {
			return capturestatus.InvalidContent
		}
		state.finishReason = choice.FinishReason
	}
	return status
}
func (c *chatChoice) addDelta(raw json.RawMessage) capturestatus.Code {
	var delta chatDelta
	if decodeObject(raw, &delta) != capturestatus.Complete {
		return capturestatus.InvalidContent
	}
	status := capturestatus.Unset
	if unknownFields(raw, true, "role", "content", "refusal", "tool_calls", "function_call") {
		status = capturestatus.UnsupportedEvent
	}
	if delta.Role != nil {
		if len(*delta.Role) > 64 {
			return capturestatus.InvalidContent
		}
		c.role = *delta.Role
	}
	if delta.Content != nil {
		c.retained.append(&c.text, *delta.Content)
	}
	if delta.Refusal != nil {
		c.retained.append(&c.refusal, *delta.Refusal)
	}
	if !isNull(delta.ToolCalls) {
		if next := c.addTools(delta.ToolCalls); next != capturestatus.Unset {
			if next != capturestatus.UnsupportedEvent {
				return next
			}
			status = next
		}
	}
	if !isNull(delta.FunctionCall) {
		if c.legacy == nil {
			c.legacy = &chatFunctionState{}
		}
		if !c.legacy.add(delta.FunctionCall, c.retained) {
			return capturestatus.InvalidContent
		}
		if unknownFields(delta.FunctionCall, false, "name", "arguments") {
			status = capturestatus.UnsupportedEvent
		}
	}
	return status
}
func (fn *chatFunctionState) add(raw json.RawMessage, retained *retention) bool {
	var delta functionDelta
	if decodeObject(raw, &delta) != capturestatus.Complete {
		return false
	}
	for _, field := range []struct {
		raw     json.RawMessage
		builder *strings.Builder
		set     *bool
	}{
		{delta.Name, &fn.name, &fn.nameSet}, {delta.Arguments, &fn.arguments, &fn.argumentsSet},
	} {
		if field.raw == nil {
			continue
		}
		value, ok := rawString(field.raw)
		if !ok || value == nil {
			return false
		}
		if retained.append(field.builder, *value) {
			*field.set = true
		}
	}
	return true
}
func (c *chatChoice) addTools(raw json.RawMessage) capturestatus.Code {
	tools, ok := rawArray(raw)
	if !ok {
		return capturestatus.InvalidContent
	}
	status := capturestatus.Unset
	for _, raw := range tools {
		var wire toolWire
		if decodeObject(raw, &wire) != capturestatus.Complete || wire.Index == nil {
			return capturestatus.InvalidContent
		}
		if unknownFields(raw, true, "index", "id", "type", "function") ||
			wire.Type != nil && *wire.Type != "function" ||
			unknownFields(wire.Function, false, "name", "arguments") {
			status = capturestatus.UnsupportedEvent
		}
		if !c.retained.enabled || c.retained.truncated {
			var function chatFunctionState
			if wire.Function != nil && !function.add(wire.Function, c.retained) {
				return capturestatus.InvalidContent
			}
			continue
		}
		index := int(*wire.Index)
		target := c.tools[index]
		if target == nil {
			if !c.retained.item() {
				return capturestatus.TooLarge
			}
			target = &chatToolState{}
			c.tools[index] = target
		}
		if !c.keepToolIdentity(target, &wire) {
			return capturestatus.InvalidContent
		}
		if wire.Function != nil {
			if target.function == nil {
				target.function = &chatFunctionState{}
			}
			if !target.function.add(wire.Function, c.retained) {
				return capturestatus.InvalidContent
			}
		}
	}
	return status
}
func (c *chatChoice) keepToolIdentity(target *chatToolState, wire *toolWire) bool {
	for _, field := range []struct {
		target **string
		value  *string
	}{{&target.id, wire.ID}, {&target.kind, wire.Type}} {
		if field.value == nil {
			continue
		}
		if *field.target != nil {
			if **field.target != *field.value {
				return false
			}
			continue
		}
		if c.retained.keep(*field.value) {
			*field.target = field.value
		}
	}
	return true
}
func (s *chatStream) finish() (*LLMView, capturestatus.Code) {
	if !s.done {
		return nil, capturestatus.IncompleteStream
	}
	view := s.metadata()
	if s.apiError != nil {
		return &LLMView{Format: view.Format, Error: view.Error}, capturestatus.Complete
	}
	if s.model == "" || len(s.choices) == 0 {
		return nil, capturestatus.InvalidContent
	}
	indices := make([]int, 0, len(s.choices))
	for index := range s.choices {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	view.OutputMessages = make([]Message, 0, len(indices))
	for _, index := range indices {
		choice := s.choices[index]
		if choice.finishReason == nil {
			return nil, capturestatus.IncompleteStream
		}
		view.OutputMessages = append(view.OutputMessages, choice.message(index))
	}
	return view, capturestatus.Complete
}
func (c *chatChoice) message(index int) Message {
	content := plainText(c.text.String())
	indices := make([]int, 0, len(c.tools))
	for i := range c.tools {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	for _, i := range indices {
		tool := c.tools[i]
		if tool.function != nil {
			content = append(content, tool.function.block(tool.id))
		} else {
			raw := make(map[string]any)
			if tool.id != nil {
				raw["id"] = *tool.id
			}
			if tool.kind != nil {
				raw["type"] = *tool.kind
			}
			content = append(content, providerBlock(raw, "openai-chat-completions"))
		}
	}
	if c.legacy != nil {
		content = append(content, c.legacy.block(nil))
	}
	if c.refusal.Len() > 0 {
		content = append(content, TextBlock{Type: "refusal", Text: c.refusal.String()})
	}
	return Message{Index: &index, Role: c.role, Content: content, FinishReason: c.finishReason}
}
func (fn *chatFunctionState) block(id *string) ToolCallBlock {
	var name *string
	var arguments any
	if fn.nameSet {
		text := fn.name.String()
		name = &text
	}
	if fn.argumentsSet {
		arguments = fn.arguments.String()
	}
	return newToolCall(id, name, arguments)
}
func (s *chatStream) discardContent() {
	for _, c := range s.choices {
		c.role = "assistant"
		c.text.Reset()
		c.refusal.Reset()
		c.tools = make(map[int]*chatToolState)
		c.legacy = nil
	}
}
func (s *chatStream) metadata() *LLMView {
	view := &LLMView{Format: "openai-chat-completions", Usage: s.usage}
	if s.model != "" {
		model := s.model
		view.Model = &model
	}
	if s.apiError != nil {
		value := s.apiError
		view.Error = &value
	}
	return view
}
