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
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/content/decoder"
	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

type anthropicStream struct {
	retained   *retention
	model      *string
	stopReason *string
	usage      *Usage
	blocks     []*anthropicBlock
	apiError   any
	done       bool
}
type anthropicEvent struct {
	Type    *string         `json:"type"`
	Message json.RawMessage `json:"message"`
	Delta   json.RawMessage `json:"delta"`
	Usage   json.RawMessage `json:"usage"`
	Error   json.RawMessage `json:"error"`
}
type anthropicBlockEvent struct {
	Index        *wireIndex      `json:"index"`
	ContentBlock json.RawMessage `json:"content_block"`
	Delta        json.RawMessage `json:"delta"`
}
type anthropicDelta struct {
	Type        *string         `json:"type"`
	Text        *string         `json:"text"`
	Thinking    *string         `json:"thinking"`
	Signature   *string         `json:"signature"`
	PartialJSON *string         `json:"partial_json"`
	Citation    json.RawMessage `json:"citation"`
	StopReason  *string         `json:"stop_reason"`
}
type anthropicBlock struct {
	retained     *retention
	kind         string
	source       json.RawMessage
	text         strings.Builder
	thinking     strings.Builder
	signature    strings.Builder
	textSet      bool
	thinkingSet  bool
	signatureSet bool
	input        strings.Builder
	hasInput     bool
	parsedInput  any
	citations    []any
	closed       bool
}

func (s *anthropicStream) add(event decoder.Event) capturestatus.Code {
	var wire anthropicEvent
	if code := decodeEvent(event.Data, &wire); code != capturestatus.Complete {
		return code
	}
	if wire.Type == nil || event.Type != *wire.Type {
		return capturestatus.InvalidContent
	}
	kind := *wire.Type
	if kind == "ping" {
		return capturestatus.Unset
	}
	if s.done {
		return capturestatus.InvalidContent
	}
	if kind == "error" {
		if !isObject(wire.Error) {
			return capturestatus.InvalidContent
		}
		s.apiError = rawValue(wire.Error)
		s.done = true
		return capturestatus.Unset
	}
	if kind == "message_start" {
		return s.startMessage(wire.Message)
	}
	if s.model == nil {
		return capturestatus.InvalidContent
	}
	switch kind {
	case "content_block_start":
		var block anthropicBlockEvent
		if code := decodeEvent(event.Data, &block); code != capturestatus.Complete {
			return code
		}
		return s.startBlock(&block)
	case "content_block_delta", "content_block_stop":
		var block anthropicBlockEvent
		if code := decodeEvent(event.Data, &block); code != capturestatus.Complete {
			return code
		}
		return s.updateBlock(&block, kind)
	case "message_delta":
		return s.updateMessage(&wire)
	case "message_stop":
		s.done = true
	default:
		return capturestatus.UnsupportedEvent
	}
	return capturestatus.Unset
}
func (s *anthropicStream) startMessage(raw json.RawMessage) capturestatus.Code {
	var message anthropicDocument
	if s.model != nil || decodeObject(raw, &message) != capturestatus.Complete || message.Model == nil {
		return capturestatus.InvalidContent
	}
	content, ok := rawArray(message.Content)
	if !ok || len(content) != 0 {
		return capturestatus.InvalidContent
	}
	s.model = message.Model
	s.usage = decodeUsage(message.Usage, true, false)
	return capturestatus.Unset
}
func (s *anthropicStream) startBlock(event *anthropicBlockEvent) capturestatus.Code {
	if event.Index == nil || int(*event.Index) != len(s.blocks) {
		return capturestatus.InvalidContent
	}
	var header struct {
		Type *string `json:"type"`
	}
	if decodeObject(event.ContentBlock, &header) != capturestatus.Complete || header.Type == nil ||
		len(*header.Type) > 128 {
		return capturestatus.InvalidContent
	}
	if !s.retained.item() {
		return capturestatus.TooLarge
	}
	block := &anthropicBlock{retained: s.retained, kind: *header.Type}
	if s.retained.keepRaw(event.ContentBlock) {
		block.source = event.ContentBlock
	}
	s.blocks = append(s.blocks, block)
	return capturestatus.Unset
}
func (s *anthropicStream) updateBlock(event *anthropicBlockEvent, kind string) capturestatus.Code {
	if event.Index == nil || int(*event.Index) >= len(s.blocks) {
		return capturestatus.InvalidContent
	}
	block := s.blocks[int(*event.Index)]
	if block.closed {
		return capturestatus.InvalidContent
	}
	if kind == "content_block_stop" {
		block.closed = true
		if block.hasInput {
			var input map[string]any
			if json.Unmarshal([]byte(block.input.String()), &input) != nil || input == nil {
				return capturestatus.InvalidContent
			}
			block.parsedInput = input
			block.input.Reset()
		}
		return capturestatus.Unset
	}
	return block.addDelta(event.Delta)
}
func (b *anthropicBlock) addDelta(raw json.RawMessage) capturestatus.Code {
	var tag struct {
		Type *string `json:"type"`
	}
	if decodeObject(raw, &tag) != capturestatus.Complete {
		return capturestatus.InvalidContent
	}
	if tag.Type == nil {
		return capturestatus.UnsupportedEvent
	}
	switch *tag.Type {
	case "text_delta", "thinking_delta", "signature_delta", "input_json_delta", "citations_delta":
	default:
		return capturestatus.UnsupportedEvent
	}
	var delta anthropicDelta
	if decodeObject(raw, &delta) != capturestatus.Complete {
		return capturestatus.InvalidContent
	}
	if delta.Type == nil {
		return capturestatus.UnsupportedEvent
	}
	switch *delta.Type {
	case "text_delta":
		if b.kind != "text" || !b.appendField("text", delta.Text, &b.text, &b.textSet) {
			return capturestatus.InvalidContent
		}
	case "thinking_delta":
		if b.kind != "thinking" || !b.appendField("thinking", delta.Thinking, &b.thinking, &b.thinkingSet) {
			return capturestatus.InvalidContent
		}
	case "signature_delta":
		if b.kind != "thinking" || !b.appendField("signature", delta.Signature, &b.signature, &b.signatureSet) {
			return capturestatus.InvalidContent
		}
	case "input_json_delta":
		return b.addInput(delta.PartialJSON)
	case "citations_delta":
		if b.kind != "text" || !isObject(delta.Citation) {
			return capturestatus.InvalidContent
		}
		citation := rawValue(delta.Citation)
		if b.retained.keep(citation) {
			b.citations = append(b.citations, citation)
		}
	default:
		return capturestatus.UnsupportedEvent
	}
	return capturestatus.Unset
}
func (b *anthropicBlock) addInput(part *string) capturestatus.Code {
	if (b.kind != "tool_use" && b.kind != "server_tool_use") || part == nil {
		return capturestatus.InvalidContent
	}
	// Empty deltas preserve the initial input object for zero-argument tools.
	if *part != "" && b.retained.append(&b.input, *part) {
		b.hasInput = true
	}
	return capturestatus.Unset
}

func (b *anthropicBlock) appendField(key string, value *string, builder *strings.Builder, set *bool) bool {
	if value == nil {
		return false
	}
	if !b.retained.reserve(len(*value)) {
		return true
	}
	if !*set {
		var initial struct {
			Text      json.RawMessage `json:"text"`
			Thinking  json.RawMessage `json:"thinking"`
			Signature json.RawMessage `json:"signature"`
		}
		if len(b.source) > 0 && json.Unmarshal(b.source, &initial) != nil {
			return false
		}
		raw := initial.Text
		if key == "thinking" {
			raw = initial.Thinking
		}
		if key == "signature" {
			raw = initial.Signature
		}
		text, ok := rawString(raw)
		if !ok {
			return false
		}
		if text != nil {
			builder.WriteString(*text)
		}
		*set = true
	}
	builder.WriteString(*value)
	return true
}
func (s *anthropicStream) updateMessage(event *anthropicEvent) capturestatus.Code {
	var delta struct {
		StopReason *string `json:"stop_reason"`
	}
	if decodeObject(event.Delta, &delta) != capturestatus.Complete {
		return capturestatus.InvalidContent
	}
	for _, block := range s.blocks {
		if !block.closed {
			return capturestatus.InvalidContent
		}
	}
	if delta.StopReason != nil && len(*delta.StopReason) > 256 {
		return capturestatus.InvalidContent
	}
	// A null stop reason clears it, while an absent field leaves prior state intact.
	var presence struct {
		StopReason json.RawMessage `json:"stop_reason"`
	}
	if json.Unmarshal(event.Delta, &presence) != nil {
		return capturestatus.InvalidContent
	}
	if presence.StopReason != nil {
		s.stopReason = delta.StopReason
	}
	if event.Usage != nil {
		if !isObject(event.Usage) {
			return capturestatus.InvalidContent
		}
		s.usage = mergeUsage(s.usage, decodeUsage(event.Usage, true, false))
	}
	if unknownFields(event.Delta, false, "stop_reason", "stop_sequence") {
		return capturestatus.UnsupportedEvent
	}
	return capturestatus.Unset
}
func (s *anthropicStream) finish() (*LLMView, capturestatus.Code) {
	if !s.done {
		return nil, capturestatus.IncompleteStream
	}
	view := s.metadata()
	if s.apiError != nil {
		return &LLMView{Format: view.Format, Error: view.Error}, capturestatus.Complete
	}
	if s.model == nil || s.stopReason == nil {
		return nil, capturestatus.IncompleteStream
	}
	content := make([]ContentBlock, 0)
	for _, block := range s.blocks {
		if !block.closed {
			return nil, capturestatus.IncompleteStream
		}
		content = append(content, block.content()...)
	}
	index := 0
	view.OutputMessages = []Message{{Index: &index, Role: "assistant", Content: content, FinishReason: s.stopReason}}
	return view, capturestatus.Complete
}
func (b *anthropicBlock) content() []ContentBlock {
	// Provider extensions remain dynamic; streaming state itself never lives in this map.
	raw, _ := rawValue(b.source).(map[string]any)
	if raw == nil {
		raw = map[string]any{"type": b.kind}
	}
	if b.textSet {
		raw["text"] = b.text.String()
	}
	if b.thinkingSet {
		raw["thinking"] = b.thinking.String()
	}
	if b.signatureSet {
		raw["signature"] = b.signature.String()
	}
	if b.parsedInput != nil {
		raw["input"] = b.parsedInput
	}
	if len(b.citations) > 0 {
		prior, _ := raw["citations"].([]any)
		raw["citations"] = append(prior, b.citations...)
	}
	switch b.kind {
	case "text":
		if text, ok := raw["text"].(string); ok {
			if text == "" {
				return nil
			}
			delete(raw, "type")
			delete(raw, "text")
			return []ContentBlock{TextBlock{Type: "text", Text: text, Extensions: raw}}
		}
	case "tool_result":
		return normalizeBlock(b.source, "anthropic-messages")
	case "tool_use", "server_tool_use":
		var wire toolUseWire
		if len(b.source) == 0 || json.Unmarshal(b.source, &wire) == nil {
			arguments := rawValue(wire.Input)
			if b.parsedInput != nil {
				arguments = b.parsedInput
			}
			call := newToolCall(wire.ID, wire.Name, arguments)
			call.Server = b.kind == "server_tool_use"
			return []ContentBlock{call}
		}
	}
	return []ContentBlock{providerBlock(raw, "anthropic-messages")}
}
func (s *anthropicStream) discardContent() {
	for _, b := range s.blocks {
		b.source = nil
		b.text.Reset()
		b.thinking.Reset()
		b.signature.Reset()
		b.textSet = false
		b.thinkingSet = false
		b.signatureSet = false
		b.input.Reset()
		b.hasInput = false
		b.parsedInput = nil
		b.citations = nil
	}
}
func (s *anthropicStream) metadata() *LLMView {
	view := &LLMView{Format: "anthropic-messages", Model: s.model, Usage: anthropicUsage(s.usage)}
	if s.apiError != nil {
		value := s.apiError
		view.Error = &value
	}
	return view
}
