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

type responsesStream struct {
	retained *retention
	view     *LLMView
	items    map[int]*responsesStreamItem
	output   []json.RawMessage
	done     bool
}
type responsesStreamItem struct {
	id    string
	done  bool
	value json.RawMessage
}
type responsesEventWire struct {
	Type     *string         `json:"type"`
	Response json.RawMessage `json:"response"`
}
type responsesItemEvent struct {
	OutputIndex *wireIndex      `json:"output_index"`
	ItemID      *string         `json:"item_id"`
	Item        json.RawMessage `json:"item"`
}

func (s *responsesStream) add(event decoder.Event) capturestatus.Code {
	if strings.TrimSpace(event.Data) == "[DONE]" && s.done {
		return capturestatus.Unset
	}
	if s.done {
		return capturestatus.InvalidContent
	}
	var wire responsesEventWire
	if code := decodeEvent(event.Data, &wire); code != capturestatus.Complete {
		return code
	}
	if wire.Type == nil || (event.Type != "" && event.Type != "message" && event.Type != *wire.Type) {
		return capturestatus.InvalidContent
	}
	kind := *wire.Type
	switch kind {
	case "response.created", "response.in_progress", "response.queued":
		return s.updateEnvelope(&wire, false)
	case "response.completed", "response.failed", "response.incomplete":
		return s.updateEnvelope(&wire, true)
	case "error":
		return s.addError(event.Data)
	case "response.output_item.added", "response.output_item.done":
		var item responsesItemEvent
		if code := decodeEvent(event.Data, &item); code != capturestatus.Complete {
			return code
		}
		return s.updateItem(&item, kind == "response.output_item.done")
	case "response.output_text.delta", "response.refusal.delta", "response.function_call_arguments.delta":
		var delta struct {
			Delta *string `json:"delta"`
		}
		if decodeEvent(event.Data, &delta) != capturestatus.Complete || delta.Delta == nil {
			return capturestatus.InvalidContent
		}
		return s.checkItem(event.Data)
	case "response.output_text.done", "response.refusal.done", "response.function_call_arguments.done",
		"response.content_part.added", "response.content_part.done", "response.output_text.annotation.added",
		"response.reasoning_summary_part.added", "response.reasoning_summary_part.done",
		"response.reasoning_summary_text.delta", "response.reasoning_summary_text.done":
		return s.checkItem(event.Data)
	default:
		return capturestatus.UnsupportedEvent
	}
}
func (s *responsesStream) addError(raw string) capturestatus.Code {
	var failure struct {
		Message *string `json:"message"`
	}
	if decodeEvent(raw, &failure) != capturestatus.Complete || failure.Message == nil {
		return capturestatus.InvalidContent
	}
	if s.view == nil {
		s.view = &LLMView{Format: responsesFormat}
	}
	value := rawValue(json.RawMessage(raw))
	s.view.Error = &value
	s.done = true
	return capturestatus.Unset
}
func (s *responsesStream) checkItem(raw string) capturestatus.Code {
	var event responsesItemEvent
	if code := decodeEvent(raw, &event); code != capturestatus.Complete {
		return code
	}
	if event.OutputIndex == nil {
		return capturestatus.InvalidContent
	}
	item := s.items[int(*event.OutputIndex)]
	if event.ItemID == nil || item == nil || item.done || item.id != *event.ItemID {
		return capturestatus.InvalidContent
	}
	return capturestatus.Unset
}
func (s *responsesStream) updateItem(event *responsesItemEvent, done bool) capturestatus.Code {
	if event.OutputIndex == nil {
		return capturestatus.InvalidContent
	}
	var wire struct {
		ID *string `json:"id"`
	}
	if decodeObject(event.Item, &wire) != capturestatus.Complete || wire.ID == nil || len(*wire.ID) > 1024 {
		return capturestatus.InvalidContent
	}
	if s.items == nil {
		s.items = make(map[int]*responsesStreamItem)
	}
	index := int(*event.OutputIndex)
	item := s.items[index]
	if item == nil {
		if !s.retained.item() {
			return capturestatus.TooLarge
		}
		item = &responsesStreamItem{id: *wire.ID}
		s.items[index] = item
	} else if item.id != *wire.ID || item.done || !done {
		return capturestatus.InvalidContent
	}
	if done {
		if _, code := responsesItem(event.Item); code != capturestatus.Complete {
			return code
		}
		item.done = true
		if s.retained.keepRaw(event.Item) {
			item.value = event.Item
		}
	}
	return capturestatus.Unset
}
func (s *responsesStream) updateEnvelope(event *responsesEventWire, terminal bool) capturestatus.Code {
	var doc responsesDocument
	if decodeObject(event.Response, &doc) != capturestatus.Complete || doc.Model == nil || doc.Status == nil {
		return capturestatus.InvalidContent
	}
	if "response."+*doc.Status != *event.Type && *event.Type != "response.created" {
		return capturestatus.InvalidContent
	}
	view, code := responsesMetadata(&doc)
	if code != capturestatus.Complete {
		return code
	}
	if s.view != nil {
		if s.view.Model != nil && *s.view.Model != *doc.Model {
			return capturestatus.InvalidContent
		}
		if doc.Usage == nil || isNull(doc.Usage) {
			view.Usage = s.view.Usage
		}
		if doc.Error == nil {
			view.Error = s.view.Error
		}
		if doc.IncompleteDetails == nil {
			view.IncompleteReason = s.view.IncompleteReason
		}
	}
	s.view = view
	if !terminal {
		return capturestatus.Unset
	}
	if output, ok := rawArray(doc.Output); ok {
		if len(output) > 1024 {
			return capturestatus.TooLarge
		}
		// Some providers send completed items separately and leave terminal output empty.
		if len(output) > 0 {
			s.items = nil
			s.retained.used = 0
			if s.retained.keepRaw(doc.Output) {
				s.output = output
			}
		}
	} else if !isNull(doc.Output) {
		return capturestatus.InvalidContent
	}
	s.done = true
	return capturestatus.Unset
}
func (s *responsesStream) finish() (*LLMView, capturestatus.Code) {
	if !s.done {
		return nil, capturestatus.IncompleteStream
	}
	if s.view.Error != nil && s.output == nil {
		s.items = nil
	}
	output := s.output
	if output == nil {
		output = make([]json.RawMessage, 0, len(s.items))
		for i := 0; i < len(s.items); i++ {
			item := s.items[i]
			if item == nil || !item.done {
				return nil, capturestatus.IncompleteStream
			}
			if item.value != nil {
				output = append(output, item.value)
			}
		}
	}
	view := s.metadata()
	var code capturestatus.Code
	view.OutputMessages, code = responsesItems(output, true)
	return view, code
}
func (s *responsesStream) discardContent() {
	s.output = nil
	for _, item := range s.items {
		item.value = nil
	}
}
func (s *responsesStream) metadata() *LLMView {
	if s.view == nil {
		return &LLMView{Format: responsesFormat}
	}
	view := *s.view
	return &view
}
