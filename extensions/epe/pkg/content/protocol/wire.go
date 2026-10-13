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
	"bytes"
	"encoding/json"
	"fmt"
	"math"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

// Raw fields are unions, extensible payloads, or values decoded only when selected.
type chatDocument struct {
	Model    *string         `json:"model"`
	Messages json.RawMessage `json:"messages"`
	Choices  json.RawMessage `json:"choices"`
	System   json.RawMessage `json:"system"`
	Tools    json.RawMessage `json:"tools"`
	Usage    json.RawMessage `json:"usage"`
	Error    json.RawMessage `json:"error"`
}
type chatMessage struct {
	Role         *string         `json:"role"`
	Content      json.RawMessage `json:"content"`
	ToolCallID   *string         `json:"tool_call_id"`
	ToolCalls    json.RawMessage `json:"tool_calls"`
	FunctionCall json.RawMessage `json:"function_call"`
	Refusal      json.RawMessage `json:"refusal"`
}
type chatChoiceWire struct {
	Index        *wireIndex      `json:"index"`
	Message      json.RawMessage `json:"message"`
	Delta        json.RawMessage `json:"delta"`
	FinishReason *string         `json:"finish_reason"`
}
type functionWire struct {
	Name      *string         `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}
type toolWire struct {
	Index    *wireIndex      `json:"index"`
	ID       *string         `json:"id"`
	Type     *string         `json:"type"`
	Function json.RawMessage `json:"function"`
}
type anthropicDocument struct {
	Model      *string         `json:"model"`
	Messages   json.RawMessage `json:"messages"`
	System     json.RawMessage `json:"system"`
	Content    json.RawMessage `json:"content"`
	Tools      json.RawMessage `json:"tools"`
	Usage      json.RawMessage `json:"usage"`
	StopReason *string         `json:"stop_reason"`
	Error      json.RawMessage `json:"error"`
}
type responsesDocument struct {
	Model             *string         `json:"model"`
	Status            *string         `json:"status"`
	Instructions      *string         `json:"instructions"`
	Input             json.RawMessage `json:"input"`
	Output            json.RawMessage `json:"output"`
	Tools             json.RawMessage `json:"tools"`
	Usage             json.RawMessage `json:"usage"`
	Error             json.RawMessage `json:"error"`
	IncompleteDetails json.RawMessage `json:"incomplete_details"`
}
type responsesItemWire struct {
	Type      *string         `json:"type"`
	ID        *string         `json:"id"`
	Role      *string         `json:"role"`
	Content   json.RawMessage `json:"content"`
	CallID    *string         `json:"call_id"`
	Name      *string         `json:"name"`
	Arguments *string         `json:"arguments"`
	Output    json.RawMessage `json:"output"`
}

// JSON numbers such as 0.0 retain the prior numeric-index semantics.
type wireIndex int

func (i *wireIndex) UnmarshalJSON(raw []byte) error {
	var n float64
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	if n < 0 || n > math.MaxInt32 || n != math.Trunc(n) {
		return fmt.Errorf("invalid index %s", raw)
	}
	*i = wireIndex(n)
	return nil
}

func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
func isObject(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && raw[0] == '{'
}
func decodeObject(raw []byte, dst any) capturestatus.Code {
	if !json.Valid(raw) {
		return capturestatus.InvalidJSON
	}
	if !isObject(raw) || json.Unmarshal(raw, dst) != nil {
		return capturestatus.InvalidContent
	}
	return capturestatus.Complete
}
func decodeEvent(raw string, dst any) capturestatus.Code {
	if !isObject([]byte(raw)) {
		return capturestatus.InvalidJSON
	}
	return decodeObject([]byte(raw), dst)
}
func rawArray(raw json.RawMessage) ([]json.RawMessage, bool) {
	var result []json.RawMessage
	err := json.Unmarshal(raw, &result)
	return result, err == nil && result != nil
}
func rawValue(raw json.RawMessage) any {
	var value any
	// RawMessage values originate from a successfully decoded document/event.
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil
		}
	}
	return value
}
func rawString(raw json.RawMessage) (*string, bool) {
	var value *string
	if len(raw) == 0 {
		return nil, true
	}
	if json.Unmarshal(raw, &value) != nil {
		return nil, false
	}
	return value, true
}
func unknownFields(raw json.RawMessage, ignoreNull bool, known ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, key := range known {
		delete(fields, key)
	}
	for _, value := range fields {
		if !ignoreNull || !isNull(value) {
			return true
		}
	}
	return false
}
