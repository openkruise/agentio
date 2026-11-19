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
	"maps"
)

// LLMView is the common content view of a JSON document or completed SSE response.
// Nil slices are absent; non-nil empty slices are captured empty collections.
type LLMView struct {
	Format           string            `json:"format"`
	Status           *string           `json:"status,omitempty"`
	IncompleteReason *string           `json:"incompleteReason,omitempty"`
	Model            *string           `json:"model,omitempty"`
	InputMessages    []Message         `json:"inputMessages,omitzero"`
	OutputMessages   []Message         `json:"outputMessages,omitzero"`
	Tools            *[]ToolDefinition `json:"tools,omitempty"`
	Usage            *Usage            `json:"usage,omitempty"`
	Error            *any              `json:"error,omitempty"`
	Partial          bool              `json:"partial,omitempty"`
	Truncated        bool              `json:"truncated,omitempty"`
}

// Message preserves role, content order and an optional response choice index.
type Message struct {
	Index        *int           `json:"index,omitempty"`
	Role         string         `json:"role"`
	Content      []ContentBlock `json:"content"`
	FinishReason *string        `json:"finishReason,omitempty"`
}

// ContentBlock is a supported normalized block or an opaque provider block.
type ContentBlock interface{ contentBlock() }

// TextBlock carries text or refusal content and provider annotations.
type TextBlock struct {
	Type       string         `json:"type"`
	Text       string         `json:"text"`
	Extensions map[string]any `json:"-"`
}

// ToolCallBlock preserves the call identity and decoded or unparseable arguments.
type ToolCallBlock struct {
	Type      string  `json:"type"`
	ID        *string `json:"id"`
	Name      *string `json:"name"`
	Arguments any     `json:"arguments"`
	Server    bool    `json:"server,omitempty"`
}

// ToolResultBlock associates tool output with its call.
type ToolResultBlock struct {
	Type       string         `json:"type"`
	ToolCallID *string        `json:"toolCallId"`
	Content    []ContentBlock `json:"content"`
	IsError    bool           `json:"isError"`
}

// ProviderBlock retains content whose semantics are not normalized here.
type ProviderBlock struct {
	Type   string `json:"type"`
	Format string `json:"format"`
	Data   any    `json:"data"`
}

func (TextBlock) contentBlock()       {}
func (ToolCallBlock) contentBlock()   {}
func (ToolResultBlock) contentBlock() {}
func (ProviderBlock) contentBlock()   {}

// MarshalJSON keeps text annotations alongside the normalized fields.
func (b TextBlock) MarshalJSON() ([]byte, error) {
	value := make(map[string]any, len(b.Extensions)+2)
	maps.Copy(value, b.Extensions)
	value["type"], value["text"] = b.Type, b.Text
	return json.Marshal(value)
}

// ToolDefinition describes a function tool, or retains an unsupported definition.
type ToolDefinition struct {
	Name        *string        `json:"name"`
	Description *string        `json:"description"`
	Parameters  any            `json:"parameters"`
	Provider    *ProviderBlock `json:"-"`
}

// MarshalJSON preserves unsupported provider tool definitions without inventing fields.
func (t ToolDefinition) MarshalJSON() ([]byte, error) {
	if t.Provider != nil {
		return json.Marshal(t.Provider)
	}
	type definition ToolDefinition
	return json.Marshal(definition(t))
}

// Usage keeps absent counters distinct from reported zero values.
// Float64 preserves the numeric representation of the decoded provider JSON.
type Usage struct {
	InputTokens              *float64 `json:"inputTokens,omitempty"`
	OutputTokens             *float64 `json:"outputTokens,omitempty"`
	TotalTokens              *float64 `json:"totalTokens,omitempty"`
	CachedInputTokens        *float64 `json:"cachedInputTokens,omitempty"`
	CacheCreationInputTokens *float64 `json:"cacheCreationInputTokens,omitempty"`
	ReasoningTokens          *float64 `json:"reasoningTokens,omitempty"`
}
