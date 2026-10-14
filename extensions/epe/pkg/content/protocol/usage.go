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

import "encoding/json"

// Non-numeric optional counters remain absent, as in the dynamic decoder.
type usageCounter struct{ value *float64 }

func (n *usageCounter) UnmarshalJSON(raw []byte) error {
	n.value = nil
	if !isNull(raw) {
		var v float64
		if json.Unmarshal(raw, &v) == nil {
			n.value = &v
		}
	}
	return nil
}

type usageWire struct {
	Prompt            usageCounter    `json:"prompt_tokens"`
	Completion        usageCounter    `json:"completion_tokens"`
	Input             usageCounter    `json:"input_tokens"`
	Output            usageCounter    `json:"output_tokens"`
	Total             usageCounter    `json:"total_tokens"`
	CacheRead         usageCounter    `json:"cache_read_input_tokens"`
	CacheCreation     usageCounter    `json:"cache_creation_input_tokens"`
	PromptDetails     json.RawMessage `json:"prompt_tokens_details"`
	CompletionDetails json.RawMessage `json:"completion_tokens_details"`
	InputDetails      json.RawMessage `json:"input_tokens_details"`
	OutputDetails     json.RawMessage `json:"output_tokens_details"`
}
type usageDetails struct {
	Cached    usageCounter `json:"cached_tokens"`
	Written   usageCounter `json:"cache_write_tokens"`
	Reasoning usageCounter `json:"reasoning_tokens"`
}

func decodeUsage(raw json.RawMessage, anthropic, responses bool) *Usage {
	var wire usageWire
	if !isObject(raw) || json.Unmarshal(raw, &wire) != nil {
		return nil
	}
	result := &Usage{InputTokens: wire.Prompt.value, OutputTokens: wire.Completion.value, TotalTokens: wire.Total.value}
	inDetails, outDetails := wire.PromptDetails, wire.CompletionDetails
	if anthropic || responses {
		result.InputTokens, result.OutputTokens = wire.Input.value, wire.Output.value
	}
	if anthropic {
		result.CachedInputTokens, result.CacheCreationInputTokens = wire.CacheRead.value, wire.CacheCreation.value
		result.TotalTokens = nil
	}
	if responses {
		inDetails, outDetails = wire.InputDetails, wire.OutputDetails
	}
	var in, out usageDetails
	if json.Unmarshal(inDetails, &in) == nil {
		if in.Cached.value != nil {
			result.CachedInputTokens = in.Cached.value
		}
		if responses {
			result.CacheCreationInputTokens = in.Written.value
		}
	}
	if json.Unmarshal(outDetails, &out) == nil {
		result.ReasoningTokens = out.Reasoning.value
	}
	return result
}
func anthropicUsage(usage *Usage) *Usage {
	if usage == nil {
		return nil
	}
	result := *usage
	if usage.InputTokens != nil {
		total := *usage.InputTokens
		for _, n := range []*float64{usage.CachedInputTokens, usage.CacheCreationInputTokens} {
			if n != nil {
				total += *n
			}
		}
		result.InputTokens = &total
		if usage.OutputTokens != nil {
			n := total + *usage.OutputTokens
			result.TotalTokens = &n
		}
	}
	return &result
}
func mergeUsage(dst, src *Usage) *Usage {
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	for _, pair := range []struct {
		dst **float64
		src *float64
	}{
		{&dst.InputTokens, src.InputTokens}, {&dst.OutputTokens, src.OutputTokens}, {&dst.TotalTokens, src.TotalTokens},
		{&dst.CachedInputTokens, src.CachedInputTokens}, {&dst.CacheCreationInputTokens, src.CacheCreationInputTokens}, {&dst.ReasoningTokens, src.ReasoningTokens},
	} {
		if pair.src != nil {
			*pair.dst = pair.src
		}
	}
	return dst
}
