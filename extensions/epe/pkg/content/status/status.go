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
// Package status defines content decoding and protocol outcomes.
package status

// Code is a content processing outcome, independent of consumer policy.
type Code string

// Outcomes shared by decoders, protocol adapters and their consumers.
const (
	// Unset is used by internal protocol steps with no failure; it is not a Progress status.
	Unset      Code = ""
	Incomplete Code = "incomplete"
	Complete   Code = "complete"
	Partial    Code = "partial"

	InvalidConfig        Code = "invalid_config"
	TooLarge             Code = "too_large"
	InvalidJSON          Code = "invalid_json"
	InvalidText          Code = "invalid_text"
	InvalidSSE           Code = "invalid_sse"
	InvalidContent       Code = "invalid_content"
	IncompleteStream     Code = "incomplete_stream"
	UnsupportedEvent     Code = "unsupported_event"
	UnsupportedMediaType Code = "unsupported_media_type"
	UnsupportedEncoding  Code = "unsupported_encoding"

	// Truncated indicates that retained content exceeded its budget.
	Truncated Code = "truncated"
)
