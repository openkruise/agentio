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
// Package protocol interprets decoded content independently of engine and audit.
package protocol

import (
	"fmt"
	"mime"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"

	"github.com/openkruise/agentio/extensions/epe/pkg/content/decoder"
)

// Observation owns its content: *LLMView for LLM formats, a JSON value or string
// otherwise. Content must not be mutated after being handed to emit.
type Observation struct {
	Content   any
	Truncated bool
	Partial   bool
}

// Config selects a protocol and limits the input bytes captured per direction.
type Config struct {
	// Format selects
	// - "json" (application/json or application/*+json)
	// - "text" (UTF-8 text/plain)
	// - "openai-chat-completions"
	// - "anthropic-messages"
	// - "openai-responses".
	//
	// The LLM formats accept JSON requests and responses,
	// and SSE responses with Content-Type text/event-stream. "sse" is an
	// internal decoder format, not a valid protocol selection. Empty is invalid.
	Format string
	// Response selects response semantics; false selects request semantics.
	// Only LLM response adapters accept SSE.
	Response bool
	// MaxCaptureBytes limits one JSON/text document or one SSE event.
	// MaxContentBytes bounds retained LLM content; zero uses MaxCaptureBytes.
	MaxCaptureBytes int
	MaxContentBytes int
	Fields          *CaptureFields
}

// Adapter owns per-direction decoding, protocol state and bounded content retention.
type Adapter struct {
	decoder          decoder.Decoder
	format           string
	response         bool
	stream           streamAccumulator
	streamError      capturestatus.Code
	contentDiscarded bool
	partial          bool
	fields           CaptureFields
	retention        *retention
	seen             int
}

// ValidateFormat checks the formats implemented by this package.
func ValidateFormat(format string) error {
	switch format {
	case "json", "text", "openai-chat-completions", "anthropic-messages", "openai-responses":
		return nil
	default:
		return fmt.Errorf("unsupported content format %q", format)
	}
}

// New prepares a per-direction adapter without observing or modifying traffic.
func New(cfg Config, headers map[string]string) (*Adapter, capturestatus.Code) {
	if ValidateFormat(cfg.Format) != nil {
		return nil, capturestatus.InvalidConfig
	}
	fields := allFields()
	if cfg.Fields != nil {
		fields = *cfg.Fields
	}
	if cfg.MaxContentBytes == 0 {
		cfg.MaxContentBytes = cfg.MaxCaptureBytes
	}
	if cfg.MaxContentBytes <= 0 {
		return nil, capturestatus.InvalidConfig
	}
	retained := &retention{limit: cfg.MaxContentBytes, enabled: fields.OutputMessages}
	format := cfg.Format
	var stream streamAccumulator
	if format != "json" && format != "text" {
		format = "json"
		media, _, err := mime.ParseMediaType(headers["content-type"])
		if err == nil && cfg.Response && media == "text/event-stream" {
			format = "sse"
			switch cfg.Format {
			case "openai-chat-completions":
				stream = &chatStream{retained: retained}
			case "anthropic-messages":
				stream = &anthropicStream{retained: retained}
			case "openai-responses":
				stream = &responsesStream{retained: retained}
			}
		}
	}
	a := &Adapter{format: cfg.Format, response: cfg.Response, stream: stream, fields: fields, retention: retained}
	dc := decoder.Config{Format: format, MaxCaptureBytes: cfg.MaxCaptureBytes}
	if cfg.Format != "json" && cfg.Format != "text" && format != "sse" {
		dc.DecodeJSON = func(raw []byte) (any, capturestatus.Code) { return a.documentView(raw) }
	}
	d, status := decoder.New(dc, headers)
	if d == nil {
		return nil, status
	}
	a.decoder = d
	return a, status
}

// Feed emits owned observations synchronously. A terminal status requires the
// caller to discard this adapter, as with decoder.Decoder.
func (a *Adapter) Feed(chunk []byte, complete bool, emit func(Observation)) decoder.Progress {
	if a.stream != nil {
		return a.feedStream(chunk, complete, emit)
	}
	return a.decoder.Feed(chunk, complete, func(value any) {
		if obs, ok := value.(Observation); ok {
			emit(obs)
		} else {
			emit(Observation{Content: value})
		}
	})
}

func (a *Adapter) feedStream(chunk []byte, complete bool, emit func(Observation)) decoder.Progress {
	// shortcut: cap total SSE work at 64 MiB; expose a policy when workloads need more.
	if len(chunk) > (64<<20)-a.seen {
		return decoder.Progress{CapturedBytes: a.seen, Status: capturestatus.TooLarge}
	}
	a.seen += len(chunk)
	progress := a.decoder.Feed(chunk, complete, func(value any) {
		if a.streamError == capturestatus.Unset {
			a.streamError = a.stream.add(value.(decoder.Event))
			if a.streamError == capturestatus.UnsupportedEvent {
				a.partial = true
				a.streamError = capturestatus.Unset
				a.retention.enabled = false
			}
			if (a.retention.truncated || a.partial) && !a.contentDiscarded {
				a.contentDiscarded = true
				a.stream.discardContent()
			}
		}
	})
	if progress.Status != capturestatus.Incomplete && progress.Status != capturestatus.Complete {
		return progress
	}
	if a.streamError != capturestatus.Unset {
		progress.Status = a.streamError
		return progress
	}
	if complete {
		if a.partial {
			view := a.stream.metadata()
			view.Partial, view.Truncated = true, a.retention.truncated
			emit(Observation{Content: view, Partial: true, Truncated: view.Truncated})
			return progress
		}
		view, status := a.stream.finish()
		progress.Status = status
		if status == capturestatus.Complete {
			if !a.fields.OutputMessages {
				view.OutputMessages = nil
			}
			if a.retention.truncated {
				view.OutputMessages = nil
				view.Truncated = true
			}
			a.boundView(view)
			emit(Observation{Content: view, Truncated: view.Truncated})
		}
	}
	return progress
}

func (a *Adapter) documentView(raw []byte) (Observation, capturestatus.Code) {
	view, status := llmView(raw, a.format, a.response, a.fields)
	if status != capturestatus.Complete {
		return Observation{}, status
	}
	a.boundView(view)
	return Observation{Content: view, Truncated: view.Truncated}, capturestatus.Complete
}

func (a *Adapter) boundView(view *LLMView) {
	budget := retention{limit: a.retention.limit, enabled: true}
	if view.InputMessages != nil {
		budget.keep(view.InputMessages)
	}
	if view.OutputMessages != nil {
		budget.keep(view.OutputMessages)
	}
	if view.Tools != nil {
		budget.keep(view.Tools)
	}
	if budget.truncated {
		view.InputMessages, view.OutputMessages, view.Tools = nil, nil, nil
		view.Truncated = true
	}
}
