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
// Package decoder turns bounded byte streams into JSON values or UTF-8 strings.
package decoder

import (
	"mime"
	"strings"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

// Progress reports admitted input and parsing status. Any status other than
// capturestatus.Incomplete is terminal; the caller must discard the decoder afterwards.
type Progress struct {
	CapturedBytes int
	Status        capturestatus.Code
}

// Decoder consumes borrowed chunks and synchronously emits owned values.
// Chunk boundaries must not change decoded values. complete is HTTP EOF, not
// a protocol end marker. Capture failures are statuses, never engine errors.
type Decoder interface {
	Feed(chunk []byte, complete bool, emit func(any)) Progress
}

// Config selects a document format and bounds retained input bytes.
type Config struct {
	Format          string
	MaxCaptureBytes int
	// DecodeJSON optionally interprets the bounded JSON document directly.
	DecodeJSON func([]byte) (any, capturestatus.Code)
}

// New prepares a per-direction decoder without observing or modifying traffic.
func New(cfg Config, headers map[string]string) (Decoder, capturestatus.Code) {
	if (cfg.Format != "json" && cfg.Format != "text" && cfg.Format != "sse") || cfg.MaxCaptureBytes <= 0 {
		return nil, capturestatus.InvalidConfig
	}
	if encoding := strings.TrimSpace(
		headers["content-encoding"],
	); encoding != "" &&
		!strings.EqualFold(encoding, "identity") {
		return nil, capturestatus.UnsupportedEncoding
	}
	media, params, err := mime.ParseMediaType(headers["content-type"])
	media = strings.ToLower(media)
	if err != nil {
		return nil, capturestatus.UnsupportedMediaType
	}
	if cfg.Format == "sse" {
		if media != "text/event-stream" {
			return nil, capturestatus.UnsupportedMediaType
		}
		if charset := params["charset"]; charset != "" && !strings.EqualFold(charset, "utf-8") {
			return nil, capturestatus.UnsupportedEncoding
		}
		return &sseDecoder{limit: cfg.MaxCaptureBytes, firstLine: true}, capturestatus.Incomplete
	}
	decode := cfg.DecodeJSON
	if decode == nil {
		decode = decodeJSON
	}
	if cfg.Format == "text" {
		if media != "text/plain" {
			return nil, capturestatus.UnsupportedMediaType
		}
		if charset := params["charset"]; charset != "" && !strings.EqualFold(charset, "utf-8") {
			return nil, capturestatus.UnsupportedEncoding
		}
		decode = decodeText
	} else {
		if media != "application/json" &&
			!(strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json")) {
			return nil, capturestatus.UnsupportedMediaType
		}
	}
	return &documentDecoder{limit: cfg.MaxCaptureBytes, decode: decode}, capturestatus.Incomplete
}
