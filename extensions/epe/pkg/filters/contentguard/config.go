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
package contentguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/cel-go/cel"

	"github.com/openkruise/agentio/extensions/epe/pkg/content/protocol"
)

const (
	defaultCaptureBytes = 64 << 10
	defaultRecordBytes  = 16 << 10
	maxCaptureBytes     = 1 << 20
	maxRecordBytes      = 64 << 10
)

// config is compiled from the neutral payload, independently of CRD definitions.
type config struct {
	request  captureConfig
	response *captureConfig
}

// captureConfig is the compiled capture policy for one traffic direction.
type captureConfig struct {
	// format selects the protocol view; LLM responses use Content-Type to select JSON or SSE.
	format string
	// response selects response parsing semantics, not whether capture is enabled.
	response bool
	// captureBytes limits one JSON/text document or one SSE event, not the entire SSE stream.
	captureBytes int
	// recordBytes bounds {"content": value} (excluding record metadata) and retained LLM content.
	recordBytes int
	// transform optionally converts the protocol view without changing forwarded bytes.
	transform cel.Program
	// fields is inferred from transform to avoid retaining unused messages and tools.
	fields protocol.CaptureFields
}

type captureSpec struct {
	Format          string `json:"format"`
	MaxCaptureBytes int    `json:"maxCaptureBytes"`
	MaxRecordBytes  int    `json:"maxRecordBytes"`
	Transform       string `json:"transform"`
}

func parse(raw json.RawMessage) (config, error) {
	var spec struct {
		captureSpec
		Response *struct {
			captureSpec
			Enabled bool `json:"enabled"`
		} `json:"response"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return config{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return config{}, fmt.Errorf("expected one content configuration JSON object")
	}
	request, err := compileCapture(spec.captureSpec, false)
	if err != nil {
		return config{}, err
	}
	cfg := config{request: request}
	if spec.Response != nil {
		response, err := compileCapture(spec.Response.captureSpec, true)
		if err != nil {
			return config{}, fmt.Errorf("response capture: %w", err)
		}
		if spec.Response.Enabled {
			cfg.response = &response
		}
	}
	return cfg, nil
}

func compileCapture(spec captureSpec, response bool) (captureConfig, error) {
	if spec.Format == "" {
		spec.Format = "openai-chat-completions"
		if response {
			spec.Format = "json"
		}
	}
	if err := protocol.ValidateFormat(spec.Format); err != nil {
		return captureConfig{}, err
	}
	if spec.MaxCaptureBytes == 0 {
		spec.MaxCaptureBytes = defaultCaptureBytes
	}
	if spec.MaxRecordBytes == 0 {
		spec.MaxRecordBytes = defaultRecordBytes
	}
	if spec.MaxCaptureBytes < 1 || spec.MaxCaptureBytes > maxCaptureBytes ||
		spec.MaxRecordBytes < 1 || spec.MaxRecordBytes > maxRecordBytes {
		return captureConfig{}, fmt.Errorf(
			"capture limit must be 1..%d and record limit 1..%d bytes",
			maxCaptureBytes,
			maxRecordBytes,
		)
	}
	program, fields, err := compileTransformation(spec.Transform)
	if err != nil {
		return captureConfig{}, err
	}
	return captureConfig{
		format:       spec.Format,
		response:     response,
		captureBytes: spec.MaxCaptureBytes,
		recordBytes:  spec.MaxRecordBytes,
		transform:    program,
		fields:       fields,
	}, nil
}
