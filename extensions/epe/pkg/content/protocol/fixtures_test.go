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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

func TestProtocolFixtures(t *testing.T) {
	for _, tt := range []struct {
		file    string
		format  string
		request bool
	}{
		{"anthropic-empty-tool.sse", "anthropic-messages", false},
		{"anthropic-usage.sse", "anthropic-messages", false},
		{"anthropic-citations.json", "anthropic-messages", false},
		{"responses-tools.sse", "openai-responses", false},
		{"responses-refusal.sse", "openai-responses", false},
		{"responses-truncated.json", "openai-responses", false},
		{"responses-parallel.json", "openai-responses", true},
		{"responses-media.json", "openai-responses", true},
		{"chat-empty-content.sse", "openai-chat-completions", false},
		{"chat-truncated.json", "openai-chat-completions", false},
		{"chat-annotations.sse", "openai-chat-completions", false},
		{"chat-obfuscation.sse", "openai-chat-completions", false},
	} {
		t.Run(tt.file, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.ReadFile(
				filepath.Join("testdata", strings.TrimSuffix(tt.file, filepath.Ext(tt.file))+".want.json"),
			)
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]any
			if err := json.Unmarshal(expected, &want); err != nil {
				t.Fatal(err)
			}
			media := "application/json"
			if filepath.Ext(tt.file) == ".sse" {
				media = "text/event-stream"
			}
			cfg := Config{Format: tt.format, Response: !tt.request, MaxCaptureBytes: 16 << 10}
			for _, size := range []int{1, 7, 64, len(input)} {
				for _, separateEOF := range []bool{false, true} {
					t.Run(fmt.Sprintf("chunk=%d/separateEOF=%t", size, separateEOF), func(t *testing.T) {
						checkFixtureDelivery(t, cfg, media, input, want, size, separateEOF)
					})
				}
			}
		})
	}
}

func checkFixtureDelivery(
	t *testing.T,
	cfg Config,
	media string,
	input []byte,
	want map[string]any,
	size int,
	separateEOF bool,
) {
	t.Helper()
	a, status := New(cfg, map[string]string{"content-type": media})
	if a == nil {
		t.Fatal(status)
	}
	count := 0
	var got Observation
	emit := func(obs Observation) {
		count++
		got = obs
	}
	for at := 0; at < len(input); at += size {
		end := min(at+size, len(input))
		chunk := bytes.Clone(input[at:end])
		complete := end == len(input) && !separateEOF
		p := a.Feed(chunk, complete, emit)
		expected := capturestatus.Incomplete
		if complete {
			expected = capturestatus.Complete
		}
		if p.Status != expected {
			t.Fatalf("at=%d progress=%+v want=%s", at, p, expected)
		}
		if !bytes.Equal(chunk, input[at:end]) {
			t.Fatal("mutated input bytes")
		}
		clear(chunk)
		if !complete && count != 0 {
			t.Fatal("published before HTTP EOF")
		}
	}
	if separateEOF {
		if p := a.Feed(nil, true, emit); p.Status != capturestatus.Complete {
			t.Fatal(p)
		}
	}
	if count != 1 || got.Truncated || got.Partial != (want["partial"] == true) {
		t.Fatalf("count=%d observation=%+v", count, got)
	}
	if actual := jsonValue(t, got.Content); !reflect.DeepEqual(actual, want) {
		encoded, err := json.MarshalIndent(actual, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("view mismatch\ngot: %s\nwant: %+v", encoded, want)
	}
}
