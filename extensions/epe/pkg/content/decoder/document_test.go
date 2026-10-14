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
package decoder

import (
	"reflect"
	"strings"
	"testing"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

func TestDocumentBufferBound(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			media := "application/json"
			if format == "text" {
				media = "text/plain"
			}
			parser, status := New(Config{Format: format, MaxCaptureBytes: 7}, map[string]string{"content-type": media})
			if status != capturestatus.Incomplete {
				t.Fatal(status)
			}
			d := parser.(*documentDecoder)
			var progress Progress
			for _, chunk := range []string{"123", "456", strings.Repeat("x", 1024)} {
				progress = d.Feed(
					[]byte(chunk),
					false,
					func(any) { t.Fatal("emitted invalid or incomplete document") },
				)
				if cap(d.buffer) > 7 {
					t.Fatalf("capacity: %d", cap(d.buffer))
				}
			}
			if progress.Status != capturestatus.TooLarge || progress.CapturedBytes != 6 || d.buffer != nil {
				t.Fatalf("progress: %+v", progress)
			}
		})
	}
}

func TestDocumentOwnsInputAndOutput(t *testing.T) {
	d := &documentDecoder{limit: 64, decode: decodeJSON}
	prefix := []byte(`{"x":`)
	if progress := d.Feed(
		prefix,
		false,
		func(any) { t.Fatal("early observation") },
	); progress.Status != capturestatus.Incomplete {
		t.Fatal(progress)
	}
	copy(prefix, "xxxxx")
	tail := []byte(`"你好"}`)
	var result any
	emitted := 0
	progress := d.Feed(tail, true, func(value any) {
		result = value
		emitted++
	})
	for i := range tail {
		tail[i] = 'x'
	}
	if progress.Status != capturestatus.Complete || emitted != 1 || d.buffer != nil {
		t.Fatalf("progress: %+v, emissions: %d", progress, emitted)
	}
	want := map[string]any{"x": "你好"}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("observation: %+v", result)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, cfg := range []Config{{Format: "unknown", MaxCaptureBytes: 64}, {Format: "json"}} {
		parser, status := New(cfg, map[string]string{"content-type": "application/json"})
		if parser != nil || status != capturestatus.InvalidConfig {
			t.Fatalf("accepted config: %+v", cfg)
		}
	}
}

func TestCustomDocumentDecoderHonorsBudgetAndStatus(t *testing.T) {
	for _, tt := range []struct {
		input  string
		result capturestatus.Code
		want   capturestatus.Code
		calls  int
		emits  int
	}{
		{"{}", capturestatus.Complete, capturestatus.Complete, 1, 1},
		{"{}", capturestatus.InvalidContent, capturestatus.InvalidContent, 1, 0},
		{"{ }", capturestatus.Complete, capturestatus.TooLarge, 0, 0},
	} {
		calls, emits := 0, 0
		parser, status := New(Config{
			Format:          "json",
			MaxCaptureBytes: 2,
			DecodeJSON: func(raw []byte) (any, capturestatus.Code) {
				calls++
				if string(raw) != tt.input {
					t.Fatal("wrong document")
				}
				return "typed value", tt.result
			},
		}, map[string]string{"content-type": "application/json"})
		if status != capturestatus.Incomplete {
			t.Fatal(status)
		}
		progress := parser.Feed([]byte(tt.input), true, func(value any) {
			emits++
			if value != "typed value" {
				t.Fatal(value)
			}
		})
		if progress.Status != tt.want || calls != tt.calls || emits != tt.emits {
			t.Fatalf("progress=%+v calls=%d emits=%d", progress, calls, emits)
		}
	}
}
