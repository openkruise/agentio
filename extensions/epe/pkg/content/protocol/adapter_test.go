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
	"reflect"
	"testing"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

func TestAdapterPreservesDecodeAndProtocolFailures(t *testing.T) {
	for _, tt := range []struct {
		body   string
		status capturestatus.Code
	}{
		{body: `{`, status: capturestatus.InvalidJSON},
		{body: `{}`, status: capturestatus.InvalidContent},
		{body: `{"model":"qwen","messages":[],"extra":"keep"}`, status: capturestatus.Complete},
	} {
		a, status := New(
			Config{Format: "openai-chat-completions", MaxCaptureBytes: 128},
			map[string]string{"content-type": "application/json"},
		)
		if status != capturestatus.Incomplete {
			t.Fatal(status)
		}
		var observations []Observation
		emit := func(obs Observation) { observations = append(observations, obs) }
		for _, b := range []byte(tt.body) {
			progress := a.Feed([]byte{b}, false, emit)
			if progress.Status != capturestatus.Incomplete || len(observations) != 0 {
				t.Fatalf("premature observation: %+v", progress)
			}
		}
		progress := a.Feed(nil, true, emit)
		if progress.Status != tt.status || progress.CapturedBytes != len(tt.body) {
			t.Fatalf("body=%s progress=%+v", tt.body, progress)
		}
		if tt.status != capturestatus.Complete {
			if len(observations) != 0 {
				t.Fatal("emitted malformed content")
			}
			continue
		}
		if len(observations) != 1 {
			t.Fatalf("emissions: %d", len(observations))
		}
		obs := observations[0]
		if !reflect.DeepEqual(
			jsonValue(t, obs.Content),
			map[string]any{"format": "openai-chat-completions", "model": "qwen", "inputMessages": []any{}},
		) {
			t.Fatalf("view: %+v", obs.Content)
		}
	}
}

func TestAdapterRejectsInvalidConfiguration(t *testing.T) {
	for _, cfg := range []Config{{Format: "unknown", MaxCaptureBytes: 64}, {Format: "openai-chat-completions"}} {
		a, status := New(cfg, map[string]string{"content-type": "application/json"})
		if a != nil || status != capturestatus.InvalidConfig {
			t.Fatalf("accepted config: %+v", cfg)
		}
	}
}
