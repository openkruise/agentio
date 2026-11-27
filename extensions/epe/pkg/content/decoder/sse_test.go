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
	"bytes"
	"reflect"
	"strings"
	"testing"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

func TestSSEChunkBoundaries(t *testing.T) {
	input := "\xef\xbb\xbf: comment\r\nevent: delta\rdata: 你\ndata: 好\r\n\r\nid: 1\nretry: 10\nunknown: ignored\ndata\n\ndata: discarded"
	want := []Event{{Type: "delta", Data: "你\n好"}, {Type: "message", Data: ""}}
	for size := 1; size <= len(input); size++ {
		parser, status := New(
			Config{Format: "sse", MaxCaptureBytes: len(input)},
			map[string]string{"content-type": "text/event-stream; charset=utf-8"},
		)
		if status != capturestatus.Incomplete {
			t.Fatal(status)
		}
		var got []Event
		emit := func(v any) { got = append(got, v.(Event)) }
		for at := 0; at < len(input); at += size {
			chunk := []byte(input[at:min(at+size, len(input))])
			p := parser.Feed(chunk, false, emit)
			if p.Status != capturestatus.Incomplete {
				t.Fatal(p)
			}
			for i := range chunk {
				chunk[i] = 'x'
			}
		}
		p := parser.Feed(nil, true, emit)
		if p.Status != capturestatus.Complete || p.CapturedBytes != len(input) || !reflect.DeepEqual(got, want) {
			t.Fatalf("size=%d progress=%+v got=%+v", size, p, got)
		}
	}
}

func TestSSELimitsAndInvalidUTF8(t *testing.T) {
	for _, input := range []string{"data: " + strings.Repeat("x", 20), ": " + strings.Repeat("x", 20)} {
		d := &sseDecoder{limit: 10, firstLine: true}
		emit := func(any) { t.Fatal("unexpected event") }
		var p Progress
		for _, b := range []byte(input) {
			p = d.Feed([]byte{b}, false, emit)
			if cap(d.line) > 10 || cap(d.data) > 10 {
				t.Fatal("capacity exceeded limit")
			}
			if p.Status != capturestatus.Incomplete {
				break
			}
		}
		if p.Status != capturestatus.TooLarge || d.line != nil || d.data != nil {
			t.Fatal(p)
		}
	}
	d := &sseDecoder{limit: 20, firstLine: true}
	p := d.Feed(
		bytes.Join([][]byte{[]byte("data: "), {0xff}, []byte("\n\n")}, nil),
		true,
		func(any) { t.Fatal("invalid UTF-8 emitted") },
	)
	if p.Status != capturestatus.InvalidSSE {
		t.Fatal(p)
	}
}

func TestSSELimitAppliesToEachEvent(t *testing.T) {
	for _, ending := range []string{"\n", "\r", "\r\n"} {
		event := "data: ok" + ending + ending
		input := strings.Repeat(event, 100)
		for _, size := range []int{1, len(input)} {
			d := &sseDecoder{limit: len(event), firstLine: true}
			count := 0
			for at := 0; at < len(input); at += size {
				p := d.Feed([]byte(input[at:min(at+size, len(input))]), at+size >= len(input), func(any) { count++ })
				if p.Status != capturestatus.Incomplete && p.Status != capturestatus.Complete {
					t.Fatal(p)
				}
			}
			if count != 100 || d.captured != len(input) {
				t.Fatalf("events=%d captured=%d", count, d.captured)
			}
		}
	}
}
