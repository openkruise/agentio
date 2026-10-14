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
	"strings"
	"unicode/utf8"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

// Event is one complete SSE event. Reconnection fields are not exposed.
type Event struct {
	Type string
	Data string
}

type sseDecoder struct {
	limit      int
	captured   int
	eventBytes int
	line       []byte
	data       []byte
	event      string
	firstLine  bool
	skipLF     bool
}

func (d *sseDecoder) Feed(chunk []byte, complete bool, emit func(any)) Progress {
	for _, b := range chunk {
		if d.skipLF {
			d.skipLF = false
			if b == '\n' {
				if d.eventBytes != 0 {
					if d.eventBytes == d.limit {
						d.line, d.data = nil, nil
						return Progress{CapturedBytes: d.captured, Status: capturestatus.TooLarge}
					}
					d.eventBytes++
				}
				d.captured++
				continue
			}
		}
		if d.eventBytes == d.limit {
			d.line, d.data = nil, nil
			return Progress{CapturedBytes: d.captured, Status: capturestatus.TooLarge}
		}
		d.eventBytes++
		d.captured++
		if b == '\r' || b == '\n' {
			if !d.consumeLine(emit) {
				return Progress{CapturedBytes: d.captured, Status: capturestatus.InvalidSSE}
			}
			d.line = d.line[:0]
			d.skipLF = b == '\r'
		} else {
			d.line = boundedAppend(d.line, []byte{b}, d.limit)
		}
	}
	status := capturestatus.Incomplete
	if complete {
		// SSE dispatch requires a blank line; HTTP EOF never completes a partial event.
		d.line, d.data = nil, nil
		status = capturestatus.Complete
	}
	return Progress{CapturedBytes: d.captured, Status: status}
}

func (d *sseDecoder) consumeLine(emit func(any)) bool {
	line := d.line
	if d.firstLine {
		line = bytes.TrimPrefix(line, []byte{0xef, 0xbb, 0xbf})
		d.firstLine = false
	}
	if !utf8.Valid(line) {
		return false
	}
	if len(line) == 0 {
		d.eventBytes = 0
		if len(d.data) > 0 {
			event := d.event
			if event == "" {
				event = "message"
			}
			emit(Event{Type: event, Data: string(d.data[:len(d.data)-1])})
		}
		d.data = d.data[:0]
		d.event = ""
		return true
	}
	if line[0] == ':' {
		return true
	}
	field, value, _ := strings.Cut(string(line), ":")
	value = strings.TrimPrefix(value, " ")
	switch field {
	case "event":
		d.event = value
	case "data":
		d.data = boundedAppend(d.data, []byte(value), d.limit)
		d.data = boundedAppend(d.data, []byte{'\n'}, d.limit)
	}
	return true
}

func boundedAppend(dst, src []byte, limit int) []byte {
	if needed := len(dst) + len(src); needed > cap(dst) {
		grown := make([]byte, len(dst), min(limit, max(needed, 2*cap(dst), 512)))
		copy(grown, dst)
		dst = grown
	}
	return append(dst, src...)
}
