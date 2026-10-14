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

import capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"

// documentDecoder collects one bounded document and releases it at HTTP EOF.
// JSON and text share this framing.
type documentDecoder struct {
	limit  int
	buffer []byte
	decode func([]byte) (any, capturestatus.Code)
}

func (d *documentDecoder) Feed(chunk []byte, complete bool, emit func(any)) Progress {
	if len(chunk) > d.limit-len(d.buffer) {
		captured := len(d.buffer)
		d.buffer = nil
		return Progress{CapturedBytes: captured, Status: capturestatus.TooLarge}
	}
	// Bound capacity as well as length; never retain the caller's slice.
	if needed := len(d.buffer) + len(chunk); needed > cap(d.buffer) {
		capacity := min(d.limit, max(needed, 2*cap(d.buffer), 512))
		grown := make([]byte, len(d.buffer), capacity)
		copy(grown, d.buffer)
		d.buffer = grown
	}
	d.buffer = append(d.buffer, chunk...)
	progress := Progress{CapturedBytes: len(d.buffer), Status: capturestatus.Incomplete}
	if complete {
		value, status := d.decode(d.buffer)
		d.buffer = nil
		progress.Status = status
		if status == capturestatus.Complete {
			emit(value)
		}
	}
	return progress
}
