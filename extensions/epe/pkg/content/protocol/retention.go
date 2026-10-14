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
	"encoding/json"
	"strings"
)

// retention bounds payload accumulated across SSE events, separately from the
// decoder's single-event limit. Overflow drops payload, but keeps usage parsing.
type retention struct {
	limit     int
	used      int
	items     int
	enabled   bool
	truncated bool
}

func (r *retention) reserve(n int) bool {
	if !r.enabled || r.truncated {
		return false
	}
	if n > r.limit-r.used {
		r.truncated = true
		return false
	}
	r.used += n
	return true
}

func (r *retention) keep(value any) bool {
	if !r.enabled || r.truncated {
		return false
	}
	data, err := json.Marshal(value)
	return err == nil && r.reserve(len(data))
}

func (r *retention) keepRaw(raw json.RawMessage) bool {
	if !r.enabled || r.truncated {
		return false
	}
	return r.keep(rawValue(raw))
}

func (r *retention) item() bool {
	// Even metadata-only parsing needs bounded choice/block state for completion checks.
	r.items++
	return r.items <= 1024
}

func (r *retention) append(dst *strings.Builder, text string) bool {
	if !r.reserve(len(text)) {
		return false
	}
	dst.WriteString(text)
	return true
}
