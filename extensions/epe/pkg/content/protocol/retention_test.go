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
	"testing"
)

func TestKeepRawSkipsUnretainedContent(t *testing.T) {
	raw := json.RawMessage(`{"text":"` + strings.Repeat("x", 4096) + `"}`)
	for _, r := range []retention{{limit: 8192}, {limit: 8192, enabled: true, truncated: true}} {
		before := r
		allocs := testing.AllocsPerRun(10, func() {
			if r.keepRaw(raw) {
				t.Fatal("retained disabled content")
			}
		})
		if allocs != 0 || r != before {
			t.Fatalf("allocations=%v retention=%+v", allocs, r)
		}
	}
	for _, limit := range []int{len(raw), len(raw) - 1} {
		r := retention{enabled: true, limit: limit}
		got := r.keepRaw(raw)
		if got != (limit == len(raw)) || r.truncated != !got {
			t.Fatalf("limit=%d retained=%v state=%+v", limit, got, r)
		}
	}
}
