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
package attributes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// BenchmarkExtractSandboxToken measures unused, used, and repeated token access
// with synthetic opaque access tokens; JWT verification is not part of EPE.
func BenchmarkExtractSandboxToken(b *testing.B) {
	for _, size := range []int{0, 256, 2048, 8192} {
		fields := map[string]any{
			FilterStateDownstreamPeerNamespace: "default",
			FilterStateDownstreamPeerName:      "sandbox-pod",
			FilterStateSandboxLabels:           b64("app=sandbox"),
			AttrDestinationPort:                443,
		}
		if size > 0 {
			payload, err := json.Marshal(
				map[string]string{"requestId": "r1", "accessToken": strings.Repeat("a", size), "sandboxClientId": "c1"},
			)
			if err != nil {
				b.Fatal(err)
			}
			fields[FilterStateSandboxToken] = b64(string(payload))
		}
		attrs := makeAttrs(b, fields)
		headers := benchHeaders(0)
		for _, uses := range []int{0, 1, 2} {
			b.Run(fmt.Sprintf("bytes=%d/uses=%d", size, uses), func(b *testing.B) {
				ctx := context.Background()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					caller, req := Extract(ctx, headers, attrs)
					for range uses {
						benchSink = caller.Token.Parse(ctx)
					}
					benchSink = caller
					benchSink = req
				}
			})
		}
	}
}
