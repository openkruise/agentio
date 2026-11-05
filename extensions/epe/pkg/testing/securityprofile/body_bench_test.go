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
package securityprofile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

// BenchmarkRequestMCP exercises resolution, header processing, buffering,
// body authorization and audit logging through the ext_proc harness.
func BenchmarkRequestMCP(b *testing.B) {
	for _, size := range []int{0, 4096, 65536} {
		for _, allowed := range []bool{true, false} {
			b.Run(fmt.Sprintf("padding=%d/allowed=%t", size, allowed), func(b *testing.B) {
				h := New(b, Options{DisableResolutionProbe: true})
				h.Fixture.ApplyYAML(mcpPolicyYAML)
				tool := "unlisted-tool"
				if allowed {
					tool = "allowed-tool"
				}
				body := []byte(
					fmt.Sprintf(
						`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":%q,"arguments":{"padding":%q}}}`,
						tool,
						strings.Repeat("x", size),
					),
				)
				msgs := benchRequest("/mcp").Header("mcp-protocol-version", "2025-11-25").Body(body).Build()
				verdict := h.RunMessages(b, msgs)
				if verdict.Err != nil || verdict.ModeOverride == nil {
					b.Fatalf("body path not exercised: %+v", verdict)
				}
				if allowed && verdict.Kind == enginetest.VerdictBlocked {
					b.Fatalf("allowed tool blocked: %+v", verdict)
				}
				if !allowed && verdict.ImmediateStatus != 451 {
					b.Fatalf("denied tool not blocked: %+v", verdict)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					benchSink = h.RunMessages(b, msgs)
				}
			})
		}
	}
}

// BenchmarkRequestMCPChain checks scaling when several matching profiles each
// register a body callback for the same request.
func BenchmarkRequestMCPChain(b *testing.B) {
	for _, count := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("profiles=%d", count), func(b *testing.B) {
			h := New(b, Options{DisableResolutionProbe: true})
			for i := range count {
				h.Fixture.ApplyYAML(
					strings.Replace(mcpPolicyYAML, "name: mcp-whitelist", fmt.Sprintf("name: mcp-%d", i), 1),
				)
			}
			msgs := benchRequest("/mcp").Header("mcp-protocol-version", "2025-11-25").
				Body([]byte(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"allowed-tool"}}`)).
				Build()
			verdict := h.RunMessages(b, msgs)
			if verdict.Err != nil || verdict.ModeOverride == nil || verdict.Kind == enginetest.VerdictBlocked {
				b.Fatalf("allowed body path not exercised: %+v", verdict)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				benchSink = h.RunMessages(b, msgs)
			}
		})
	}
}
