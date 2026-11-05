// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/openkruise/agentio/extensions/epe/pkg/credential/credentialtest"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

// BenchmarkRequestSandboxToken covers full in-process ext_proc exchanges,
// excluding gRPC transport. The provider arm warms the real credential cache.
func BenchmarkRequestSandboxToken(b *testing.B) {
	for _, size := range []int{256, 2048, 8192} {
		for _, useProvider := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/provider=%t", size, useProvider), func(b *testing.B) {
				opts := Options{DisableResolutionProbe: true}
				var provider *credentialtest.FakeProvider
				if useProvider {
					provider = credentialtest.NewAPIKeyProvider(b, "provider-token")
					opts.Providers = providerRegistry(b, provider.Server.URL)
				}
				h := New(b, opts)
				if useProvider {
					h.Fixture.ApplyYAML(
						strings.Replace(secretInjectionProfileYAML(""), "kind: Secret", "kind: CredentialProvider", 1),
					)
				} else {
					h.Fixture.ApplyYAML(benchPassthroughProfileYAML("non-matching"))
				}
				msgs := benchRequest(
					injectionPath,
				).SandboxToken("r1", strings.Repeat("a", size), "sandbox-client").
					Build()
				verdict := h.RunMessages(b, msgs)
				if verdict.Err != nil {
					b.Fatal(verdict.Err)
				}
				if useProvider {
					if values := verdict.RequestHeaderValues(
						"Authorization",
					); len(values) != 1 ||
						values[0] != "Bearer provider-token" {
						b.Fatalf("unexpected credential mutation: %v", values)
					}
				} else {
					if verdict.Kind != enginetest.VerdictPassthrough {
						b.Fatalf("verdict = %s, want passthrough", verdict.Kind)
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = h.RunMessages(b, msgs)
				}
				b.StopTimer()
				if useProvider && provider.Calls.Load() != 1 {
					b.Fatalf("provider calls = %d, want 1 (cache hits)", provider.Calls.Load())
				}
			})
		}
	}
}
