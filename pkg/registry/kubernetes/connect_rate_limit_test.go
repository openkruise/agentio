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

package kubernetes

import (
	"strings"
	"testing"
)

func TestConnectRateLimitGroupingAtBothEntrypoints(t *testing.T) {
	valid := `connectRateLimit:
  rateLimits:
  - actions:
    - filterState: {key: agentio.sandbox.uid, descriptorKey: sandbox}
    - genericKey: {descriptorKey: class, descriptorValue: default}
  descriptors:
  - entries: [{key: sandbox}, {key: class, value: default}]
    tokenBucket: {maxTokens: 10, tokensPerFill: 2, fillInterval: 1s}
`
	for _, tc := range []struct {
		name    string
		content string
		valid   bool
	}{
		{"grouped", valid, true},
		{"global shorthand", "connectRateLimit:\n  tokenBucket: {maxTokens: 10, fillInterval: 1s}\n", true},
		{"legacy CEL", "connectRateLimit:\n  descriptors:\n  - entries: [{key: sandbox, cel: 'filter_state[\"agentio.sandbox.uid\"]'}]\n    tokenBucket: {maxTokens: 10, fillInterval: 1s}\n", true},
		{"mixed CEL", strings.Replace(valid, "{key: sandbox}", "{key: sandbox, cel: 'filter_state[\"agentio.sandbox.uid\"]'}", 1), false},
		{"wrong order", strings.Replace(valid, "[{key: sandbox}, {key: class, value: default}]", "[{key: class, value: default}, {key: sandbox}]", 1), false},
		{"missing source", strings.Replace(valid, "key: agentio.sandbox.uid", `key: ""`, 1), false},
		{"empty fixed value", strings.Replace(valid, "descriptorValue: default", `descriptorValue: ""`, 1), false},
		{"two sources", strings.Replace(valid, "    - genericKey:", "      genericKey:", 1), false},
		{"per connection wildcard", valid + "  perDownstreamConnection: true\n", false},
		{"missing descriptors", strings.Split(valid, "  descriptors:")[0], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeEgressGateway(tc.content)
			if (err == nil) != tc.valid {
				t.Fatalf("Gateway parameters error = %v", err)
			}
			_, err = applyAgentioConfig("egressGateways:\n- name: egress\n  namespace: agentio-system\n  "+
				strings.ReplaceAll(strings.TrimSuffix(tc.content, "\n"), "\n", "\n  "), nil)
			if (err == nil) != tc.valid {
				t.Fatalf("AgentioConfig error = %v", err)
			}
		})
	}
}
