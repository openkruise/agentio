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
package mcpacl

import (
	"encoding/base64"
	"testing"
)

func TestDecodeMcpHeaderValue(t *testing.T) {
	// "Hello, 世界" encoded as =?base64?SGVsbG8sIOS4lueVjA==?=
	helloWorld := "Hello, 世界"
	helloWorldB64 := base64.StdEncoding.EncodeToString([]byte(helloWorld))

	// " 日本語 " (leading/trailing space, non-ASCII) — encoded
	japanese := " 日本語 "
	japaneseB64 := base64.StdEncoding.EncodeToString([]byte(japanese))

	cases := []struct {
		name   string
		input  string
		want   string
		wantOk bool
	}{
		// Plain literals — returned as-is, ok=true.
		{"plain ASCII", "allowed-tool", "allowed-tool", true},
		{"plain with internal spaces", "my tool", "my tool", true},
		{"plain with hyphens", "read-file", "read-file", true},
		{"empty string", "", "", true},

		// Valid Base64 sentinel — decoded, ok=true.
		{"valid: Hello 世界", base64SentinelPrefix + helloWorldB64 + base64SentinelSuffix, helloWorld, true},
		{"valid: Japanese with spaces", base64SentinelPrefix + japaneseB64 + base64SentinelSuffix, japanese, true},
		{"valid: simple ASCII encoded", base64SentinelPrefix + base64.StdEncoding.EncodeToString([]byte("get_weather")) + base64SentinelSuffix, "get_weather", true},
		{"valid: empty payload", base64SentinelPrefix + "" + base64SentinelSuffix, "", true},

		// Invalid — matches sentinel pattern but bad content, ok=false.
		{"invalid: bad padding", base64SentinelPrefix + "SGVsbG8" + base64SentinelSuffix, base64SentinelPrefix + "SGVsbG8" + base64SentinelSuffix, false},
		{"invalid: bad characters", base64SentinelPrefix + "SGVs!!!bG8=" + base64SentinelSuffix, base64SentinelPrefix + "SGVs!!!bG8=" + base64SentinelSuffix, false},

		// Not matching sentinel pattern — treated as plain literal, ok=true.
		{"missing prefix", "SGVsbG8=", "SGVsbG8=", true},
		{"missing suffix", base64SentinelPrefix + "SGVsbG8=", base64SentinelPrefix + "SGVsbG8=", true},
		{"non-lowercase prefix", "=?BASE64?SGVsbG8=?=", "=?BASE64?SGVsbG8=?=", true},
		{"partial encoding (prefix only)", "prefix" + base64SentinelPrefix + "dGVzdA==" + base64SentinelSuffix, "prefix" + base64SentinelPrefix + "dGVzdA==" + base64SentinelSuffix, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeMcpHeaderValue(tc.input)
			if got != tc.want || ok != tc.wantOk {
				t.Errorf("decodeMcpHeaderValue(%q) = (%q, %v), want (%q, %v)", tc.input, got, ok, tc.want, tc.wantOk)
			}
		})
	}
}
