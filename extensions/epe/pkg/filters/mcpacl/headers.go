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

// MCP 2026-07-28 header value encoding and decoding.
package mcpacl

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// base64SentinelPrefix and base64SentinelSuffix delimit the Base64 sentinel
// encoding defined by MCP 2026-07-28 (SEP-2243) for header values that
// cannot be safely represented as plain ASCII — non-ASCII characters,
// control characters, or leading/trailing whitespace. The format is:
//
//	=?base64?<Base64-of-UTF-8>?=
//
// The MCP spec says "Base64 encoding of the UTF-8 representation" without
// naming a specific RFC for the Base64 scheme; standard Base64 (A-Za-z0-9+/
// with = padding) is what the spec examples use. The markers are
// case-sensitive and must be lowercase. The entire value must be wrapped
// (all-or-nothing); partial encoding is not supported.
const (
	base64SentinelPrefix = "=?base64?"
	base64SentinelSuffix = "?="
)

// canonicalBase64 matches valid standard Base64 with required padding.
// Invalid padding, invalid characters, or non-canonical form do not match.
var canonicalBase64 = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)

// decodeMcpHeaderValue decodes the Base64 sentinel encoding used by MCP
// 2026-07-28 for header values containing non-ASCII characters. Values
// without the sentinel prefix are returned as-is (plain literal).
//
// Returns (decoded, true) on success — including plain literals that need
// no decoding. Returns (original, false) when the value matches the
// sentinel pattern but is invalid (bad padding, invalid characters, or
// invalid UTF-8 after decoding). Callers should treat a false result as
// "header value unusable" and fall back to body-based evaluation.
func decodeMcpHeaderValue(v string) (string, bool) {
	if !strings.HasPrefix(v, base64SentinelPrefix) || !strings.HasSuffix(v, base64SentinelSuffix) {
		return v, true // plain literal, not encoded
	}
	encoded := v[len(base64SentinelPrefix):]
	if strings.HasSuffix(encoded, base64SentinelSuffix) {
		encoded = encoded[:len(encoded)-len(base64SentinelSuffix)]
	}
	if !canonicalBase64.MatchString(encoded) {
		return v, false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return v, false
	}
	if !utf8.Valid(decoded) {
		return v, false
	}
	return string(decoded), true
}
