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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"unicode/utf16"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

const deniedCall = `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"denied-tool"}}`
const allowedCall = `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"allowed-tool"}}`

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func utf16leBytes(s string, bom bool) []byte {
	var out []byte
	if bom {
		out = append(out, 0xFF, 0xFE)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

// blacklistCfg allows by default and denies one named tool. This is the posture
// that makes an unreadable tool name dangerous: falling through to
// defaultAction admits the call.
func blacklistCfg() Config {
	return Config{
		DefaultAction: "allow",
		DenyStatus:    451,
		DenyBody:      "denied-by-blacklist",
		Rules:         []RuleEntry{{Method: "tools/call", ToolNames: []string{"denied-tool"}, Action: actionDeny}},
	}
}

// runRawBody drives the body phase with raw bytes and caller-supplied headers,
// defaulting the protocol version to a supported one.
func runRawBody(t *testing.T, cfg Config, headers map[string]string, body []byte) filter.Action {
	t.Helper()
	if headers == nil {
		headers = map[string]string{}
	}
	if _, ok := headers[mcpProtocolVersionHeader]; !ok {
		headers[mcpProtocolVersionHeader] = "2025-11-25"
	}
	st := &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Headers: headers}}}
	f := New(filter.RuleConfig[Config]{ID: filter.UnitID{Scope: "ns/p", Name: "r"}, Cfg: cfg})
	act, err := f.OnRequestBody(context.Background(), st, filter.Body{Bytes: body, Complete: true})
	if err != nil {
		t.Fatalf("OnRequestBody: %v", err)
	}
	return act
}

// nestedGzip compresses payload through n gzip layers.
func nestedGzip(t *testing.T, payload []byte, n int) []byte {
	t.Helper()
	cur := payload
	for range n {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(cur); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		cur = buf.Bytes()
	}
	return cur
}

// exactAllowCfg builds the blacklist posture with the rule action spelled as
// given, to prove that only an exact "allow" allows.
func exactAllowCfg(action string) Config {
	return Config{
		DefaultAction: "allow",
		Rules:         []RuleEntry{{Method: "tools/call", ToolNames: []string{"denied-tool"}, Action: action}},
	}
}

// TestOnRequestBody drives the body-normalization and action-normalization
// decisions through one table: each case is a config, an on-the-wire body
// (plus optional headers), and the verdict the filter must reach.
func TestOnRequestBody(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		headers map[string]string
		body    func(t *testing.T) []byte
		want    filter.ActionKind
	}{
		{
			// A gzip-encoded tools/call must be decompressed and judged, not
			// waved through because the raw bytes failed to parse.
			// express.json inflates gzip request bodies by default, so a
			// decompressing MCP server executes what the ACL never read.
			name:    "gzip-encoded denied call is decoded and judged",
			cfg:     blacklistCfg(),
			headers: map[string]string{"content-encoding": "gzip"},
			body:    func(t *testing.T) []byte { return gzipped(t, deniedCall) },
			want:    filter.KindStop,
		},
		{
			// The allowed tool must survive the same encoding: normalization
			// exists so legitimate compressed clients keep working rather than
			// being denied.
			name:    "gzip-encoded allowed call passes",
			cfg:     whitelistCfg(),
			headers: map[string]string{"content-encoding": "gzip"},
			body:    func(t *testing.T) []byte { return gzipped(t, allowedCall) },
			want:    filter.KindContinue,
		},
		{
			// A UTF-8 BOM must not hide the message. Go's json rejects a
			// leading BOM, but System.Text.Json — the official C# MCP SDK's
			// ASP.NET Core path — skips it.
			name: "BOM-prefixed call is judged",
			cfg:  blacklistCfg(),
			body: func(*testing.T) []byte { return append([]byte{0xEF, 0xBB, 0xBF}, deniedCall...) },
			want: filter.KindStop,
		},
		{
			// A BOM must likewise not hide a batch array from the framing
			// check: the BOM is stripped first, so the batch is still detected.
			// The detected violation is then decided by defaultAction, which is
			// allow in this arm.
			name: "BOM-prefixed batch follows defaultAction",
			cfg:  blacklistCfg(),
			body: func(*testing.T) []byte { return append([]byte{0xEF, 0xBB, 0xBF}, "["+deniedCall+"]"...) },
			want: filter.KindContinue,
		},
		{
			// UTF-16 with a BOM is auto-detected by Jackson byte-based stacks,
			// so it must be transcoded and judged rather than passed through.
			name: "UTF-16 call is judged",
			cfg:  blacklistCfg(),
			body: func(*testing.T) []byte { return utf16leBytes(deniedCall, true) },
			want: filter.KindStop,
		},
		{
			// A governed call whose params.name is absent cannot be attributed
			// to a tool rule, so defaultAction decides. The accepted
			// consequence on this arm: omitting the name evades every
			// tool-scoped rule under a blacklist. whitelistCfg denies it.
			name: "governed call with absent tool name follows defaultAction",
			cfg:  blacklistCfg(),
			body: func(*testing.T) []byte { return []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`) },
			want: filter.KindContinue,
		},
		{
			// A non-string params.name used to break the whole unmarshal,
			// which made the method unreadable too and bypassed even a
			// whitelist policy.
			name: "non-string tool name is denied under whitelist",
			cfg:  whitelistCfg(),
			body: func(*testing.T) []byte {
				return []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":123}}`)
			},
			want: filter.KindStop,
		},
		{
			// An empty body carries no JSON-RPC message — there is nothing to
			// govern, and denying it would break every request that has no
			// body at all.
			name: "empty body passes",
			cfg:  whitelistCfg(),
			body: func(*testing.T) []byte { return nil },
			want: filter.KindContinue,
		},
		{
			// Each declared coding is another decompression pass over up to
			// 8MiB, and the list is client-supplied, so a long chain is still
			// refused outright rather than executed: four nested gzip layers of
			// 1MiB of zeros is ~115 bytes on the wire but expands to 1MiB, and
			// nothing bounds how many layers a client may claim. That refusal —
			// the decompression bomb guard — is unchanged; what defaultAction
			// decides is only the verdict on the request whose body was refused,
			// so under a blacklist it is forwarded still compressed and the
			// upstream decides what to do with it.
			name:    "long coding chain is refused, verdict follows defaultAction",
			cfg:     blacklistCfg(),
			headers: map[string]string{"content-encoding": "gzip, gzip, gzip, gzip"},
			body:    func(t *testing.T) []byte { return nestedGzip(t, make([]byte, 1<<20), 4) },
			want:    filter.KindContinue,
		},
		{
			// A single coding — what real clients send — still works.
			name:    "single coding still decodes",
			cfg:     blacklistCfg(),
			headers: map[string]string{"content-encoding": "gzip"},
			body:    func(t *testing.T) []byte { return gzipped(t, deniedCall) },
			want:    filter.KindStop,
		},
		{
			// An ungoverned method still passes after normalization.
			name: "ungoverned method passes",
			cfg:  whitelistCfg(),
			body: func(*testing.T) []byte { return []byte(`{"jsonrpc":"2.0","method":"tools/list"}`) },
			want: filter.KindContinue,
		},

		// Only an exact "allow" allows. A deny used to need the exact spelling
		// instead, so any other value — a differently-cased "Deny", a typo, an
		// un-defaulted empty string — read as allow and silently disabled the
		// rule it was written for. The permissive value is the one that must
		// be spelled exactly, matching how tokentransform resolves
		// failStrategy.
		{
			name: `rule action "Deny" still denies`,
			cfg:  exactAllowCfg("Deny"),
			body: func(*testing.T) []byte { return []byte(deniedCall) },
			want: filter.KindStop,
		},
		{
			name: `rule action "DENY" still denies`,
			cfg:  exactAllowCfg("DENY"),
			body: func(*testing.T) []byte { return []byte(deniedCall) },
			want: filter.KindStop,
		},
		{
			name: `rule action " deny " still denies`,
			cfg:  exactAllowCfg(" deny "),
			body: func(*testing.T) []byte { return []byte(deniedCall) },
			want: filter.KindStop,
		},
		{
			name: `rule action "bogus" still denies`,
			cfg:  exactAllowCfg("bogus"),
			body: func(*testing.T) []byte { return []byte(deniedCall) },
			want: filter.KindStop,
		},
		{
			name: "empty rule action still denies",
			cfg:  exactAllowCfg(""),
			body: func(*testing.T) []byte { return []byte(deniedCall) },
			want: filter.KindStop,
		},

		// The same rule applies to defaultAction: an unrecognized value
		// denies.
		{
			name: `defaultAction "Allow" denies an unmatched call`,
			cfg:  Config{DefaultAction: "Allow"},
			body: func(*testing.T) []byte { return []byte(deniedCall) },
			want: filter.KindStop,
		},
		{
			name: `defaultAction "bogus" denies an unmatched call`,
			cfg:  Config{DefaultAction: "bogus"},
			body: func(*testing.T) []byte { return []byte(deniedCall) },
			want: filter.KindStop,
		},
		{
			name: "empty defaultAction denies an unmatched call",
			cfg:  Config{DefaultAction: ""},
			body: func(*testing.T) []byte { return []byte(deniedCall) },
			want: filter.KindStop,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			act := runRawBody(t, tc.cfg, tc.headers, tc.body(t))
			if act.Kind() != tc.want {
				t.Fatalf("OnRequestBody kind = %v, want %v", act.Kind(), tc.want)
			}
		})
	}
}

// Casing is normalized rather than punished: an operator who wrote "Allow"
// meant allow, and failing that closed would be a surprise, not a safeguard.
//
// Driven through parse so it proves the payload path applies the
// normalization, not merely that normalizeActions exists.
func TestParse_NormalizesActionCasing(t *testing.T) {
	for _, action := range []string{"Allow", "ALLOW", " allow "} {
		payload := fmt.Sprintf(
			`{"defaultAction":"deny","rules":[{"method":"tools/call","toolNames":["denied-tool"],"action":%q}]}`,
			action)
		cfg, err := parse([]byte(payload))
		if err != nil {
			t.Fatalf("parse(%q): %v", action, err)
		}
		act := runRawBody(t, cfg, nil, []byte(deniedCall))
		if act.Kind() != filter.KindContinue {
			t.Errorf("rule action %q was not honoured as allow", action)
		}
	}
}

// And to unsupportedVersionAction, where only an exact "passthrough" skips the
// ACL. Casing is normalized there too, again through parse.
func TestParse_NormalizesUnsupportedVersionAction(t *testing.T) {
	cfg, err := parse([]byte(`{"defaultAction":"deny","unsupportedVersionAction":"Passthrough"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	act := runRawBody(t, cfg, map[string]string{mcpProtocolVersionHeader: "1999-01-01"}, []byte(deniedCall))
	if act.Kind() != filter.KindContinue {
		t.Errorf("unsupportedVersionAction %q was not honoured as passthrough", "Passthrough")
	}
}
