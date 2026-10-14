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

// Full-chain audit access-log scenarios: one auditlog.Entry per request,
// asserted via the harness's capturing audit logger (Verdict.AccessLog).
package securityprofile

import (
	"testing"

	auditlog "github.com/openkruise/agentio/extensions/epe/pkg/audit/log"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

// accessLogEntry returns the single audit entry captured for this verdict.
// One request produces exactly one entry, and Verdict.AccessLog holds this run
// alone — the harness resets the logger per run — so any other count is a bug
// worth failing on rather than an index to reach past.
func accessLogEntry(t *testing.T, v *enginetest.Verdict) auditlog.Entry {
	t.Helper()
	if len(v.AccessLog) != 1 {
		t.Fatalf("want exactly 1 audit entry, got %d: %+v", len(v.AccessLog), v.AccessLog)
	}
	return v.AccessLog[0]
}

// TestHandleRequestHeaders_AuditEntry_NoProfileMatch_Passthrough verifies
// the passthrough path produces an audit entry with zero profiles and an
// empty actions list.
func TestHandleRequestHeaders_AuditEntry_NoProfileMatch_Passthrough(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(otherSelectorProfileYAML)

	verdict := h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x"))
	verdict.RequirePassthrough(t)

	e := accessLogEntry(t, verdict)
	if e.Outcome != "passthrough" {
		t.Errorf("outcome: want passthrough, got %q", e.Outcome)
	}
	if e.Units != 0 {
		t.Errorf("units: want 0, got %d", e.Units)
	}
	if len(e.Actions) != 0 || len(e.Skipped) != 0 || e.Error != "" {
		t.Errorf("expected empty actions/skipped/error, got %+v", e)
	}
	if e.Pod.Namespace != "default" || e.Pod.Name != "pod-x" {
		t.Errorf("pod: want default/pod-x, got %s", e.Pod)
	}
	if e.Method != "GET" || e.Host != "api.example.com" || e.Path != "/x" {
		t.Errorf("request fields wrong: %+v", e)
	}
}

// TestHandleRequestHeaders_AuditEntry_BypassMatched marks the entry as
// "bypassed" with the bypass action recorded.
func TestHandleRequestHeaders_AuditEntry_BypassMatched(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: trust-internal
    match:
    - domains:
      - internal.local
    actions:
      bypass: true
`))

	verdict := h.Run(t, blockedPeerRequest("GET", "internal.local", "/anything"))
	verdict.RequireBypassed(t)

	e := accessLogEntry(t, verdict)
	if e.Outcome != "bypassed" {
		t.Errorf("outcome: want bypassed, got %q", e.Outcome)
	}
	if got := e.Actions; len(got) != 1 || got[0] != "bypass:bypass:default/p1/trust-internal#0" {
		t.Errorf("actions: want [bypass:bypass:default/p1/trust-internal#0], got %v", got)
	}
	if len(e.Skipped) != 0 {
		t.Errorf("skipped: want empty, got %v", e.Skipped)
	}
}

// TestHandleRequestHeaders_AuditEntry_BlockMatched marks the entry as
// "blocked".
func TestHandleRequestHeaders_AuditEntry_BlockMatched(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockedAppProfileYAML(`  - name: block-admin
    match:
    - domains:
      - "*"
      paths:
      - type: Prefix
        value: /admin
    actions:
      block:
        statusCode: 403
`))

	verdict := h.Run(t, blockedPeerRequest("GET", "api.example.com", "/admin/keys"))
	verdict.RequireBlocked(t, 403)

	e := accessLogEntry(t, verdict)
	if e.Outcome != "blocked" {
		t.Errorf("outcome: want blocked, got %q", e.Outcome)
	}
	if got := e.Actions; len(got) != 1 || got[0] != "block:block:default/p1/block-admin#0" {
		t.Errorf("actions: want [block:block:default/p1/block-admin#0], got %v", got)
	}
}
