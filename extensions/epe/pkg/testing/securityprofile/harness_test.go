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

// The tests here prove the harness itself works: request assembly, verdict
// parsing, probe capture, access-log capture, and fixture admission. Feature
// scenarios live next to the behavior they exercise (see doc.go).
package securityprofile

import (
	"fmt"
	"strings"
	"testing"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

var testLabels = map[string]string{"app": "sandbox"}

func testRequest(path string) *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", "server.example.com", path).
		Workload("test-ns", "sandbox-pod", testLabels)
}

func blockProfileYAML(name, path string, status int, body string, priority int) string {
	priorityYAML := ""
	if priority >= 0 {
		priorityYAML = fmt.Sprintf("  priority: %d\n", priority)
	}
	return fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: %s
  namespace: test-ns
spec:
%s  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: block
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: %s
    actions:
      block:
        statusCode: %d
        body: %s
`, name, priorityYAML, path, status, body)
}

func bypassProfileYAML(name, path string, priority int) string {
	priorityYAML := ""
	if priority >= 0 {
		priorityYAML = fmt.Sprintf("  priority: %d\n", priority)
	}
	return fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: %s
  namespace: test-ns
spec:
%s  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: bypass
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: %s
    actions:
      bypass: true
`, name, priorityYAML, path)
}

func TestHarness_BlockAndNearMiss(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockProfileYAML("block", "/blocked", 451, "blocked-by-test", -1))

	h.Run(t, testRequest("/blocked")).RequireBlockedBody(t, 451, "blocked-by-test")
	h.Run(t, testRequest("/blocked/near-miss")).RequirePassthrough(t)
}

func TestHarness_BypassDistinguishedFromPassthrough(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(bypassProfileYAML("bypass", "/bypassed", -1))

	bypassed := h.Run(t, testRequest("/bypassed"))
	bypassed.RequireBypassed(t)
	// The test's name is about telling bypass from passthrough, which after the
	// outcome derivation needs the action, not just the outcome.
	bypassed.RequireAction(t, ":bypass:")
	h.Run(t, testRequest("/other")).RequirePassthrough(t)
}

func TestHarness_ProcessUnknownMessageReturnsUnknown(t *testing.T) {
	h := New(t, Options{})
	verdict := h.RunMessages(t, []*extProcPb.ProcessingRequest{{}})
	verdict.RequireGRPCCode(t, codes.Unknown)
}

func TestHarness_AccessLogCapturesOutcome(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockProfileYAML("block", "/logged", 451, "blocked-logged", -1))

	verdict := h.Run(t, testRequest("/logged").RequestID("req-123"))
	verdict.RequireBlocked(t, 451)

	e := accessLogEntry(t, verdict)
	if e.RequestID != "req-123" {
		t.Errorf("access log request id = %q, want req-123", e.RequestID)
	}
	if e.Outcome != "blocked" {
		t.Errorf("access log outcome = %q, want blocked", e.Outcome)
	}
}

func TestFixture_ValidationRejectsInvalidProfiles(t *testing.T) {
	f := NewFixture(t)
	base := `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: invalid
  namespace: test-ns
spec:
%s`
	tests := []struct {
		name string
		spec string
	}{
		{
			name: "status code below range",
			spec: `  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: r
    match:
    - domains:
      - example.com
    actions:
      block:
        statusCode: 99
`,
		},
		{
			name: "missing rule name",
			spec: `  selector:
    matchLabels:
      app: sandbox
  rules:
  - match:
    - domains:
      - example.com
    actions:
      block: {}
`,
		},
		{
			name: "path too long",
			spec: fmt.Sprintf(`  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: r
    match:
    - domains:
      - example.com
      paths:
      - type: Exact
        value: %s
    actions:
      block: {}
`, strings.Repeat("a", 257)),
		},
		{
			name: "negative priority",
			spec: `  priority: -1
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: r
    match:
    - domains:
      - example.com
    actions:
      block: {}
`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.ValidateYAML(fmt.Sprintf(base, tc.spec)); err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}

	if err := f.ValidateYAML(blockProfileYAML("valid", "/ok", 451, "ok", 100)); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}

	// The CRD deliberately allows method matches without paths.
	methodsWithoutPaths := `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: methods-only
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: r
    match:
    - domains:
      - example.com
      methods:
      - POST
    actions:
      block: {}
`
	if err := f.ValidateYAML(methodsWithoutPaths); err != nil {
		t.Fatalf("methods-without-paths profile rejected: %v", err)
	}
}

func TestHarness_ProbeCapturesMatchedRules(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(blockProfileYAML("block", "/probed", 451, "blocked-probe", -1))

	verdict := h.Run(t, testRequest("/probed"))
	verdict.RequireBlocked(t, 451)
	if verdict.Info == nil {
		t.Fatal("no stream info captured")
	}
	if verdict.Info.Outcome.String() != "blocked" {
		t.Errorf("outcome = %q, want blocked", verdict.Info.Outcome)
	}
	if len(verdict.Info.Matched) == 0 {
		t.Error("stream info has no matched units")
	}
}
