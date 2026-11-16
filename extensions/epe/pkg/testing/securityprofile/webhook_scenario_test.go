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

// Full-chain audit webhook delivery scenarios: profile audit config through
// the router and webhook sink to an in-process receiver.
package securityprofile

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/pkg/dns"
)

func webhookAuditProfileYAML(receiverURL string) string {
	return fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: audit-profile
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  audit:
  - name: on-block
    when: 'result == "blocked"'
    webhook:
      url: '%s/{{ .Request.Header "x-audit-marker" }}'
      request:
        method: POST
        headers:
        - name: X-Audit-Profile
          value: '{{ .Profile.Name }}'
        body:
          json:
            path: '{{ .Request.Path }}'
            rule: '{{ .Rule.Name }}'
  rules:
  - name: audited-block
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /audited
    actions:
      block:
        statusCode: 451
        body: blocked-audited
`, receiverURL)
}

// auditedRequest builds a request from the test-ns pod the audit profile
// selects.
func auditedRequest(path string) *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", "server.example.com", path).
		Workload("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"})
}

func newWebhookAuditHarness(t *testing.T, mode enginetest.AuditMode) (*Harness, *enginetest.AuditReceiver) {
	t.Helper()
	receiver := enginetest.NewAuditReceiver(t)
	wiring := enginetest.WireAudit(t, enginetest.AuditOptions{Mode: mode})
	h := New(t, Options{AuditRouter: wiring.Router})
	h.Fixture.ApplyYAML(webhookAuditProfileYAML(receiver.URL("")))
	return h, receiver
}

func TestScenario_AuditBlockDeliversWebhookSynchronously(t *testing.T) {
	h, receiver := newWebhookAuditHarness(t, enginetest.AuditSync)

	marker := "sync-block-marker"
	h.Run(t, auditedRequest("/audited").Header("x-audit-marker", marker)).
		RequireBlockedBody(t, 451, "blocked-audited")

	// Sync mode: delivery finished before Run returned.
	hits := receiver.Matching(marker)
	if len(hits) != 1 {
		t.Fatalf("audit deliveries containing %q = %d, want 1 (%+v)", marker, len(hits), hits)
	}
	got := hits[0]
	if got.Method != http.MethodPost {
		t.Errorf("audit method = %q, want POST", got.Method)
	}
	if !strings.HasSuffix(got.URL, "/"+marker) {
		t.Errorf("audit URL = %q, want template-rendered marker suffix", got.URL)
	}
	if profileHeader := got.Header.Get("X-Audit-Profile"); profileHeader != "audit-profile" {
		t.Errorf("X-Audit-Profile = %q, want audit-profile", profileHeader)
	}
	body := string(got.Body)
	for _, want := range []string{`"path":"/audited"`, `"rule":"audited-block"`} {
		if !strings.Contains(body, want) {
			t.Errorf("audit body = %s, want it to contain %s", body, want)
		}
	}
}

func TestScenario_AuditNonMatchingRequestDoesNotDeliver(t *testing.T) {
	h, receiver := newWebhookAuditHarness(t, enginetest.AuditSync)

	marker := "absent-marker"
	h.Run(t, auditedRequest("/not-audited").Header("x-audit-marker", marker)).
		RequirePassthrough(t)

	receiver.AssertAbsent(t, marker)
}

func TestScenario_AuditWhenConditionFiltersPassthrough(t *testing.T) {
	h, receiver := newWebhookAuditHarness(t, enginetest.AuditSync)

	// The rule matches nothing for this path, so result is "passthrough"
	// and the `result == "blocked"` condition must suppress delivery even
	// though the profile itself selected the workload.
	marker := "when-filtered-marker"
	h.Run(t, auditedRequest("/audited/near-miss").Header("x-audit-marker", marker)).
		RequirePassthrough(t)
	receiver.AssertAbsent(t, marker)
}

func TestScenario_AuditReceiverErrorDoesNotAffectBlockResponse(t *testing.T) {
	h, receiver := newWebhookAuditHarness(t, enginetest.AuditSync)
	receiver.SetResponse(http.StatusServiceUnavailable, "receiver-down")

	marker := "http-error-marker"
	h.Run(t, auditedRequest("/audited").Header("x-audit-marker", marker)).
		RequireBlockedBody(t, 451, "blocked-audited")

	// The delivery reached the receiver and failed there; the block
	// response above proves the failure stayed off the request path.
	if hits := receiver.Matching(marker); len(hits) != 1 {
		t.Fatalf("audit deliveries containing %q = %d, want 1", marker, len(hits))
	}
}

func TestScenario_AuditUnreachableSinkDoesNotAffectBlockResponse(t *testing.T) {
	wiring := enginetest.WireAudit(t, enginetest.AuditOptions{Mode: enginetest.AuditSync})
	h := New(t, Options{AuditRouter: wiring.Router})
	// 127.0.0.1:1 refuses connections: transport_error path.
	h.Fixture.ApplyYAML(webhookAuditProfileYAML("http://127.0.0.1:1"))

	h.Run(t, auditedRequest("/audited").Header("x-audit-marker", "unreachable")).
		RequireBlockedBody(t, 451, "blocked-audited")
}

func TestScenario_AuditBufferedModeDelivers(t *testing.T) {
	h, receiver := newWebhookAuditHarness(t, enginetest.AuditBuffered)

	marker := "buffered-marker"
	h.Run(t, auditedRequest("/audited").Header("x-audit-marker", marker)).
		RequireBlockedBody(t, 451, "blocked-audited")

	receiver.WaitFor(t, marker, 5*time.Second)
}

func TestScenario_AuditAuthorizationConditions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		when       string
		deny       bool
		path       string
		want       string
		deliveries int
	}{
		{name: "bypass delivers", when: "bypassed", path: "/audited", want: "bypassed", deliveries: 1},
		{name: "pinning does not trigger mutated audit", when: "mutated", path: "/audited", want: "bypassed"},
		{name: "allow does not trigger blocked audit", when: "blocked", path: "/audited", want: "bypassed"},
		{name: "denial suppresses bypass audit", when: "bypassed", deny: true, path: "/audited", want: "blocked"},
		{name: "denial triggers blocked audit", when: "blocked", deny: true, path: "/audited", want: "blocked", deliveries: 1},
		{name: "unmatched rule does not deliver", when: "passthrough", path: "/not-audited", want: "passthrough"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receiver := enginetest.NewAuditReceiver(t)
			wiring := enginetest.WireAudit(t, enginetest.AuditOptions{Mode: enginetest.AuditBuffered})
			client := dns.NewClient(nil, time.Second)
			if err := client.SetRecord(
				"server.example.com",
				[]netip.Addr{netip.MustParseAddr("192.0.2.1")},
			); err != nil {
				t.Fatal(err)
			}

			h := New(t, Options{
				AuditRouter: wiring.Router,
				AuthorizeRequest: func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
					if tc.deny {
						stream.Info.RecordAuthorization(
							filter.AuthorizationDecision{
								Action: "deny",
								Reason: filter.AuthorizationReasonPolicyDenied,
							},
						)
						return nil, &filter.Reply{Status: 403}, nil
					}
					return egressauthz.NewAggregate(client).Authorize(ctx, stream)
				},
			})
			profile := strings.NewReplacer(
				`result == "blocked"`, fmt.Sprintf(`result == %q`, tc.when),
				"      block:\n        statusCode: 451\n        body: blocked-audited", "      bypass: true",
				"            path:", "            result: '{{ .Result }}'\n            path:",
			).Replace(webhookAuditProfileYAML(receiver.URL("")))
			h.Fixture.ApplyYAML(profile)

			marker := "authorized-audit"
			verdict := h.Run(t, auditedRequest(tc.path).DestinationPort(80).Header("x-audit-marker", marker))
			verdict.RequireOutcome(t, tc.want)
			if tc.deny {
				verdict.RequireBlocked(t, 403)
				verdict.RequireNoUpstream(t)
			} else {
				verdict.RequireUpstream(t, "192.0.2.1:80")
			}
			// Drain accepted events before asserting absence; no timing window or sleep.
			wiring.Drain(t)
			hits := receiver.Matching(marker)
			if len(hits) != tc.deliveries {
				t.Fatalf("audit deliveries = %d, want %d", len(hits), tc.deliveries)
			}
			if len(hits) > 0 && !strings.Contains(string(hits[0].Body), fmt.Sprintf(`"result":%q`, tc.want)) {
				t.Fatalf("webhook body does not contain final outcome %q: %s", tc.want, hits[0].Body)
			}
		})
	}
}
