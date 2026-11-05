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

package securitypolicy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	utilexec "k8s.io/client-go/util/exec"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

const sniHTTPRule = `{name: inspect, match: [{domains: ["*"], schemes: [https]}], actions: {bypass: true}}`

const sniTLSProfileYAML = `
apiVersion: agents.kruise.io/v1alpha1
kind: {{ .Kind }}
metadata:
  name: {{ .Name }}
spec:
  priority: {{ .Priority }}
  selector:
    matchLabels:
      ` + sniPolicyLabel + `: {{ .Selector }}
  rules: {{ .Rules }}
`

var sniTLSCases = []struct {
	name      string
	rules     string
	apex      string
	subdomain string
	priority  int
}{
	{
		name:      "deny before HTTP",
		rules:     `[{name: deny, match: [{domains: [example.com], ports: [443]}], actions: {tls: {action: Deny}}}, ` + sniHTTPRule + `]`,
		apex:      "deny",
		subdomain: "terminate",
		priority:  10,
	},
	{
		name:      "passthrough before HTTP",
		rules:     `[{name: passthrough, match: [{domains: [example.com], ports: [443]}], actions: {tls: {action: Passthrough}}}, ` + sniHTTPRule + `]`,
		apex:      "passthrough",
		subdomain: "terminate",
		priority:  10,
	},
	{
		name: "first TLS action wins",
		rules: `[
    {name: passthrough, match: [{domains: ["*"]}], actions: {tls: {action: Passthrough}}},
    {name: deny, match: [{domains: ["*"]}], actions: {tls: {action: Deny}}}
  ]`,
		apex:      "passthrough",
		subdomain: "passthrough",
		priority:  10,
	},
	{
		name:      "HTTP before TLS action",
		rules:     `[` + sniHTTPRule + `, {name: deny, match: [{domains: ["*"]}], actions: {tls: {action: Deny}}}]`,
		apex:      "terminate",
		subdomain: "terminate",
		priority:  10,
	},
	{
		name: "domain and original port stay paired per match",
		rules: `[{name: ports, match: [
    {domains: [example.com], ports: [8443]},
    {domains: [www.example.com], ports: [443]}
  ], actions: {tls: {action: Deny}}}]`,
		apex:      "terminate",
		subdomain: "deny",
		priority:  10,
	},
	{
		name:      "wildcard deny without port restriction",
		rules:     `[{name: wildcard, match: [{domains: ["*.example.com"]}], actions: {tls: {action: Deny}}}]`,
		apex:      "terminate",
		subdomain: "deny",
		priority:  10,
	},
	{
		name:      "profile priority precedes TLS action",
		rules:     `[{name: deny, match: [{domains: ["*"]}], actions: {tls: {action: Deny}}}]`,
		apex:      "terminate",
		subdomain: "terminate",
		priority:  30,
	},
	{
		name: "HTTP termination respects original port",
		rules: `[
    {name: http, match: [{domains: ["*"], ports: [8443], schemes: [https]}], actions: {bypass: true}},
    {name: passthrough, match: [{domains: ["*"]}], actions: {tls: {action: Passthrough}}}
  ]`,
		apex:      "passthrough",
		subdomain: "passthrough",
		priority:  10,
	},
}

// Reconcile the same CRD between cases so every assertion also checks hot updates
// across the compiler, xDS, Porter and the gateway's actual TLS inspector.
func TestSecurityProfileTLSActions(t *testing.T) {
	for _, target := range []struct {
		kind      string
		namespace string
		selector  string
		client    echo.Instance
	}{
		{"SecurityProfile", sniFixture.localNamespace.Name(), "selected", sniFixture.selected},
		{"GlobalSecurityProfile", sniFixture.globalNamespace.Name(), "global", sniFixture.global},
	} {
		if !t.Run(target.kind, func(t *testing.T) {
			_, scope := rig.BeginScenario(t)
			applySNITrafficConfig(t, scope)
			assertTLSPassthrough(t, target.client, terminatedHost)
			assertTLSPassthrough(t, target.client, wildcardHost)

			fallback := e2econfig.New(scope).Eval(target.namespace, map[string]any{
				"Kind":     "SecurityProfile",
				"Name":     "tls-http-fallback",
				"Priority": 20,
				"Selector": target.selector,
				"Rules":    "[" + sniHTTPRule + "]",
			}, sniTLSProfileYAML)
			fallback.ApplyOrFail(t, kube.CreateOnly)
			assertTLSTerminated(t, target.client, terminatedHost)

			var active *e2econfig.Plan
			for _, tc := range sniTLSCases {
				if !t.Run(tc.name, func(t *testing.T) {
					active = e2econfig.New(scope).Eval(target.namespace, map[string]any{
						"Kind":     target.kind,
						"Name":     "tls-actions",
						"Priority": tc.priority,
						"Selector": target.selector,
						"Rules":    tc.rules,
					}, sniTLSProfileYAML)
					active.ApplyOrFail(t, kube.ReconcileOwned)
					for _, check := range []struct {
						host   string
						action string
					}{
						{terminatedHost, tc.apex}, {wildcardHost, tc.subdomain},
					} {
						switch check.action {
						case "deny":
							assertTLSDenied(t, target.client, check.host)
						case "passthrough":
							assertTLSPassthrough(t, target.client, check.host)
						case "terminate":
							assertTLSTerminated(t, target.client, check.host)
						}
					}
					assertTLSPassthrough(t, sniFixture.unselected, terminatedHost)
				}) {
					return
				}
			}
			active.DeleteOrFail(t)
			assertTLSTerminated(t, target.client, terminatedHost)
			fallback.DeleteOrFail(t)
			assertTLSPassthrough(t, target.client, terminatedHost)
		}) {
			return
		}
	}
}

func assertTLSDenied(t *testing.T, source echo.Instance, host string) {
	t.Helper()
	harness.RetryAssertion(t, 3*time.Minute, 5*time.Second, func() error {
		for range 3 {
			stdout, stderr, err := curlExternalHTTPS(t, source, host, true)
			if !isTLSConnectionDenied(stdout, err) {
				return fmt.Errorf("expected TLS connection to %s from %s to be denied: %w; stdout=%s; stderr=%s",
					host, source.Name(), err, stdout, stderr)
			}
		}
		return nil
	})
}

func isTLSConnectionDenied(stdout string, err error) bool {
	exit, ok := errors.AsType[utilexec.ExitError](err)
	// curl 35/56 report handshake or receive failure; DNS, deadlines, certificate
	// trust errors and Kubernetes exec failures must not count as policy denial.
	return ok && (exit.ExitStatus() == 35 || exit.ExitStatus() == 56) && strings.TrimSpace(stdout) == "000"
}
