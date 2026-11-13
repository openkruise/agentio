// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package epe

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func sandboxHTTPRules(marker string, status int) string {
	return fmt.Sprintf(`[
  {"name":"block","match":[{"domains":["*"],"paths":[{"type":"Exact","value":"/sandbox-block"}]}],
   "actions":{"block":{"statusCode":%d,"body":%q}}},
  {"name":"mutate","match":[{"domains":["*"],"paths":[{"type":"Exact","value":"/sandbox-mutate"}]}],
   "actions":{"headerManipulation":{"set":[{"name":"x-sandbox-policy","value":%q}]}}}
]`, status, marker, marker)
}

func TestSandboxInlineHTTPPolicies(t *testing.T) {
	f := newSandboxPolicyFixture(t)
	caller := f.caller(t, "sandbox-http", true)
	f.rules(t, caller, sandboxHTTPRules("sandbox-http-enforced", 451))
	for _, id := range []string{caller.id, ""} {
		if !t.Run(fmt.Sprintf("id=%q", id), func(t *testing.T) {
			f.check(t, caller, id, "/sandbox-block", false, 451, "sandbox-http-enforced")
			f.check(t, caller, id, "/sandbox-mutate", false, http.StatusOK, "RequestHeader=X-Sandbox-Policy:sandbox-http-enforced")
			f.check(t, caller, id, "/sandbox-control", false, http.StatusOK, "Hostname=")
			// The HTTP block also proves EPE receives identity after TLS termination.
			reply := f.check(t, caller, id, "/sandbox-block", true, 451, "sandbox-http-enforced")
			if _, err := reply.peer.Verify(x509.VerifyOptions{Roots: f.roots, DNSName: trafficFixture.Server.Address()}); err != nil {
				t.Fatalf("terminated TLS certificate: %v", err)
			}
		}) {
			return
		}
	}
}

func TestSandboxInlineTLSPolicies(t *testing.T) {
	f := newSandboxPolicyFixture(t)
	caller := f.caller(t, "sandbox-tls", true)
	baseline := f.check(t, caller, caller.id, "/sandbox-control", true, http.StatusOK, "Hostname=")
	for _, action := range []string{"Deny", "Passthrough"} {
		f.rules(t, caller, fmt.Sprintf(`[{"name":"tls","match":[{"domains":[%q],"ports":[443]}],"actions":{"tls":{"action":%q}}}]`, trafficFixture.Server.Address(), action))
		for _, id := range []string{caller.id, ""} {
			if !t.Run(fmt.Sprintf("%s/id=%q", action, id), func(t *testing.T) {
				if action == "Deny" {
					harness.RetryAssertion(t, 90*time.Second, time.Second, func() error {
						for range 3 {
							ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
							response, err := f.request(ctx, caller, id, "/sandbox-control", "443", true)
							budgetError := ctx.Err()
							cancel()
							if budgetError != nil {
								return budgetError
							}
							if response.connect != http.StatusOK || !sandboxTLSRejected(err) {
								return fmt.Errorf("expected TLS policy rejection after CONNECT, got CONNECT=%d, HTTP=%d, error=%v", response.connect, response.status, err)
							}
						}
						return nil
					})
				} else {
					response := f.check(t, caller, id, "/sandbox-control", true, http.StatusOK, "Hostname=")
					if !bytes.Equal(response.peer.Raw, baseline.peer.Raw) {
						t.Fatal("TLS passthrough replaced the origin certificate")
					}
				}
				// The same TLS host on 9443 must not match the 443-only rule.
				harness.RetryAssertion(t, time.Minute, time.Second, func() error {
					ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
					defer cancel()
					response, err := f.request(ctx, caller, id, "/sandbox-control", "9443", true)
					if err != nil {
						return err
					}
					if response.connect != http.StatusOK || response.status != http.StatusOK || !bytes.Equal(response.peer.Raw, baseline.peer.Raw) {
						return fmt.Errorf("unmatched TLS port: CONNECT=%d HTTP=%d, want origin passthrough", response.connect, response.status)
					}
					return nil
				})
				f.check(t, caller, id, "/sandbox-control", false, http.StatusOK, "Hostname=")
			}) {
				return
			}
		}
	}
	f.rules(t, caller, sandboxHTTPRules("sandbox-tls-terminated", 451))
	for _, id := range []string{caller.id, ""} {
		reply := f.check(t, caller, id, "/sandbox-block", true, 451, "sandbox-tls-terminated")
		if bytes.Equal(reply.peer.Raw, baseline.peer.Raw) {
			t.Fatal("HTTP policy did not terminate TLS")
		}
		if _, err := reply.peer.Verify(x509.VerifyOptions{Roots: f.roots, DNSName: trafficFixture.Server.Address()}); err != nil {
			t.Fatalf("TLS termination certificate: %v", err)
		}
	}
}

func TestSandboxInlinePolicyLifecycle(t *testing.T) {
	f := newSandboxPolicyFixture(t)
	caller := f.caller(t, "sandbox-lifecycle", true)
	check := func(marker string, status int) {
		t.Helper()
		for _, id := range []string{caller.id, ""} {
			f.check(t, caller, id, "/sandbox-block", false, status, marker)
		}
	}
	check("Hostname=", http.StatusOK)
	f.rules(t, caller, sandboxHTTPRules("sandbox-v1", 451))
	check("sandbox-v1", 451)
	f.rules(t, caller, sandboxHTTPRules("sandbox-v2", 452))
	check("sandbox-v2", 452)
	// Wait for the compiler's failure before checking last-known-good enforcement.
	f.rules(t, caller, `[{`)
	f.compileFailure(t, caller)
	check("sandbox-v2", 452)
	f.rules(t, caller, sandboxHTTPRules("sandbox-restored", 451))
	check("sandbox-restored", 451)
	f.rules(t, caller, "")
	check("Hostname=", http.StatusOK)
	f.rules(t, caller, sandboxHTTPRules("sandbox-readded", 453))
	check("sandbox-readded", 453)
}

func TestSandboxIdentitySelection(t *testing.T) {
	f := newSandboxPolicyFixture(t)
	a := f.caller(t, "sandbox-a", true)
	b := f.caller(t, "sandbox-b", true)
	ordinary := f.caller(t, "sandbox-ordinary", false)
	f.rules(t, a, sandboxHTTPRules("sandbox-a-policy", 451))
	f.rules(t, b, sandboxHTTPRules("sandbox-b-policy", 452))
	for range 3 {
		// Alternate callers and selection modes through the same gateway.
		f.check(t, a, a.id, "/sandbox-block", false, 451, "sandbox-a-policy")
		f.check(t, b, "", "/sandbox-block", false, 452, "sandbox-b-policy")
		f.check(t, a, "", "/sandbox-block", false, 451, "sandbox-a-policy")
		f.check(t, b, b.id, "/sandbox-block", false, 452, "sandbox-b-policy")
	}
	denied := func(caller sandboxCaller, id string) {
		t.Helper()
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			reply, err := f.request(ctx, caller, id, "/sandbox-block", "80", false)
			if err != nil {
				return err
			}
			if reply.connect != http.StatusForbidden {
				return fmt.Errorf("CONNECT=%d, want identity rejection 403", reply.connect)
			}
			return nil
		})
	}
	// A valid name fallback must not rescue an explicit missing or wrong identity.
	denied(a, "kruise:missing")
	denied(a, b.id)
	denied(b, a.id)
	f.check(t, ordinary, "", "/sandbox-block", false, http.StatusOK, "Hostname=")
	for _, binding := range []string{string(b.pod.UID), ""} {
		f.bind(t, a, binding)
		for _, id := range []string{a.id, ""} {
			denied(a, id)
		}
	}
	f.bind(t, a, string(a.pod.UID))
	for _, id := range []string{a.id, ""} {
		f.check(t, a, id, "/sandbox-block", false, 451, "sandbox-a-policy")
	}
}

func applySandboxPolicyConfig(t *testing.T, scope *kube.ResourceScope) {
	t.Helper()
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": resolvedAgentioConfig.Namespace, "Host": trafficFixture.Server.Address()}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: agentio-epe.{{ .Namespace }}.svc.cluster.local
      port: 9002
      messageTimeout: 5s
      request:
        headerMode: SEND
        attributes:
        - filter_state['agentio.sandbox.id']
        - filter_state['agentio.workload.uid']
        - filter_state['agentio.workload.name']
        - filter_state['agentio.workload.namespace']
        - destination.port
        - source.address
      response:
        headerMode: SKIP
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts: [{{ .Host | printf "%q" }}]
`)
}
