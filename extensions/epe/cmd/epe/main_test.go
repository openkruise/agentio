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

package main

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAuditWebhookVerifiesTLSByDefault(t *testing.T) {
	configured := flag.Lookup("audit-webhook-insecure-skip-verify")
	if configured == nil {
		t.Fatal("audit webhook TLS verification flag is not registered")
	}
	if configured.DefValue != "false" {
		t.Fatalf("audit webhook insecure-skip-verify default = %q, want false", configured.DefValue)
	}
}

func TestPrintEnvironmentExitsBeforeStartup(t *testing.T) {
	if os.Getenv("EPE_ENV_DOC_TEST_HELPER") == "true" {
		// Run in a subprocess because EPE owns the process-global flag set.
		os.Args = []string{"epe", "-print-env", "-print-env-format=" + os.Getenv("EPE_ENV_DOC_TEST_FORMAT")}
		flag.CommandLine = flag.NewFlagSet("epe", flag.ContinueOnError)
		if err := run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, format := range []string{"text", "markdown"} {
		command := exec.Command(os.Args[0], "-test.run=^TestPrintEnvironmentExitsBeforeStartup$")
		command.Env = append(os.Environ(), "EPE_ENV_DOC_TEST_HELPER=true", "EPE_ENV_DOC_TEST_FORMAT="+format,
			"CREDENTIAL_PROVIDER_MTLS_SOURCE=invalid", "KUBECONFIG=/does/not/exist")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s export attempted startup: %v\n%s", format, err, output)
		}
		for _, expected := range []string{"IDENTITY_PROVIDER_URL", "TOKEN_CACHE_TTL", "TOKEN_CACHE_MAX_SIZE",
			"STS_CACHE_MAX_SIZE", "CREDENTIAL_PROVIDER_MTLS_SOURCE", "AUDIT_WEBHOOK_DIAL_TIMEOUT"} {
			if !strings.Contains(string(output), expected) {
				t.Errorf("%s export missing %s", format, expected)
			}
		}
		if format == "markdown" && strings.Contains(string(output), "AGENTIO_CA_SECRET_NAME") {
			t.Fatal("EPE table includes unrelated control-plane settings")
		}
	}
}

// The bounded wait is an independent knob, not a derivative of the collection
// debounce: the debounce bounds coalescing of events the informer already
// holds and never watch latency, so no arithmetic over it can bound
// convergence. What the wait must respect is the enclosing request budget,
// whose expiry would surface as a gRPC error instead of the intended 503.
func TestSandboxPolicyWaitFlagDefaultsBelowPluginBudget(t *testing.T) {
	configured := flag.Lookup("sandbox-policy-wait")
	if configured == nil {
		t.Fatal("sandbox policy wait flag is not registered")
	}
	if configured.DefValue != "200ms" {
		t.Fatalf("sandbox policy wait default = %q, want 200ms", configured.DefValue)
	}
	if err := validateSandboxPolicyWait(200*time.Millisecond, 4500*time.Millisecond); err != nil {
		t.Fatalf("default wait must pass validation: %v", err)
	}
}

func TestValidateSandboxPolicyWait(t *testing.T) {
	tests := []struct {
		name    string
		wait    time.Duration
		budget  time.Duration
		wantErr bool
	}{
		{name: "default wait under the default budget", wait: 200 * time.Millisecond, budget: 4500 * time.Millisecond},
		{name: "zero disables the wait", wait: 0, budget: 4500 * time.Millisecond},
		{name: "negative wait", wait: -time.Millisecond, budget: 4500 * time.Millisecond, wantErr: true},
		{name: "wait equal to the budget", wait: 4500 * time.Millisecond, budget: 4500 * time.Millisecond, wantErr: true},
		{name: "wait above the budget", wait: 5 * time.Second, budget: 4500 * time.Millisecond, wantErr: true},
		{name: "disabled budget accepts any wait", wait: 10 * time.Second, budget: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSandboxPolicyWait(tc.wait, tc.budget)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("validateSandboxPolicyWait(%v, %v) error = %v, wantErr %v", tc.wait, tc.budget, err, tc.wantErr)
			}
		})
	}
}
