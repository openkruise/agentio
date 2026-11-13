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

package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestRunRejectsPlaintextDiscoveryPort(t *testing.T) {
	err := run(context.Background(), []string{"--discovery-address=:15010"})
	if err == nil {
		t.Fatal("run() accepted plaintext discovery port")
	}
}

func TestRunStopsWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := run(ctx, nil); err != nil {
		t.Fatalf("run() returned error: %v", err)
	}
}

// The README tells an operator to discover configuration with -print-env, so the
// flag has to produce the dump and return without contacting a cluster.
func TestPrintEnvFlagDumpsTheEnvironment(t *testing.T) {
	for _, format := range []string{"text", "markdown"} {
		t.Run(format, func(t *testing.T) {
			output, err := os.CreateTemp(t.TempDir(), "environment")
			if err != nil {
				t.Fatal(err)
			}
			original := os.Stdout
			os.Stdout = output
			t.Cleanup(func() { os.Stdout = original })
			// Export must work even when runtime configuration cannot start a server.
			originalFormat := logFormat
			logFormat = "invalid"
			t.Cleanup(func() { logFormat = originalFormat })
			runErr := run(
				context.Background(),
				[]string{"-print-env", "-print-env-format=" + format, "-kubeconfig=/does/not/exist"},
			)
			os.Stdout = original
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			if runErr != nil {
				t.Fatalf("-print-env must not start the server or configure logging: %v", runErr)
			}
			dumped, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{
				"AGENTIO_PUSH_DEBOUNCE", "AGENTIO_KRT_DEBOUNCE",
				"AGENTIO_SANDBOX_MODE",
				"AGENTIO_ENABLE_POLICY_STATUS",
				"AGENTIO_CA_ROOT_LIFETIME", "AGENTIO_LOG_LEVEL", "AGENTIO_LOG_FORMAT",
			} {
				if !strings.Contains(string(dumped), expected) {
					t.Errorf("-print-env output is missing %s", expected)
				}
			}
			if format == "markdown" && !strings.Contains(string(dumped), "automatic (see description)") {
				t.Fatal("Markdown export froze a machine-specific default")
			}
		})
	}
}

// Each wiring flag must reach Options.
func TestWiringFlagsReachOptions(t *testing.T) {
	options, printEnv, err := parseFlags([]string{
		"-discovery-address", ":16012",
		"-monitoring-address", ":16014",
		"-cluster-id", "remote",
		"-namespace", "agentio-alt",
		"-domain", "alt.local",
		"-trust-domain", "alt.trust",
		"-kubeconfig", "/tmp/kubeconfig",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if printEnv.Enabled {
		t.Error("-print-env was not requested but came back set")
	}
	for _, check := range []struct {
		flag string
		got  string
		want string
	}{
		{"-discovery-address", options.DiscoveryAddress, ":16012"},
		{"-monitoring-address", options.MonitoringAddress, ":16014"},
		{"-cluster-id", options.ClusterID, "remote"},
		{"-namespace", options.RootNamespace, "agentio-alt"},
		{"-domain", options.ClusterDomain, "alt.local"},
		{"-trust-domain", options.TrustDomain, "alt.trust"},
		{"-kubeconfig", options.Kubeconfig, "/tmp/kubeconfig"},
	} {
		if check.got != check.want {
			t.Errorf("%s did not reach Options: got %q, want %q", check.flag, check.got, check.want)
		}
	}
	// Behavioural configuration must not have a command-line flag.
	if err := parseFlagsAccepts("-push-debounce"); err == nil {
		t.Error("a behavioural setting gained a command-line flag; it belongs in env.go only")
	}
}

func parseFlagsAccepts(flag string) error {
	_, _, err := parseFlags([]string{flag, "1s"})
	return err
}

// An unknown flag has to fail loudly rather than being ignored.
func TestUnknownFlagIsRejected(t *testing.T) {
	if _, _, err := parseFlags([]string{"-not-a-flag"}); err == nil {
		t.Fatal("an unknown flag was accepted")
	}
}
