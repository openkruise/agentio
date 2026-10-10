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

package gatewayagent

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRuntimeConfigPrecedence(t *testing.T) {
	t.Setenv("AGENTIO_CPU_LIMIT", "3")
	t.Setenv(
		"AGENTIO_GATEWAY_CONFIG",
		`{"envoyLogLevel":"info","metadata":{"team":"base","enabled":true},"terminationDrainDuration":"40s","minimumDrainDuration":"2s","exitOnZeroActiveConnections":true}`,
	)
	t.Setenv("AGENTIO_META_team", "infra")
	t.Setenv("AGENTIO_METAJSON_labels", `{"region":"east","weight":2}`)
	t.Setenv("AGENTIO_TERMINATION_GRACE_PERIOD_SECONDS", "30")
	c, err := LoadConfig([]string{"--envoy-log-level=debug"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Proxy.Concurrency != 3 || c.LogLevel != "debug" || c.Proxy.TerminationDrainDuration != 25*time.Second ||
		!c.ExitOnZeroActiveConnections {
		t.Fatalf("bad effective runtime: %+v", c)
	}
	c.Namespace, c.PodUID = "ns", "uid"
	bootstrap, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	meta := bootstrap.Node.Metadata.AsMap()
	if meta["POD_UID"] != "uid" || meta["team"] != "infra" || meta["enabled"] != true ||
		meta["labels"].(map[string]any)["weight"] != float64(2) ||
		meta["AGENTIO_VERSION"] == "" {
		t.Fatalf("bad metadata: %v", meta)
	}
	// Explicit zero is different from omission, and overrides even a malformed CPU hint.
	t.Setenv("AGENTIO_CPU_LIMIT", "bad")
	c, err = LoadConfig([]string{"--concurrency=0"}, io.Discard)
	if err != nil || c.Proxy.Concurrency != 0 {
		t.Fatalf("explicit zero: %v, %v", c.Proxy.Concurrency, err)
	}
	t.Setenv("AGENTIO_GATEWAY_CONFIG", `{"concurrency":2}`)
	c, err = LoadConfig(nil, io.Discard)
	if err != nil || c.Proxy.Concurrency != 2 {
		t.Fatalf("JSON concurrency: %v, %v", c.Proxy.Concurrency, err)
	}
}

func TestRejectInvalidRuntimeConfig(t *testing.T) {
	for _, raw := range []string{
		`{"concurency":2}`, `{"concurrency":-1}`, `{"concurrency":65536}`, `{"secretTTL":"0s"}`,
		`{"keepaliveInterval":"1s"}`, `{"keepaliveInterval":"20s"}`, `{"keepaliveTimeout":"0s"}`, `{"minimumDrainDuration":"-1s"}`,
		`{"exitOnZeroActiveConnections":true,"minimumDrainDuration":"26s"}`,
		`{"agentLogLevel":"typo"}`, `{"envoyLogLevel":"typo"}`, `{} {}`,
		`{"metadata":{"POD_UID":"forged"}}`, `{"metadata":{"AGENTIO_VERSION":"forged"}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("AGENTIO_GATEWAY_CONFIG", raw)
			if _, err := LoadConfig(nil, io.Discard); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	for _, env := range []map[string]string{
		{"AGENTIO_META_POD_UID": "forged"}, {"AGENTIO_METAJSON_team": "{"}, {"AGENTIO_CPU_LIMIT": "0"},
		{"AGENTIO_META_team": "plain", "AGENTIO_METAJSON_team": `"json"`},
	} {
		t.Run("environment", func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := LoadConfig(nil, io.Discard); err == nil {
				t.Fatal("accepted invalid environment")
			}
		})
	}
}

func TestDiagnosticsRedactMetadataAndNeedNoIdentity(t *testing.T) {
	t.Setenv("AGENTIO_META_token", "secret-value")
	t.Setenv("AGENTIO_METAJSON_nested", `{"password":"secret-value"}`)
	var output bytes.Buffer
	if err := Command(t.Context(), []string{"print-config"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "secret-value") || !strings.Contains(output.String(), "redacted") {
		t.Fatal(output.String())
	}
	output.Reset()
	// version must work even with broken environment configuration.
	t.Setenv("AGENTIO_GATEWAY_CONFIG", "broken")
	if err := Command(t.Context(), []string{"version"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	var v VersionInfo
	if err := json.Unmarshal(output.Bytes(), &v); err != nil || v.Version == "" {
		t.Fatalf("invalid version: %s", output.String())
	}
}
