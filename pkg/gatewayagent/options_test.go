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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	if c.Proxy.Concurrency != 3 || c.LogLevel != "debug" || c.Proxy.TerminationDrainDuration != 20*time.Second ||
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
		`{"concurency":2}`, "concurency: 2", "concurrency: [", "concurrency: 1\nconcurrency: 2", `{"concurrency":-1}`, `{"concurrency":65536}`, `{"secretTTL":"0s"}`,
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

func TestWaitCustomStatusPort(t *testing.T) {
	t.Setenv("INSTANCE_IP", "127.0.0.1")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz/ready" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := Command(
		t.Context(),
		[]string{"wait", "--port", port, "--timeout", "3s"},
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2 {
		t.Fatal("did not wait for readiness")
	}
}

func TestDrainDefaultsAndOverrides(t *testing.T) {
	t.Setenv("AGENTIO_GATEWAY_CONFIG", "")
	t.Setenv("AGENTIO_TERMINATION_GRACE_PERIOD_SECONDS", "")
	c, err := LoadConfig(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Proxy.DrainDuration != 45*time.Second || c.Proxy.TerminationDrainDuration != 25*time.Second {
		t.Fatalf("unexpected drain defaults: %+v", c.Proxy)
	}
	t.Setenv("AGENTIO_GATEWAY_CONFIG", "{\"drainDuration\":\"30s\"}")
	c, err = LoadConfig(nil, io.Discard)
	if err != nil || c.Proxy.DrainDuration != 30*time.Second {
		t.Fatalf("JSON override: %v, %v", c.Proxy.DrainDuration, err)
	}
	c, err = LoadConfig([]string{"--drain-duration=10s"}, io.Discard)
	if err != nil || c.Proxy.DrainDuration != 10*time.Second {
		t.Fatalf("CLI override: %v, %v", c.Proxy.DrainDuration, err)
	}
}

func TestEnvironmentReadsAndEmptyFallbacks(t *testing.T) {
	for _, name := range []string{"AGENTIO_GATEWAY_CONFIG", "AGENTIO_ROOT_CA", "AGENTIO_CA_ROOT_CA", "AGENTIO_XDS_ROOT_CA", "CA_ADDR", "AGENTIO_CONFIG_DIR", "ENVOY_BINARY", "CLUSTER_ID", "TRUST_DOMAIN", "AGENTIO_TOKEN_FILE"} {
		t.Setenv(name, "")
	}
	t.Setenv("AGENTIO_XDS_ADDRESS", "first:15012")
	c, err := LoadConfig(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.RootCertFile != "/var/run/secrets/agentio/root-cert.pem" || c.CARootCertFile != c.RootCertFile ||
		c.XDSRootCertFile != c.RootCertFile ||
		c.CAAddress != "first:15012" ||
		c.Proxy.ConfigPath != "/etc/agentio/proxy" ||
		c.Proxy.BinaryPath != "/usr/local/bin/envoy" ||
		c.ClusterID != "Kubernetes" ||
		c.TrustDomain != "cluster.local" ||
		c.TokenFile != "/var/run/secrets/tokens/agentio-token" {
		t.Fatalf("empty environment lost defaults: %+v", c)
	}
	t.Setenv("AGENTIO_XDS_ADDRESS", "second:15012")
	t.Setenv("AGENTIO_ROOT_CA", "/custom/root.pem")
	t.Setenv("AGENTIO_CA_ROOT_CA", "/custom/ca.pem")
	c, err = LoadConfig(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.CAAddress != "second:15012" || c.RootCertFile != "/custom/root.pem" || c.CARootCertFile != "/custom/ca.pem" ||
		c.XDSRootCertFile != "/custom/root.pem" {
		t.Fatalf("environment cached or fallback changed: %+v", c)
	}
}

func TestNodeIDUsesProxyDNSDomain(t *testing.T) {
	t.Setenv("POD_NAME", "egress-pod")
	t.Setenv("POD_NAMESPACE", "demo")
	t.Setenv("POD_UID", "pod-uid")
	t.Setenv("INSTANCE_IP", "10.0.0.1")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "agentio-egress~10.0.0.1~egress-pod.demo~demo.svc.cluster.local"},
		{"custom domain", []string{"--domain=demo.svc.example.internal"}, "agentio-egress~10.0.0.1~egress-pod.demo~demo.svc.example.internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := LoadConfig(tc.args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			bootstrap, err := bootstrapConfig(c)
			if err != nil {
				t.Fatal(err)
			}
			if bootstrap.Node.Id != tc.want {
				t.Fatalf("node ID = %q, want %q", bootstrap.Node.Id, tc.want)
			}
			if bootstrap.Node.Metadata.GetFields()["POD_UID"].GetStringValue() != "pod-uid" {
				t.Fatal("Pod UID must remain in metadata")
			}
		})
	}
}

func TestRuntimeConfigFormatsAndLogDefaults(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       string
		level     string
		component string
	}{
		{"unset", "", "warning", "misc:error"},
		{"empty object", "{}", "warning", "misc:error"},
		{"JSON", `{"envoyLogLevel":"info","envoyComponentLogLevel":"misc:debug"}`, "info", "misc:debug"},
		{"YAML", "envoyLogLevel: info\nenvoyComponentLogLevel: misc:debug", "info", "misc:debug"},
		{"clear component", `{"envoyComponentLogLevel":""}`, "warning", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGENTIO_GATEWAY_CONFIG", tc.raw)
			c, err := LoadConfig(nil, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if c.LogLevel != tc.level || c.ComponentLogLevel != tc.component {
				t.Fatalf("log levels = %q, %q; want %q, %q", c.LogLevel, c.ComponentLogLevel, tc.level, tc.component)
			}
		})
	}
}

func TestTerminationBudgetReservesGatewayAndPorterCleanup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		grace string
		drain string
		want  time.Duration
	}{
		{"default pod", "30", "40s", 20 * time.Second},
		{"longer pod", "60", "50s", 50 * time.Second},
		{"explicit shorter drain", "30", "2s", 2 * time.Second},
		{"cleanup only", "10", "40s", 0},
		{"short pod", "5", "40s", 0},
		{"outside Kubernetes", "", "40s", 40 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGENTIO_TERMINATION_GRACE_PERIOD_SECONDS", tc.grace)
			c, err := LoadConfig(
				[]string{"--termination-drain-duration=" + tc.drain, "--minimum-drain-duration=0s"},
				io.Discard,
			)
			if err != nil {
				t.Fatal(err)
			}
			if c.Proxy.TerminationDrainDuration != tc.want {
				t.Fatalf("drain = %v, want %v", c.Proxy.TerminationDrainDuration, tc.want)
			}
		})
	}
}
