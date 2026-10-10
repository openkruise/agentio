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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestLegacyBootstrap(t *testing.T) {
	c := testConfig(t)
	c.Legacy, c.DNSDomain = true, "demo.svc.cluster.local"
	enabled := true
	c.PolicyStore = &enabled
	b, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if b.Node.Id != "waypoint~10.0.0.1~gateway.demo~demo.svc.cluster.local" {
		t.Fatal(b.Node.Id)
	}
	for key, value := range map[string]string{
		"ISTIO_VERSION":       legacyProxyVersion,
		"METADATA_DISCOVERY":  "true",
		"ENABLE_POLICY_STORE": "true",
		"NAMESPACE":           "demo",
		"SERVICE_ACCOUNT":     "egress",
	} {
		if b.Node.Metadata.Fields[key].GetStringValue() != value {
			t.Fatalf("missing legacy metadata %s", key)
		}
	}
	if len(b.BootstrapExtensions) != 3 {
		t.Fatal("missing legacy extensions")
	}
	if b.BootstrapExtensions[0].Name != "metadata_discovery" ||
		b.BootstrapExtensions[1].Name != "kruise.bootstrap.policy_store" {
		t.Fatal("incorrect legacy extensions")
	}
	c.Metadata = map[string]any{"ISTIO_VERSION": "untrusted"}
	if _, err := bootstrapConfig(c); err == nil {
		t.Fatal("accepted overridden proxy compatibility version")
	}
}

func TestLegacyDefaults(t *testing.T) {
	for _, name := range []string{"AGENTIO_CONFIG_DIR", "AGENTIO_ROOT_CA", "AGENTIO_TOKEN_FILE", "AGENTIO_XDS_ADDRESS"} {
		t.Setenv(name, "")
	}
	t.Setenv("CA_ADDR", "agentiod.demo.svc:15012")
	t.Setenv("POD_NAMESPACE", "demo")
	c, err := LoadConfig([]string{"--legacy"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Legacy || c.RootCertFile != "/var/run/secrets/istio/root-cert.pem" ||
		c.TokenFile != "/var/run/secrets/tokens/istio-token" ||
		c.XDSSocket != "/etc/istio/proxy/XDS" ||
		c.Proxy.DiscoveryAddress != c.CAAddress {
		t.Fatal("legacy deployment defaults not applied")
	}
	t.Setenv("AGENTIO_ROOT_CA", "/custom/root.pem")
	c, err = LoadConfig([]string{"--legacy"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.RootCertFile != "/custom/root.pem" {
		t.Fatal("explicit root path lost")
	}
}

func TestLegacyPodLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels")
	if err := os.WriteFile(path, []byte("app=\"gateway\"\npod-template-hash=\"abc\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	labels, err := readLegacyPodLabels(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(labels) != 1 || labels["app"] != "gateway" {
		t.Fatal(labels)
	}
}

func TestLegacyEnvoyBootstrap(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_LEGACY_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_LEGACY_ENVOY_BINARY to validate the pinned custom Envoy")
	}
	c := testConfig(t)
	c.Legacy, c.DNSDomain = true, "demo.svc.cluster.local"
	enabled := true
	c.PolicyStore = &enabled
	b, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	content, err := protojson.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), binary, "--mode", "validate", "-c", path, "--concurrency", "1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("legacy Envoy bootstrap: %v\n%s", err, output)
	}
}
