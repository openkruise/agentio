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

package e2e

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveConfigPrecedence(t *testing.T) {
	t.Setenv("E2E_CLUSTER_NAME", "from-env")
	path := writeConfig(t, "cluster:\n  name: from-file\n")
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	in := RegisterFlags(fs)
	if err := fs.Parse([]string{"-e2e.config=" + path, "-e2e.cluster.name=from-cli"}); err != nil {
		t.Fatal(err)
	}

	cfg, err := ResolveConfig(in, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cluster.Name != "from-cli" {
		t.Fatalf("name = %q, want from-cli", cfg.Cluster.Name)
	}
}

func TestResolveConfigAppliesFileOverSuiteDefaults(t *testing.T) {
	suite := DefaultConfig()
	suite.Cluster.Name = "from-suite"
	path := writeConfig(t, "cluster:\n  name: from-file\n")
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	in := RegisterFlags(fs)
	if err := fs.Parse([]string{"-e2e.config=" + path}); err != nil {
		t.Fatal(err)
	}

	cfg, err := ResolveConfig(in, suite)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cluster.Name != "from-file" {
		t.Fatalf("name = %q, want from-file", cfg.Cluster.Name)
	}
}

func TestResolveConfigRejectsUnknownYAMLField(t *testing.T) {
	path := writeConfig(t, "cluster:\n  typo: value\n")
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	in := RegisterFlags(fs)
	if err := fs.Parse([]string{"-e2e.config=" + path}); err != nil {
		t.Fatal(err)
	}

	_, err := ResolveConfig(in, DefaultConfig())
	if err == nil || !strings.Contains(err.Error(), "field typo not found") {
		t.Fatalf("ResolveConfig() error = %v, want unknown-field error", err)
	}
}

func TestResolveConfigEnvironmentNames(t *testing.T) {
	t.Setenv("E2E_CLUSTER_MODE", "existing")
	t.Setenv("E2E_CLUSTER_CONTEXT", "dev")
	t.Setenv("E2E_CLUSTER_KIND_NODE_IMAGE", "kindest/node@sha256:abc")
	t.Setenv("E2E_LIFECYCLE_RETAIN", "always")
	t.Setenv("E2E_DIAGNOSTICS_MAX_FULL_DUMPS", "7")
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	in := RegisterFlags(fs)

	cfg, err := ResolveConfig(in, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cluster.Mode != ClusterModeExisting || cfg.Cluster.Context != "dev" {
		t.Fatalf("cluster = %+v", cfg.Cluster)
	}
	if cfg.Cluster.Kind.NodeImage != "kindest/node@sha256:abc" {
		t.Fatalf("node image = %q", cfg.Cluster.Kind.NodeImage)
	}
	if cfg.Lifecycle.Retain != RetainAlways || cfg.Diagnostics.MaxFullDumps != 7 {
		t.Fatalf("lifecycle/diagnostics = %+v %+v", cfg.Lifecycle, cfg.Diagnostics)
	}
}

func TestResolveConfigKubeconfigFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", path)
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	in := RegisterFlags(fs)

	cfg, err := ResolveConfig(in, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cluster.Kubeconfig != path {
		t.Fatalf("kubeconfig = %q, want %q", cfg.Cluster.Kubeconfig, path)
	}
}

func TestResolveConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown mode", args: []string{"-e2e.cluster.mode=remote"}, want: "cluster mode"},
		{name: "unknown retention", args: []string{"-e2e.lifecycle.retain=sometimes"}, want: "retain policy"},
		{name: "reuse existing", args: []string{"-e2e.cluster.mode=existing", "-e2e.cluster.reuse=true"}, want: "reuse"},
		{name: "reuse unnamed kind", args: []string{"-e2e.cluster.reuse=true"}, want: "cluster name"},
		{name: "negative dumps", args: []string{"-e2e.diagnostics.max-full-dumps=-1"}, want: "max full dumps"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
			in := RegisterFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			_, err := ResolveConfig(in, DefaultConfig())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestResolveConfigGeneratesUniqueKindName(t *testing.T) {
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	in := RegisterFlags(fs)
	first, err := ResolveConfig(in, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveConfig(in, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if first.Cluster.Name == "" || first.Cluster.Name == second.Cluster.Name {
		t.Fatalf("generated names = %q and %q", first.Cluster.Name, second.Cluster.Name)
	}
}

func TestConfigRedactedHidesKubeconfigPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cluster.Kubeconfig = "/secret/user/kubeconfig"
	redacted := cfg.Redacted()
	if strings.Contains(redacted.Cluster.Kubeconfig, "secret") {
		t.Fatalf("redacted kubeconfig = %q", redacted.Cluster.Kubeconfig)
	}
	if cfg.Cluster.Kubeconfig != "/secret/user/kubeconfig" {
		t.Fatal("Redacted mutated the source config")
	}
}

func TestRegisterFlagsDoesNotParseOrMutateGlobalFlags(t *testing.T) {
	fs := flag.NewFlagSet("isolated", flag.ContinueOnError)
	_ = RegisterFlags(fs)
	if fs.Parsed() {
		t.Fatal("RegisterFlags parsed the flag set")
	}
	if flag.CommandLine.Lookup("e2e.cluster.mode") != nil {
		t.Fatal("RegisterFlags mutated flag.CommandLine")
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "e2e.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
