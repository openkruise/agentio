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

package proxyinit

import (
	"bytes"
	"context"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/openkruise/agentio/pkg/proxyinit/config"
)

func TestNetworkFlags(t *testing.T) {
	for _, tt := range []struct {
		name     string
		priority string
		args     []string
		reject   bool
	}{
		{"defaults", "-100", nil, false},
		{"environment", "-101", nil, true},
		{"CLI overrides environment", "-110", []string{"--native-nftables-output-priority=-101", "--reject-non-tcp=false"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AGENTIO_NATIVE_NFTABLES", "true")
			t.Setenv("AGENTIO_NATIVE_NFTABLES_OUTPUT_PRIORITY", tt.priority)
			t.Setenv("AGENTIO_REJECT_NON_TCP", "false")
			if tt.name != "defaults" {
				t.Setenv("AGENTIO_REJECT_NON_TCP", "true")
			}
			cfg, err := loadConfig(tt.args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			want := tt.priority
			if len(tt.args) > 0 {
				want = "-101"
			}
			if cfg.NativeNftablesOutputPriority != want || cfg.RejectNonTCP != tt.reject {
				t.Fatalf("priority=%s reject=%v", cfg.NativeNftablesOutputPriority, cfg.RejectNonTCP)
			}
		})
	}
}

func TestRejectInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"-m", "TPROXY"},
		{"--native-nftables", "--native-nftables-output-priority=-200"},
		{"--native-nftables-output-priority=-101"},
		{"--envoy-port=18001"},
		{"--agentio-service-cidr=*"},
		{"--drop-invalid=invalid"},
	} {
		if _, err := loadConfig(args, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestUpstreamConfigurationCompatibility(t *testing.T) {
	t.Setenv("ENVOY_PORT", "18001")
	t.Setenv("AGENTIO_OUTBOUND_CAPTURE_PORT", "18002")
	t.Setenv("INVALID_DROP", "true")
	for _, args := range [][]string{
		{"--native-nftables", "--force-iptables-binary=legacy"},
		{"--network-namespace=/var/run/netns/workload"},
	} {
		cfg, err := loadConfig(args, io.Discard)
		if err != nil {
			t.Fatalf("upstream-compatible configuration %v failed: %v", args, err)
		}
		if cfg.ProxyPort != "15001" || !cfg.DropInvalid {
			t.Fatalf("upstream environment binding changed: port=%s dropInvalid=%v", cfg.ProxyPort, cfg.DropInvalid)
		}
	}
	t.Setenv("AGENTIO_REJECT_NON_TCP", "invalid")
	cfg, err := loadConfig(nil, io.Discard)
	if err != nil || cfg.RejectNonTCP {
		t.Fatalf("invalid environment value must follow upstream BindEnv: cfg=%v err=%v", cfg, err)
	}
}

func TestEnvironmentMatchesShortFlags(t *testing.T) {
	args := []string{
		"-z", "16006", "-e", "16008", "-u", "1337", "-g", "1338", "-m", "REDIRECT",
		"-b", "8080,9090", "-d", "8081", "-i", "10.0.0.0/8", "-x", "10.1.0.0/16",
		"-q", "443", "-o", "8082", "-c", "eth1", "-k", "tap0",
		"--redirect-dns", "--capture-all-dns", "--dual-stack", "--dry-run",
	}
	want, err := loadConfig(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"AGENTIO_INBOUND_CAPTURE_PORT":       "16006",
		"AGENTIO_INBOUND_TUNNEL_PORT":        "16008",
		"AGENTIO_PROXY_UID":                  "1337",
		"AGENTIO_PROXY_GID":                  "1338",
		"AGENTIO_INTERCEPTION_MODE":          "REDIRECT",
		"AGENTIO_INCLUDE_INBOUND_PORTS":      "8080,9090",
		"AGENTIO_EXCLUDE_INBOUND_PORTS":      "8081",
		"AGENTIO_INCLUDE_OUTBOUND_IP_RANGES": "10.0.0.0/8",
		"AGENTIO_EXCLUDE_OUTBOUND_IP_RANGES": "10.1.0.0/16",
		"AGENTIO_INCLUDE_OUTBOUND_PORTS":     "443",
		"AGENTIO_EXCLUDE_OUTBOUND_PORTS":     "8082",
		"AGENTIO_EXCLUDE_INTERFACES":         "eth1",
		"AGENTIO_REROUTE_VIRTUAL_INTERFACES": "tap0",
		"AGENTIO_REDIRECT_DNS":               "true",
		"AGENTIO_CAPTURE_ALL_DNS":            "true",
		"AGENTIO_DUAL_STACK":                 "true",
		"AGENTIO_DRY_RUN":                    "true",
	} {
		t.Setenv(name, value)
	}
	got, err := loadConfig(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment and CLI differ:\nenvironment: %s\nCLI: %s", got, want)
	}
	got, err = loadConfig([]string{"--outbound-capture-port=18001", "--include-inbound-ports=8088"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyPort != "18001" || got.InboundPortsInclude != "8088" {
		t.Fatalf("canonical flags did not override configuration: %s", got)
	}
}

func TestDropInvalidPrecedence(t *testing.T) {
	for _, tt := range []struct {
		name  string
		alias string
		args  []string
		want  bool
	}{
		{"alias overrides environment", "false", nil, false},
		{"CLI overrides alias", "false", []string{"--drop-invalid=true"}, true},
		{"invalid alias matches upstream parsing", "invalid", nil, false},
		{"empty alias matches upstream parsing", "", nil, false},
		{"CLI overrides invalid alias", "invalid", []string{"--drop-invalid=true"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AGENTIO_DROP_INVALID", "true")
			t.Setenv("INVALID_DROP", tt.alias)
			cfg, err := loadConfig(tt.args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DropInvalid != tt.want {
				t.Fatalf("drop-invalid=%v, want %v", cfg.DropInvalid, tt.want)
			}
		})
	}
}

func TestEnvironmentOnlyOptions(t *testing.T) {
	t.Setenv("AGENTIO_PROXY_USER", "root")
	t.Setenv("AGENTIO_INCLUDE_OUTBOUND_OWNER_GROUPS", "1,2")
	t.Setenv("AGENTIO_EXCLUDE_OUTBOUND_OWNER_GROUPS", "3")
	t.Setenv("AGENTIO_OUTBOUND_IPV4_LOOPBACK_CIDR", "127.0.0.0/8")
	cfg, err := loadConfig(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyUID != "0" || cfg.ProxyGID != "0" || cfg.OwnerGroupsInclude != "1,2" ||
		cfg.OwnerGroupsExclude != "3" || cfg.HostIPv4LoopbackCidr != "127.0.0.0/8" {
		t.Fatalf("environment-only options were not loaded: %s", cfg)
	}
}

func TestDryRunMatchesUpstreamBackends(t *testing.T) {
	local := config.LocalIPAddrs
	t.Cleanup(func() { config.LocalIPAddrs = local })
	config.LocalIPAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	t.Setenv("PATH", t.TempDir())
	for _, backend := range []string{"--native-nftables=false", "--native-nftables=true"} {
		var logs bytes.Buffer
		err := Command(
			context.Background(),
			[]string{"proxy-init", "--dry-run", backend, "--reject-non-tcp", "-u", "1337", "-i", "*", "-b", "*"},
			io.Discard,
			&logs,
		)
		if backend == "--native-nftables=true" {
			if err == nil || !strings.Contains(err.Error(), "nft binary is missing") {
				t.Fatalf("native nftables must use the real backend even with --dry-run: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if logs.Len() == 0 {
			t.Fatal("dry run did not report rules")
		}
	}
}
