// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package capture

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/proxyinit/config"
	"github.com/openkruise/agentio/pkg/proxyinit/iptables/constants"
	dep "github.com/openkruise/agentio/pkg/proxyinit/iptables/dependencies"
	testutil "github.com/openkruise/agentio/pkg/proxyinit/testutil"
)

type guardrailCleanupFailure struct {
	dep.DependenciesStub
	restoreError    error
	cleanupFailures int
}

func (ext *guardrailCleanupFailure) Run(
	logger *agentlog.Logger, quiet bool, command constants.IptablesCmd,
	version *dep.IptablesVersion, input io.ReadSeeker, args ...string,
) (*bytes.Buffer, error) {
	if command == constants.IPTablesSave {
		return bytes.NewBufferString("*nat\n:AGENTIO_OUTPUT - [0:0]\nCOMMIT\n"), nil
	}
	if command == constants.IPTablesRestore {
		return &bytes.Buffer{}, ext.restoreError
	}
	if command == constants.IPTables && !quiet && slices.Contains(args, "-D") {
		ext.cleanupFailures++
		return &bytes.Buffer{}, errors.New("guardrail cleanup failed")
	}
	return ext.DependenciesStub.Run(logger, quiet, command, version, input, args...)
}

//nolint:errorlint // Verify the original install error is returned unchanged.
func TestGuardrailCleanupPreservesInstallResult(t *testing.T) {
	for _, restoreError := range []error{nil, errors.New("restore failed")} {
		t.Run(fmt.Sprint(restoreError), func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Reconcile = true
			cfg.OutboundIPRangesInclude, cfg.InboundPortsInclude = "*", "*"
			cfg.ProxyUID, cfg.ProxyGID = "1337", "1337"
			ext := &guardrailCleanupFailure{restoreError: restoreError}
			capture, err := NewIptablesConfigurator(cfg, ext)
			if err != nil {
				t.Fatal(err)
			}
			if err := capture.Run(); err != restoreError {
				t.Fatalf("install result = %v, want %v", err, restoreError)
			}
			if ext.cleanupFailures == 0 {
				t.Fatal("guardrail cleanup was not exercised")
			}
		})
	}
}

func getCommonTestCases() []struct {
	name   string
	config func(cfg *config.Config)
} {
	return []struct {
		name   string
		config func(cfg *config.Config)
	}{
		{
			"ipv6-empty-inbound-ports",
			func(cfg *config.Config) {
				cfg.InboundPortsInclude = ""
				cfg.EnableIPv6 = true
			},
		},
		{
			"ip-range",
			func(cfg *config.Config) {
				cfg.OutboundIPRangesExclude = "1.1.0.0/16"
				cfg.OutboundIPRangesInclude = "9.9.0.0/16"
				cfg.DryRun = true
				cfg.RedirectDNS = true
				cfg.EnableIPv6 = false
				cfg.ProxyGID = "1,2"
				cfg.ProxyUID = "3,4"
				cfg.DNSServersV4 = []string{"127.0.0.53"}
			},
		},
		{
			"ipv6-inbound-ports",
			func(cfg *config.Config) {
				cfg.InboundPortsInclude = "4000,5000"
				cfg.EnableIPv6 = true
			},
		},
		{
			"ipv6-virt-interfaces",
			func(cfg *config.Config) {
				cfg.InboundPortsInclude = "4000,5000"
				cfg.RerouteVirtualInterfaces = "eth0,eth1"
				cfg.EnableIPv6 = true
			},
		},
		{
			"ipv6-ipnets",
			func(cfg *config.Config) {
				cfg.InboundPortsInclude = "4000,5000"
				cfg.InboundPortsExclude = "6000,7000,"
				cfg.RerouteVirtualInterfaces = "eth0,eth1"
				cfg.OutboundIPRangesExclude = "2001:db8::/32"
				cfg.OutboundIPRangesInclude = "2001:db8::/32"
				cfg.EnableIPv6 = true
			},
		},
		{
			"ipv6-uid-gid",
			func(cfg *config.Config) {
				cfg.InboundPortsInclude = "4000,5000"
				cfg.InboundPortsExclude = "6000,7000"
				cfg.RerouteVirtualInterfaces = "eth0,eth1"
				cfg.ProxyGID = "1,2"
				cfg.ProxyUID = "3,4"
				cfg.EnableIPv6 = true
				cfg.OutboundIPRangesExclude = "2001:db8::/32"
				cfg.OutboundIPRangesInclude = "2001:db8::/32"
			},
		},
		{
			"ipv6-outbound-ports",
			func(cfg *config.Config) {
				cfg.InboundPortsInclude = ""
				cfg.OutboundPortsInclude = "32000,31000"
				cfg.EnableIPv6 = true
			},
		},
		{
			"empty",
			func(cfg *config.Config) {},
		},
		{
			"kube-virt-interfaces",
			func(cfg *config.Config) {
				cfg.RerouteVirtualInterfaces = "eth1,eth2"
				cfg.OutboundIPRangesInclude = "*"
			},
		},
		{
			"ipnets",
			func(cfg *config.Config) {
				cfg.OutboundIPRangesInclude = "10.0.0.0/8"
			},
		},
		{
			"ipnets-with-kube-virt-interfaces",
			func(cfg *config.Config) {
				cfg.RerouteVirtualInterfaces = "eth1,eth2"
				cfg.OutboundIPRangesInclude = "10.0.0.0/8"
			},
		},
		{
			"inbound-ports-include",
			func(cfg *config.Config) {
				cfg.InboundPortsInclude = "32000,31000"
			},
		},
		{
			"inbound-ports-wildcard",
			func(cfg *config.Config) {
				cfg.InboundPortsInclude = "*"
			},
		},
		{
			"dns-uid-gid",
			func(cfg *config.Config) {
				cfg.RedirectDNS = true
				cfg.DNSServersV4 = []string{"127.0.0.53"}
				cfg.DNSServersV6 = []string{"::127.0.0.53"}
				cfg.ProxyGID = "1,2"
				cfg.ProxyUID = "3,4"
				cfg.EnableIPv6 = true
			},
		},
		{
			"ipv6-dns-uid-gid",
			func(cfg *config.Config) {
				cfg.EnableIPv6 = true
				cfg.RedirectDNS = true
				cfg.ProxyGID = "1,2"
				cfg.ProxyUID = "3,4"
			},
		},
		{
			"outbound-owner-groups",
			func(cfg *config.Config) {
				cfg.OwnerGroupsInclude = "java,202"
			},
		},
		{
			"outbound-owner-groups-exclude",
			func(cfg *config.Config) {
				cfg.OwnerGroupsExclude = "888,ftp"
			},
		},
		{
			"ipv6-dns-outbound-owner-groups",
			func(cfg *config.Config) {
				cfg.EnableIPv6 = true
				cfg.RedirectDNS = true
				cfg.OwnerGroupsInclude = "java,202"
			},
		},
		{
			"ipv6-dns-outbound-owner-groups-exclude",
			func(cfg *config.Config) {
				cfg.EnableIPv6 = true
				cfg.RedirectDNS = true
				cfg.OwnerGroupsExclude = "888,ftp"
			},
		},
		{
			"outbound-ports-include",
			func(cfg *config.Config) {
				cfg.OutboundPortsInclude = "32000,31000"
			},
		},
		{
			"loopback-outbound-iprange",
			func(cfg *config.Config) {
				cfg.OutboundIPRangesInclude = "127.1.2.3/32"
				cfg.DryRun = true
				cfg.RedirectDNS = true
				cfg.DNSServersV4 = []string{"127.0.0.53"}
				cfg.EnableIPv6 = false
				cfg.ProxyGID = "1,2"
				cfg.ProxyUID = "3,4"
			},
		},
		{
			"basic-exclude-nic",
			func(cfg *config.Config) {
				cfg.ExcludeInterfaces = "not-agentio-nic"
			},
		},
		{
			"drop-invalid",
			func(cfg *config.Config) {
				cfg.DropInvalid = true
			},
		},
		{
			"host-ipv4-loopback-cidr",
			func(cfg *config.Config) {
				cfg.HostIPv4LoopbackCidr = "127.0.0.1/8"
			},
		},
	}
}

func constructTestConfig() *config.Config {
	return &config.Config{
		ProxyPort:            "15001",
		InboundCapturePort:   "15006",
		InboundTunnelPort:    "15008",
		ProxyUID:             constants.DefaultProxyUID,
		ProxyGID:             constants.DefaultProxyUID,
		OwnerGroupsInclude:   constants.OwnerGroupsInclude,
		HostIPv4LoopbackCidr: constants.HostIPv4LoopbackCidr,
	}
}

func compareToGolden(t *testing.T, name string, actual []string) {
	t.Helper()
	gotBytes := []byte(strings.Join(actual, "\n"))
	goldenFile := filepath.Join("testdata", name+".golden")
	testutil.CompareContent(t, gotBytes, goldenFile)
}

func TestIptables(t *testing.T) {
	for _, tt := range getCommonTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			cfg := constructTestConfig()
			tt.config(cfg)

			ext := &dep.DependenciesStub{}
			iptConfigurator, err := NewIptablesConfigurator(cfg, ext)
			if err != nil {
				t.Fatal(err)
			}
			err = iptConfigurator.Run()
			if err != nil {
				t.Fatal(err)
			}
			compareToGolden(t, tt.name, ext.ExecutedAll)
		})
	}
}

func TestRejectNonTCP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		cfg := constructTestConfig()
		cfg.EnableIPv6 = ipv6
		cfg.RejectNonTCP = true
		cfg.OutboundPortsExclude = "53"
		cfg.ExcludeInterfaces = "eth0"
		cfg.OwnerGroupsInclude = "10"
		cfg.ProxyUID = "1337,1338"
		cfg.ProxyGID = "1339"
		ipt, err := NewIptablesConfigurator(cfg, &dep.DependenciesStub{})
		if err != nil {
			t.Fatal(err)
		}
		if err := ipt.Run(); err != nil {
			t.Fatal(err)
		}
		restore := ipt.ruleBuilder.BuildV4Restore()
		if ipv6 {
			restore = ipt.ruleBuilder.BuildV6Restore()
			for _, icmpType := range []string{"1", "2", "3", "4", "130", "131", "132", "133", "134", "135", "136", "143"} {
				if !strings.Contains(restore, "-p ipv6-icmp --icmpv6-type "+icmpType+" -j RETURN") {
					t.Errorf("missing essential ICMPv6 type %s", icmpType)
				}
			}
		}
		for _, rule := range []string{
			"-I OUTPUT 1 -j AGENTIO_OUTPUT_DNS",
			"-A AGENTIO_OUTPUT_DNS -m owner --uid-owner 1337 -j RETURN",
			"-A AGENTIO_OUTPUT_DNS -m owner --uid-owner 1338 -j RETURN",
			"-A AGENTIO_OUTPUT_DNS -m owner --gid-owner 1339 -j RETURN",
			"-A AGENTIO_OUTPUT_DNS -p tcp --dport 53 -j REDIRECT --to-ports 15053",
			"-A AGENTIO_OUTPUT_DNS -p udp --dport 53 -j REDIRECT --to-port 15053",
			"-A AGENTIO_INBOUND -p udp --sport 53 -j CT --zone 1",
			"-I OUTPUT 1 ! -p tcp -j AGENTIO_OUTPUT",
			"-A AGENTIO_OUTPUT -d " + map[bool]string{false: "127.0.0.1/32", true: "::1/128"}[ipv6] + " -p udp --dport 15053 -m conntrack --ctstate DNAT -j RETURN",
			"-A AGENTIO_OUTPUT -p udp --dport 53 -m owner --uid-owner 1337 -j RETURN",
			"-A AGENTIO_OUTPUT -p udp --sport 15053 -m owner --uid-owner 1338 -j RETURN",
			"-A AGENTIO_OUTPUT -p udp --dport 53 -m owner --gid-owner 1339 -j RETURN",
			"-A AGENTIO_OUTPUT -j REJECT\nCOMMIT",
		} {
			if !strings.Contains(restore, rule) {
				t.Errorf("IPv6=%v: missing rule %q", ipv6, rule)
			}
		}
	}
}
