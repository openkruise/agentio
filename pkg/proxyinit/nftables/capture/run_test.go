// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
package capture

import (
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/knftables"

	"github.com/openkruise/agentio/pkg/proxyinit/config"
	"github.com/openkruise/agentio/pkg/proxyinit/nftables/builder"
	"github.com/openkruise/agentio/pkg/proxyinit/nftables/constants"
	testutil "github.com/openkruise/agentio/pkg/proxyinit/testutil"
)

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
	cfg := config.DefaultConfig()
	cfg.ProxyUID, cfg.ProxyGID = "1337", "1337"
	return cfg
}

func compareToGolden(t *testing.T, name string, actual string) {
	t.Helper()
	gotBytes := []byte(actual)
	goldenFile := filepath.Join("testdata", name+".golden")
	testutil.CompareContent(t, gotBytes, goldenFile)
}

func TestNftables(t *testing.T) {
	for _, tt := range getCommonTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			cfg := constructTestConfig()
			tt.config(cfg)
			// Create a map to store mock instances for each table.
			mock := builder.NewMockNftables("", "")

			nftProvider := func(_ knftables.Family, table string) (builder.NftablesAPI, error) {
				return mock, nil
			}

			nftConfigurator, err := NewNftablesConfigurator(cfg, nftProvider)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := nftConfigurator.Run()
			if err != nil {
				t.Fatal(err)
			}
			// Collect the output/dump from all tables
			dump := mock.Dump(tx)
			compareToGolden(t, tt.name, dump)
		})
	}
}

func TestRejectNonTCP(t *testing.T) {
	cfg := constructTestConfig()
	cfg.RejectNonTCP = true
	cfg.EnableIPv6 = true
	cfg.NativeNftablesOutputPriority = "-101"
	cfg.OutboundPortsExclude = "53"
	cfg.ExcludeInterfaces = "eth0"
	cfg.OwnerGroupsInclude = "10"
	cfg.ProxyUID = "1337,1338"
	cfg.ProxyGID = "1339"
	mock := builder.NewMockNftables("", "")
	nft, err := NewNftablesConfigurator(cfg, func(_ knftables.Family, _ string) (builder.NftablesAPI, error) {
		return mock, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := nft.Run()
	if err != nil {
		t.Fatal(err)
	}
	rules := tx.String()
	for _, rule := range []string{
		"add chain inet agentio-proxy-nat output { type nat hook output priority -101 ; }",
		"insert rule inet agentio-proxy-nat output index 0 counter jump agentio-output-dns",
		"add rule inet agentio-proxy-nat agentio-output-dns meta skuid 1337 counter return",
		"add rule inet agentio-proxy-nat agentio-output-dns meta skuid 1338 counter return",
		"add rule inet agentio-proxy-nat agentio-output-dns meta skgid 1339 counter return",
		"add rule inet agentio-proxy-nat agentio-output-dns meta l4proto tcp tcp dport 53 counter redirect to :15053",
		"add rule inet agentio-proxy-nat agentio-output-dns udp dport 53 counter redirect to :15053",
		"add rule inet agentio-proxy-raw agentio-inbound udp sport 53 counter ct zone set 1",
		"add chain inet agentio-proxy-filter output { type filter hook output priority 0 ; }",
		"add rule inet agentio-proxy-filter output meta l4proto != tcp counter jump agentio-output",
		"add rule inet agentio-proxy-filter agentio-output icmpv6 type { 1, 2, 3, 4, 130, 131, 132, 133, 134, 135, 136, 143 } counter return",
		"add rule inet agentio-proxy-filter agentio-output ip daddr 127.0.0.1 udp dport 15053 ct status dnat counter return",
		"add rule inet agentio-proxy-filter agentio-output ip6 daddr ::1 udp dport 15053 ct status dnat counter return",
		"add rule inet agentio-proxy-filter agentio-output udp dport 53 meta skuid 1337 counter return",
		"add rule inet agentio-proxy-filter agentio-output udp sport 15053 meta skuid 1338 counter return",
		"add rule inet agentio-proxy-filter agentio-output udp dport 53 meta skgid 1339 counter return",
		"add rule inet agentio-proxy-filter agentio-output counter reject with icmpx type admin-prohibited",
	} {
		if !strings.Contains(rules, rule) {
			t.Errorf("missing rule %q", rule)
		}
	}
	output := mock.Fake.Tables[knftables.InetFamily][constants.AgentioProxyNatTable].Chains[constants.OutputChain]
	if output.Rules[0].Rule != "counter jump agentio-output-dns" {
		t.Fatalf("DNS must be captured before output exclusions: %v", output.Rules)
	}
}
