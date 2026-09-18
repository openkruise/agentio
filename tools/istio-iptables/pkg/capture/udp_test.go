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

package capture

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"istio.io/istio/tools/common/config"
	"istio.io/istio/tools/istio-iptables/pkg/builder"
	dep "istio.io/istio/tools/istio-iptables/pkg/dependencies"
)

func TestOutboundUDPTProxy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		ipv6, filtered bool
	}{
		{name: "udp-outbound"},
		{name: "udp-outbound-v6", ipv6: true},
		{name: "udp-outbound-filtered", filtered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := config.DefaultConfig()
			c.EnableUDPTProxy = true
			c.EnableIPv6 = tc.ipv6
			c.InboundInterceptionMode = "REDIRECT"
			c.InboundPortsInclude = "*"
			c.OutboundIPRangesInclude = "*"
			c.ProxyUID, c.ProxyGID = "1337", "1337"
			if tc.filtered {
				c.OutboundIPRangesInclude = "10.0.0.0/8,2001:db8::/32"
				c.OutboundIPRangesExclude = "10.1.0.0/16,2001:db8:1::/48"
				c.OutboundPortsInclude = "19090"
				c.OutboundPortsExclude = "123"
				c.ExcludeInterfaces = "eth1"
				c.OwnerGroupsInclude = "1000,1001"
			}
			ipt, err := NewIptablesConfigurator(c, &dep.DependenciesStub{})
			if err != nil {
				t.Fatal(err)
			}
			if err := ipt.Run(); err != nil {
				t.Fatal(err)
			}
			got := ipt.ruleBuilder.BuildV4Restore()
			if tc.ipv6 {
				got = ipt.ruleBuilder.BuildV6Restore()
			}
			compareToGolden(t, tc.name, []string{got})
			// Enabling UDP must leave the TCP/DNS NAT rules identical.
			c.EnableUDPTProxy = false
			baseline, err := NewIptablesConfigurator(c, &dep.DependenciesStub{})
			if err != nil {
				t.Fatal(err)
			}
			if err := baseline.Run(); err != nil {
				t.Fatal(err)
			}
			before := baseline.ruleBuilder.BuildV4Restore()
			if tc.ipv6 {
				before = baseline.ruleBuilder.BuildV6Restore()
			}
			nat := func(s string) string {
				_, s, _ = strings.Cut(s, "*nat\n")
				s, _, _ = strings.Cut(s, "COMMIT")
				return s
			}
			if nat(got) != nat(before) {
				t.Fatalf("UDP capture changed TCP/DNS NAT rules")
			}
		})
	}
}

func TestUDPOutputCleanup(t *testing.T) {
	// Cleanup must recognize both the renamed chain and previous deployments.
	for _, chain := range []string{"AGENTIO_UDP_OUTPUT", "ISTIO_UDP_OUTPUT"} {
		for _, declaration := range []string{":" + chain + " - [0:0]", "-N " + chain} {
			t.Run(declaration, func(t *testing.T) {
				rules := builder.NewIptablesRuleBuilder(nil)
				state := rules.GetStateFromSave(fmt.Sprintf(`*mangle
%s
:AGENTIO_OTHER - [0:0]
-A OUTPUT -p udp -j %s
-A OUTPUT -p tcp -j AGENTIO_OTHER
COMMIT
`, declaration, chain))
				leftovers := HasIstioLeftovers(state)
				got := builder.BuildCleanupFromState(leftovers)
				want := [][]string{
					{"-t", "mangle", "-D", "OUTPUT", "-p", "udp", "-j", chain},
					{"-t", "mangle", "-F", chain},
					{"-t", "mangle", "-X", chain},
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("cleanup = %v, want %v", got, want)
				}
			})
		}
	}
}
