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

package policy

import (
	"net/netip"
	"testing"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
)

func TestTCPRulesOrderedDestinationMatching(t *testing.T) {
	rules := []agents.TCPRule{
		{
			Name:   "exception",
			Action: agents.TCPActionAllow,
			Match:  []agents.TCPMatch{{CIDRs: []string{"10.1.0.1/16"}, Ports: []int32{443}}},
		},
		{
			Name:   "private",
			Action: agents.TCPActionDeny,
			Match:  []agents.TCPMatch{{CIDRs: []string{"10.0.0.0/8", "fc00::/7"}}},
		},
	}
	compiled, err := CompileTCPRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target string
		allow  bool
		index  int
	}{
		{"10.1.0.2:443", true, 0}, {"10.1.0.2:80", false, 1}, {"[fd00::1]:443", false, 1}, {"192.0.2.1:443", true, -1}, {"[::ffff:10.1.0.2]:443", true, 0},
	} {
		allow, index := MatchTCPRules(compiled.Rules, netip.MustParseAddrPort(tc.target))
		if allow != tc.allow || index != tc.index {
			t.Errorf("%s: %v/%d", tc.target, allow, index)
		}
	}
	for _, rule := range []agents.TCPRule{
		{Name: "bad", Action: agents.TCPActionDeny},
		{Name: "bad", Action: "allow", Match: []agents.TCPMatch{{}}},
		{Name: "bad", Action: "deny", Match: []agents.TCPMatch{{}}},
		{Name: "bad", Action: agents.TCPActionDeny, Match: []agents.TCPMatch{{CIDRs: []string{"140.205.162.999"}}}},
		{Name: "bad", Action: agents.TCPActionDeny, Match: []agents.TCPMatch{{CIDRs: []string{"140.205.162.5/33"}}}},
		{Name: "bad", Action: agents.TCPActionDeny, Match: []agents.TCPMatch{{CIDRs: []string{"fe80::1%eth0"}}}},
		{Name: "bad", Action: "invalid", Match: []agents.TCPMatch{{}}},
		{Name: "bad", Action: agents.TCPActionDeny, Match: []agents.TCPMatch{{CIDRs: []string{"::ffff:10.0.0.0/120"}}}},
		{Name: "bad", Action: agents.TCPActionDeny, Match: []agents.TCPMatch{{Ports: []int32{65536}}}},
	} {
		if _, err := CompileTCPRules([]agents.TCPRule{rule}); err == nil {
			t.Fatalf("invalid rule accepted: %+v", rule)
		}
	}
	empty, err := CompileTCPRules(nil)
	if err != nil || empty == nil {
		t.Fatalf("empty policy: %v %v", empty, err)
	}
	if allow, _ := MatchTCPRules(empty.Rules, netip.MustParseAddrPort("192.0.2.1:443")); !allow {
		t.Fatal("empty policy must allow")
	}
}

func TestTCPRulesSingleAddress(t *testing.T) {
	for _, tc := range []struct {
		address string
		prefix  string
		target  string
		other   string
	}{
		{"140.205.162.5", "140.205.162.5/32", "140.205.162.5:443", "140.205.162.6:443"},
		{"2001:db8::1", "2001:db8::1/128", "[2001:db8::1]:443", "[2001:db8::2]:443"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			compiled, err := CompileTCPRules([]agents.TCPRule{{
				Name:   "deny-host",
				Action: agents.TCPActionDeny,
				Match:  []agents.TCPMatch{{CIDRs: []string{tc.address}}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if got := compiled.Rules[0].Match[0].Cidrs[0]; got != tc.prefix {
				t.Fatalf("normalized address = %s, want %s", got, tc.prefix)
			}
			if allow, index := MatchTCPRules(compiled.Rules, netip.MustParseAddrPort(tc.target)); allow || index != 0 {
				t.Fatalf("configured address was not denied: allow=%v, index=%d", allow, index)
			}
			if allow, index := MatchTCPRules(compiled.Rules, netip.MustParseAddrPort(tc.other)); !allow || index != -1 {
				t.Fatalf("adjacent address was denied: allow=%v, index=%d", allow, index)
			}
		})
	}
}
