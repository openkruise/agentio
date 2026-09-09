// Copyright 2026 The Kruise Authors
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

package egressauthz

import (
	"net/netip"
	"testing"
)

func TestPolicyCIDRAndPortMatching(t *testing.T) {
	cfg := Config{Policies: []Policy{{Name: "test", Rules: []Rule{
		{Action: Deny, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, Ports: []PortRange{{Start: 443}}},
		{Action: Deny, CIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")}},
		{Action: Allow, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.9/24")}, Ports: []PortRange{{Start: 443}, {Start: 8000, End: 8002}}},
		{Action: Allow, CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, Ports: []PortRange{{Start: 80}}},
		{Action: Allow, CIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}},
	}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		address string
		allow   bool
	}{
		{"192.0.2.2:443", true},
		{"192.0.2.1:443", false},
		{"192.0.2.1:8000", true},
		{"192.0.2.1:8002", true},
		{"192.0.2.1:8003", false},
		{"192.0.2.2:80", false},
		{"198.51.100.1:443", false},
		{"198.51.100.1:80", true},
		{"203.0.113.1:443", false},
		{"[2001:db8:2::1]:65535", true},
		{"[2001:db8:1::1]:443", false},
		{"[::ffff:192.0.2.1]:443", false},
		{"[::ffff:192.0.2.2]:443", true},
	} {
		if got := cfg.Evaluate(netip.MustParseAddrPort(tc.address)).Action == Allow; got != tc.allow {
			t.Errorf("%s allowed=%v, want %v", tc.address, got, tc.allow)
		}
	}
	if (Config{}).Evaluate(netip.MustParseAddrPort("192.0.2.2:443")).Action == Allow {
		t.Fatal("uninitialized policy must deny")
	}
}

func TestConfigValidationDoesNotModifySnapshot(t *testing.T) {
	cfg := Config{Policies: []Policy{{Name: "test", Rules: []Rule{{
		Action: Allow,
		CIDRs:  []netip.Prefix{netip.MustParsePrefix("192.0.2.9/24")},
		Ports:  []PortRange{{Start: 443}},
	}}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	rule := cfg.Policies[0].Rules[0]
	if rule.CIDRs[0].String() != "192.0.2.9/24" || rule.Ports[0].End != 0 {
		t.Fatal("validation mutated caller-owned policy")
	}
	want := Decision{Action: Allow, PolicyName: "test", RuleIndex: 0}
	if got := cfg.Evaluate(netip.MustParseAddrPort("192.0.2.1:443")); got != want {
		t.Fatalf("decision=%+v, want %+v", got, want)
	}
	for _, invalid := range []Config{
		{Policies: []Policy{{Name: ""}}},
		{Policies: []Policy{{Name: "test"}, {Name: "test"}}},
		{Policies: []Policy{{Name: "test", Rules: []Rule{{Action: "invalid"}}}}},
		{Policies: []Policy{{Name: "test", Rules: []Rule{{Action: Allow}}}}},
		{Policies: []Policy{{Name: "test", Rules: []Rule{{Action: Allow, CIDRs: []netip.Prefix{{}}}}}}},
		{Policies: []Policy{{Name: "test", Rules: []Rule{{
			Action: Allow, CIDRs: []netip.Prefix{netip.MustParsePrefix("::ffff:192.0.2.0/120")},
		}}}}},
		{Policies: []Policy{{Name: "test", Rules: []Rule{{
			Action: Allow, CIDRs: rule.CIDRs, Ports: []PortRange{{Start: 0}},
		}}}}},
		{Policies: []Policy{{Name: "test", Rules: []Rule{{
			Action: Allow, CIDRs: rule.CIDRs, Ports: []PortRange{{Start: 443, End: 80}},
		}}}}},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", invalid)
		}
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("empty snapshot must be valid: %v", err)
	}
}
