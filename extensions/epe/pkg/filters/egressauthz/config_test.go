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

package egressauthz

import (
	"net/netip"
	"testing"
)

func TestPlatformConfigValidationAndMatching(t *testing.T) {
	cfg := Config{
		DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.9/24"), netip.MustParsePrefix("2001:db8::/32")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.DeniedCIDRs[0].String() != "192.0.2.9/24" {
		t.Fatal("validation mutated snapshot")
	}
	for _, tc := range []struct {
		target string
		action Action
		index  int
	}{
		{"192.0.2.1:443", Deny, 0}, {"[::ffff:192.0.2.1]:80", Deny, 0},
		{"[2001:db8::1]:443", Deny, 1}, {"198.51.100.1:443", Allow, -1},
	} {
		got := cfg.Evaluate(netip.MustParseAddrPort(tc.target))
		if got.Action != tc.action || got.RuleIndex != tc.index {
			t.Fatalf("%s: %+v", tc.target, got)
		}
	}
	for _, prefix := range []netip.Prefix{{}, netip.MustParsePrefix("::ffff:192.0.2.0/120")} {
		if (Config{DeniedCIDRs: []netip.Prefix{prefix}}).Validate() == nil {
			t.Fatalf("accepted %s", prefix)
		}
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatal(err)
	}
	if (Config{}).Evaluate(netip.MustParseAddrPort("192.0.2.1:443")).Action != Allow {
		t.Fatal("empty restrictions must allow")
	}
	for _, target := range []netip.AddrPort{{}, netip.MustParseAddrPort("192.0.2.1:0"), netip.MustParseAddrPort("[fe80::1%eth0]:80")} {
		if cfg.Evaluate(target).Action != Deny {
			t.Fatalf("accepted invalid target %s", target)
		}
	}
}
