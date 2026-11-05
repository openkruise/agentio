// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package egressauthz

import (
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"net/netip"
	"testing"
)

func TestDNSCandidatesMatchOriginalIPOnly(t *testing.T) {
	original := netip.MustParseAddrPort("192.0.2.9:443")
	rewritten := netip.MustParseAddrPort("192.0.2.10:443")
	cfg := Config{Policies: []Policy{{
		Name: "dns",
		Rules: []Rule{
			{Action: Allow, FQDNs: []string{"api.example.com"}, Ports: []PortRange{{Start: 443}}},
			{Action: Deny, CIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Evaluate(original).Action != Deny || cfg.Evaluate(original, "API.EXAMPLE.COM.").Action != Allow || cfg.Evaluate(netip.MustParseAddrPort("192.0.2.9:80"), "api.example.com").Action != Deny {
		t.Fatal("FQDN/port matching failed")
	}
	for _, method := range []string{"GET", "CONNECT"} {
		stream := &filter.Stream{RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: "192.0.2.9", Method: method, Port: 443, OriginalDestination: original, DNSCandidates: []string{"api.example.com"}}}, StreamRuntime: filter.StreamRuntime{Info: &filter.StreamInfo{}}}
		got, err := cfg.Authorize(t.Context(), stream, []netip.AddrPort{original, rewritten})
		if err != nil || len(got) != 1 || got[0] != original {
			t.Fatalf("%s: got=%v err=%v", method, got, err)
		}
	}
	cfg.DeniedCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if cfg.Evaluate(original, "api.example.com").Action != Deny {
		t.Fatal("DNS bypassed global deny")
	}
}
