// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package trafficpolicy

import (
	sec "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"net/netip"
	"testing"
)

func TestCompileFQDNOnlyNeverBecomesWildcard(t *testing.T) {
	source := &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{Rules: []*sec.TrafficPolicy_Rule{{Action: sec.TrafficPolicy_ALLOW, Match: &sec.TrafficPolicy_Match{DestinationFqdns: []string{"API.EXAMPLE.COM."}}}}}}
	cfg, err := Compile([]NamedPolicy{{Name: "dns", Policy: source}})
	if err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddrPort("192.0.2.1:443")
	if cfg.Evaluate(target).Action != egressauthz.Deny || cfg.Evaluate(target, "api.example.com").Action != egressauthz.Allow {
		t.Fatal("FQDN-only rule widened or lost")
	}
	source.Egress.Rules[0].Match.DestinationIps = []*sec.TrafficPolicy_Address{address("192.0.2.1/32")}
	cfg, err = Compile([]NamedPolicy{{Name: "dns", Policy: source}})
	if err != nil || cfg.Evaluate(target).Action != egressauthz.Allow {
		t.Fatalf("IP fallback failed: %v", err)
	}
	source.Egress.Rules[0].Match.DestinationFqdns = []string{"*.example.com"}
	if _, err := Compile([]NamedPolicy{{Name: "invalid", Policy: source}}); err == nil {
		t.Fatal("invalid FQDN accepted")
	}
}
