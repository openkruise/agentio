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

// Package httpreq holds the neutral request tuple shared by the filter
// framework and the policy model. It is a leaf: importing it pulls in no
// policy API, no protos, nothing but the standard library — which is what
// lets the engine's dependency closure stay free of agents-api.
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
