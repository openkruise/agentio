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
package egressauthz

import (
	"net/netip"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
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
	if cfg.Evaluate(original).Action != Deny || cfg.Evaluate(original, "API.EXAMPLE.COM.").Action != Allow ||
		cfg.Evaluate(netip.MustParseAddrPort("192.0.2.9:80"), "api.example.com").Action != Deny {
		t.Fatal("FQDN/port matching failed")
	}
	for _, tc := range []struct {
		method string
		host   string
		want   int
	}{
		{"GET", "api.example.com", 1},
		{"CONNECT", "192.0.2.9", 1},
		{"CONNECT", "api.example.com", 0},
	} {
		stream := &filter.Stream{
			RequestContext: filter.RequestContext{
				Request: httpreq.HTTPRequest{
					Host:                tc.host,
					Method:              tc.method,
					Port:                443,
					OriginalDestination: original,
					DNSCandidates:       []string{"api.example.com"},
				},
			},
			StreamRuntime: filter.StreamRuntime{Info: &filter.StreamInfo{}},
		}
		got, err := cfg.Authorize(t.Context(), stream, []netip.AddrPort{original, rewritten})
		if err != nil || len(got) != tc.want || (len(got) > 0 && got[0] != original) {
			t.Fatalf("%s %s: got=%v err=%v", tc.method, tc.host, got, err)
		}
	}
	cfg.DeniedCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if cfg.Evaluate(original, "api.example.com").Action != Deny {
		t.Fatal("DNS bypassed global deny")
	}
}
