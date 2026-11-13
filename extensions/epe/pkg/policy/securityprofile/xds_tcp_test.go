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

package securityprofile

import (
	"net/netip"
	"testing"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/policy"
)

func TestFromXDSTCPPolicy(t *testing.T) {
	value := &securityv1.SecurityProfile{
		Name:       "policy",
		Namespace:  "ns",
		Uid:        "uid",
		PolicyJson: []byte(`{"rules":[]}`),
		TcpPolicy: &securityv1.TCPPolicy{Rules: []*securityv1.TCPRule{{
			Name:   "private",
			Action: securityv1.TCPAction_TCP_ACTION_DENY,
			Match:  []*securityv1.TCPMatch{{Cidrs: []string{"10.1.2.3/8"}, Ports: []uint32{443}}},
		}}},
	}
	profile, err := FromXDS(value, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, _ := policy.MatchTCPRules(profile.TCPPolicy.Rules, netip.MustParseAddrPort("10.2.3.4:443")); allowed {
		t.Fatal("typed TCP deny was lost")
	}
	if value.TcpPolicy.Rules[0].Match[0].Cidrs[0] != "10.1.2.3/8" {
		t.Fatal("wire policy was mutated")
	}
	value.TcpPolicy.Rules[0].Match[0].Cidrs[0] = "invalid"
	if _, err := FromXDS(value, "", nil); err == nil {
		t.Fatal("invalid wire TCP policy accepted")
	}
}
