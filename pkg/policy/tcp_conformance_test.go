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
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
)

func TestTCPRulesConformance(t *testing.T) {
	data, err := os.ReadFile("testdata/tcp_rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string
		Policy  json.RawMessage
		Targets []struct {
			Address  string
			Decision string
		}
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			p := new(securityv1.TCPPolicy)
			if err := protojson.Unmarshal(tc.Policy, p); err != nil {
				t.Fatal(err)
			}
			if err := NormalizeTCPPolicy(p); err != nil {
				t.Fatal(err)
			}
			for _, target := range tc.Targets {
				allow, index := MatchTCPRules(p.Rules, netip.MustParseAddrPort(target.Address))
				got := "no_match"
				if index >= 0 {
					if allow {
						got = "allow"
					} else {
						got = "deny"
					}
				}
				if got != target.Decision {
					t.Errorf("%s: got %s want %s", target.Address, got, target.Decision)
				}
			}
		})
	}
}
