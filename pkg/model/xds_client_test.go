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

package model

import (
	"testing"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

func TestValidateXDSClients(t *testing.T) {
	for _, tc := range []struct {
		name    string
		clients []*configv1.XDSClient
		valid   bool
	}{
		{"none", nil, true},
		{"non Kubernetes identity", []*configv1.XDSClient{{Principal: "spiffe://example.com/services/policy-reader", Resources: []string{"Workload", "TrafficPolicy"}}}, true},
		{"wildcard", []*configv1.XDSClient{{Principal: "spiffe://example.com/reader", Resources: []string{"*"}}}, true},
		{"empty denies", []*configv1.XDSClient{{Principal: "spiffe://example.com/reader"}}, true},
		{"nil entry", []*configv1.XDSClient{nil}, false},
		{"wildcard principal", []*configv1.XDSClient{{Principal: "*", Resources: []string{"*"}}}, false},
		{"noncanonical", []*configv1.XDSClient{{Principal: "spiffe://EXAMPLE.COM/reader"}}, false},
		{"unknown resource", []*configv1.XDSClient{{Principal: "spiffe://example.com/reader", Resources: []string{"Worklod"}}}, false},
		{"wildcard does not hide typo", []*configv1.XDSClient{{Principal: "spiffe://example.com/reader", Resources: []string{"*", "Worklod"}}}, false},
		{"duplicate", []*configv1.XDSClient{{Principal: "spiffe://example.com/reader"}, {Principal: "spiffe://example.com/reader"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateXDSClients(tc.clients); (err == nil) != tc.valid {
				t.Fatalf("ValidateXDSClients() = %v, valid = %v", err, tc.valid)
			}
		})
	}
}
