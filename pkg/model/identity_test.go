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

import "testing"

func TestZTunnelClientClassNames(t *testing.T) {
	if got, want := ClientSharedZTunnel, ClientClass("shared-ztunnel"); got != want {
		t.Fatalf("shared ztunnel client class = %q, want %q", got, want)
	}
	if got, want := ClientDedicatedZTunnel, ClientClass("dedicated-ztunnel"); got != want {
		t.Fatalf("dedicated ztunnel client class = %q, want %q", got, want)
	}
}

func TestPrincipalSPIFFERoundTrip(t *testing.T) {
	for _, raw := range []string{
		"spiffe://cluster.local/workload/payments",
		"spiffe://cluster.local/workload/internet",
		"spiffe://cluster.local/workload/vm-inventory-v2/account/region/native-id",
		"spiffe://cluster.local/future-profile/subject",
		"spiffe://cluster.local/ns/demo/sa/app",
		"spiffe://cluster.local",
	} {
		principal, err := ParsePrincipal(raw, "cluster.local")
		if err != nil || principal.String() != raw || principal.TrustDomain() != "cluster.local" {
			t.Fatalf("round trip %q: %v %v", raw, principal, err)
		}
		if err := principal.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrincipalConfiguredTrustDomainEncoding(t *testing.T) {
	principal, err := NewPrincipal("mesh@example.com", "workload/native-v1/id")
	if err != nil || principal.String() != "spiffe://mesh.example.com/workload/native-v1/id" {
		t.Fatalf("principal: %v %v", principal, err)
	}
	parsed, err := ParsePrincipal(principal.String(), "mesh@example.com")
	if err != nil || parsed != principal {
		t.Fatalf("round trip: %v %v", parsed, err)
	}
}

func TestParsePrincipalRejectsInvalidIdentities(t *testing.T) {
	for _, raw := range []string{
		"", "https://cluster.local/workload/id", "spiffe://other/workload/id",
		"spiffe://CLUSTER.local/workload/id", "spiffe://cluster.local:443/workload/id",
		"spiffe://user@cluster.local/workload/id", "spiffe://cluster.local//id",
		"spiffe://cluster.local/workload/id/", "spiffe://cluster.local/workload/../id",
		"spiffe://cluster.local/workload/%69d", "spiffe://cluster.local/workload/id?",
		"spiffe://cluster.local/workload/id#fragment",
	} {
		if _, err := ParsePrincipal(raw, "cluster.local"); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if (Principal{}).Validate() == nil {
		t.Fatal("zero principal validated")
	}
}

func TestClientScopeValidateRequiresClassOwnership(t *testing.T) {
	principal := MustPrincipal("cluster.local", "workload/app")
	tests := []struct {
		name  string
		scope ClientScope
		valid bool
	}{
		{"node", ClientScope{Class: ClientSharedZTunnel, NodeName: "node-a"}, true},
		{"node missing ownership", ClientScope{Class: ClientSharedZTunnel, Principal: principal}, false},
		{
			"sandbox",
			ClientScope{
				Class:       ClientDedicatedZTunnel,
				Principal:   principal,
				WorkloadUID: "uid-a",
				Source:      SourceRef{Registry: "test", Key: "uid-a"},
			},
			true,
		},
		{"sandbox missing ownership", ClientScope{Class: ClientDedicatedZTunnel, Principal: principal}, false},
		{
			"gateway",
			ClientScope{
				Class:       ClientEgressGateway,
				Principal:   principal,
				GatewayKey:  "demo/agent",
				WorkloadUID: "gw",
				Source:      SourceRef{Registry: "test", Key: "pod"},
			},
			true,
		},
		{"gateway missing ownership", ClientScope{Class: ClientEgressGateway, Principal: principal}, false},
		{
			"gateway without Pod binding",
			ClientScope{Class: ClientEgressGateway, Principal: principal, GatewayKey: "other/agent"},
			false,
		},
		{
			"gateway without workload binding",
			ClientScope{Class: ClientEgressGateway, Principal: principal, GatewayKey: "demo/other"},
			false,
		},
		{
			"sandbox invalid principal",
			ClientScope{
				Class:       ClientDedicatedZTunnel,
				WorkloadUID: "vm-a",
				Source:      SourceRef{Registry: "test", Key: "vm-a"},
			},
			false,
		},
		{"unknown", ClientScope{Class: "spoofed", Principal: principal, NodeName: "node-a"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.scope.Validate()
			if tc.valid && err != nil {
				t.Fatalf("valid scope rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("invalid scope accepted")
			}
		})
	}
}
