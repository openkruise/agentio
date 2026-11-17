// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package kruise

import (
	"net/netip"
	"reflect"
	"testing"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/policy"
)

func TestE2BDestinationPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		target  string
		allowed bool
	}{
		{"default allow", `{}`, "10.0.0.1:443", true},
		{"false denies private too", `{"allow_internet_access":false}`, "10.0.0.1:443", false},
		{"false denies IPv6", `{"allow_internet_access":false}`, "[2001:db8::1]:443", false},
		{"allow before deny", `{"allow_internet_access":false,"network":{"allowOut":["10.0.0.0/8"],"denyOut":["10.0.0.1"]}}`, "10.0.0.1:443", true},
		{"IPv6 host", `{"allow_internet_access":false,"network":{"allowOut":["2001:db8::1"]}}`, "[2001:db8::1]:443", true},
		{"true retains deny", `{"allow_internet_access":true,"network":{"denyOut":["10.0.0.0/8"]}}`, "10.0.0.1:443", false},
		{"default DNS all ports", `{"allow_internet_access":false,"network":{"allowOut":["*.example.com"]}}`, "8.8.8.8:443", true},
		{"empty DNS disables exception", `{"allow_internet_access":false,"network":{"allowOut":["example.com"],"dnsServers":[]}}`, "8.8.8.8:53", false},
		{"custom DNS", `{"allow_internet_access":false,"network":{"allowOut":["example.com"],"dnsServers":["1.1.1.1"]}}`, "1.1.1.1:53", true},
		{"no domain no DNS exception", `{"allow_internet_access":false,"network":{"allowOut":["10.0.0.1"]}}`, "8.8.8.8:53", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := e2bProfile(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			tcp, err := policy.CompileTCPRules(spec.TCPRules)
			if err != nil {
				t.Fatal(err)
			}
			allowed, _ := policy.MatchTCPRules(tcp.Rules, netip.MustParseAddrPort(tc.target))
			if allowed != tc.allowed {
				t.Fatalf("allowed=%v, want %v", allowed, tc.allowed)
			}
		})
	}
}

func TestSandboxAnnotationComposition(t *testing.T) {
	sandbox := &agents.Sandbox{ObjectMeta: metav1.ObjectMeta{
		Name:      "sandbox",
		Namespace: "tenant",
		Annotations: map[string]string{
			AnnotationSecurityProfile: `{"inputs":[{"name":"data","inline":{"key":"value"}}],"rules":[{"name":"native-tls","match":[{"domains":["native.example"]}],"actions":{"tls":{"action":"Deny"}}},{"name":"native-http","match":[{"domains":["native.example"]}],"actions":{"bypass":true}}],"tcpRules":[{"name":"e2b-deny-rest","match":[{}],"action":"Deny"}]}`,
			AnnotationE2BNetwork:      `{"allow_internet_access":false,"network":{"allowOut":["api.example.com"]}}`,
			"unrelated":               "discard",
		},
	}}
	p, err := SandboxPolicies(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if p.E2BRuleOffset == nil || *p.E2BRuleOffset != 1 || len(p.Profile().Inputs) != 1 {
		t.Fatalf("native inputs/HTTP offset lost: %+v", p)
	}
	spec := p.Profile()
	if spec.Rules[0].Name != "native-tls" || spec.Rules[1].Name != "native-http" || spec.Rules[2].Name != "e2b-allow-http" || spec.TCPRules[0].Name != "e2b-deny-rest" {
		t.Fatalf("native rules must precede generated rules: %+v", spec)
	}
	if _, err := policy.CompileTCPRules(spec.TCPRules); err != nil {
		t.Fatal("generated names collide with native rules:", err)
	}
	stripped, err := stripSandbox(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if got := stripped.(*agents.Sandbox).Annotations; len(got) != 2 || !HasSecurityRules(stripped.(*agents.Sandbox)) {
		t.Fatalf("annotations not retained: %v", got)
	}
	delete(sandbox.Annotations, AnnotationE2BNetwork)
	native, err := SandboxPolicies(sandbox)
	if err != nil || !reflect.DeepEqual(native.Profile().Inputs, spec.Inputs) || len(native.Profile().Rules) != 2 {
		t.Fatalf("network removal changed native snapshot: %+v %v", native, err)
	}
	sandbox.Annotations = map[string]string{agents.AnnotationSecurityRules: `[{"name":"legacy","match":[{"domains":["*"]}]}]`, AnnotationE2BNetwork: `{}`}
	legacy, err := SandboxPolicies(sandbox)
	if err != nil || legacy.Profile().Rules[0].Name != "legacy" {
		t.Fatalf("legacy + E2B: %+v %v", legacy, err)
	}
}

func TestSandboxAnnotationErrors(t *testing.T) {
	for _, annotations := range []map[string]string{
		{AnnotationSecurityProfile: `{}`, agents.AnnotationSecurityRules: `[]`},
		{AnnotationSecurityProfile: `null`},
		{AnnotationSecurityProfile: `{} {}`},
		{AnnotationSecurityProfile: `{"priority":1}`},
		{AnnotationSecurityProfile: `{"selector":{}}`},
		{AnnotationSecurityProfile: `{"rules":[{"actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"credential"}}}}}]}`},
		{AnnotationSecurityProfile: `{"inputs":[{"name":"foreign","configMap":{"name":"data","namespace":"other"}}]}`},
		{AnnotationE2BNetwork: `null`},
		{AnnotationE2BNetwork: `{"network":{"egressProxy":{"address":"proxy.example:1080"}}}`},
		{AnnotationE2BNetwork: `{"allow_internet_access":"false"}`},
		{AnnotationE2BNetwork: `{"network":{"allowOut":["https://example.com"]}}`},
		{AnnotationE2BNetwork: `{"network":{"denyOut":["example.com"]}}`},
		{AnnotationE2BNetwork: `{"network":{"allowOut":["example.com"],"dnsServers":["::1"]}}`},
		{AnnotationE2BNetwork: `{"network":{"rules":{"*": [{"transform":{"headers":{"X-A":"value"}}}]}}}`},
		{AnnotationE2BNetwork: `{"network":{"rules":{"example.com": []}}}`},
	} {
		sandbox := &agents.Sandbox{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Annotations: annotations}}
		if _, err := SandboxPolicies(sandbox); err == nil {
			t.Errorf("accepted invalid annotation: %v", annotations)
		}
	}
}
