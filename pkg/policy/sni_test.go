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
	"strings"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestCompileSNIRulesPreservesTLSOrderAndMatchPorts(t *testing.T) {
	rules := []agentsv1alpha1.SecurityRule{
		{
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"SKIP.Example.COM."}, Ports: []int32{443, 8443}}},
			Actions: agentsv1alpha1.SecurityRuleActions{
				TLS: &agentsv1alpha1.TLSAction{Action: agentsv1alpha1.TLSActionPassthrough},
			},
		},
		{
			Match: []agentsv1alpha1.RuleMatch{
				{
					Domains: []string{"*.example.com"},
					Ports:   []int32{443},
					Schemes: []string{"https"},
					Methods: []string{"GET"},
				},
				{Domains: []string{"skip.example.com"}, Ports: []int32{9443}},
				{Domains: []string{"http.example.com"}, Schemes: []string{"http"}},
			},
		},
		{
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}},
			Actions: agentsv1alpha1.SecurityRuleActions{
				TLS: &agentsv1alpha1.TLSAction{Action: agentsv1alpha1.TLSActionDeny},
			},
		},
	}
	got, err := CompileSNIRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	want := &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{
		{
			Match:  &extensionsv1.SniMatch{Sni: []string{"skip.example.com"}, Ports: []uint32{443, 8443}},
			Action: extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH,
		},
		{
			Match:  &extensionsv1.SniMatch{Sni: []string{"*.example.com"}, Ports: []uint32{443}},
			Action: extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION,
		},
		{
			Match:  &extensionsv1.SniMatch{Sni: []string{"skip.example.com"}, Ports: []uint32{9443}},
			Action: extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION,
		},
		{Match: &extensionsv1.SniMatch{Sni: []string{"*"}}, Action: extensionsv1.SniAction_SNI_ACTION_DENY},
	}}
	if !proto.Equal(got, want) {
		t.Fatalf("SNI policy = %v, want %v", got, want)
	}
}

func TestCompileSNIRulesRejectsInvalidTLSRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*agentsv1alpha1.SecurityRule)
		want   string
	}{
		{"missing action", func(r *agentsv1alpha1.SecurityRule) { r.Actions.TLS.Action = "" }, "invalid TLS action"},
		{"unknown action", func(r *agentsv1alpha1.SecurityRule) { r.Actions.TLS.Action = "Terminate" }, "invalid TLS action"},
		{"block", func(r *agentsv1alpha1.SecurityRule) { r.Actions.Block = &agentsv1alpha1.BlockAction{} }, "HTTP actions"},
		{"bypass", func(r *agentsv1alpha1.SecurityRule) { r.Actions.Bypass = true }, "HTTP actions"},
		{"mcp", func(r *agentsv1alpha1.SecurityRule) { r.Actions.MCPToolPolicy = &agentsv1alpha1.MCPToolPolicySpec{} }, "HTTP actions"},
		{"headers action", func(r *agentsv1alpha1.SecurityRule) {
			r.Actions.HeaderManipulation = &agentsv1alpha1.HeaderManipulationAction{}
		}, "HTTP actions"},
		{"callout", func(r *agentsv1alpha1.SecurityRule) { r.Actions.HTTPCallout = &agentsv1alpha1.HTTPCalloutAction{} }, "HTTP actions"},
		{"token", func(r *agentsv1alpha1.SecurityRule) {
			r.Actions.TokenTransformation = &agentsv1alpha1.TokenTransformationAction{}
		}, "HTTP actions"},
		{"audit", func(r *agentsv1alpha1.SecurityRule) { r.Actions.Audit = []agentsv1alpha1.AuditAction{{}} }, "rule audit"},
		{"paths", func(r *agentsv1alpha1.SecurityRule) { r.Match[0].Paths = []agentsv1alpha1.PathMatch{{Value: "/"}} }, "only supports domains and ports"},
		{"methods", func(r *agentsv1alpha1.SecurityRule) { r.Match[0].Methods = []string{"GET"} }, "only supports domains and ports"},
		{"schemes", func(r *agentsv1alpha1.SecurityRule) { r.Match[0].Schemes = []string{"https"} }, "only supports domains and ports"},
		{"headers", func(r *agentsv1alpha1.SecurityRule) {
			r.Match[0].Headers = []agentsv1alpha1.HeaderMatch{{Name: "x-test"}}
		}, "only supports domains and ports"},
		{"query", func(r *agentsv1alpha1.SecurityRule) {
			r.Match[0].QueryParams = []agentsv1alpha1.QueryParamMatch{{Name: "test"}}
		}, "only supports domains and ports"},
		{"no match", func(r *agentsv1alpha1.SecurityRule) { r.Match = nil }, "requires a match"},
		{"no domains", func(r *agentsv1alpha1.SecurityRule) { r.Match[0].Domains = nil }, "requires domains"},
		{"invalid domain", func(r *agentsv1alpha1.SecurityRule) { r.Match[0].Domains = []string{"*bad.example"} }, "wildcard"},
		{"zero port", func(r *agentsv1alpha1.SecurityRule) { r.Match[0].Ports = []int32{0} }, "invalid destination port"},
		{"large port", func(r *agentsv1alpha1.SecurityRule) { r.Match[0].Ports = []int32{65536} }, "invalid destination port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := agentsv1alpha1.SecurityRule{
				Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"example.com"}}},
				Actions: agentsv1alpha1.SecurityRuleActions{
					TLS: &agentsv1alpha1.TLSAction{Action: agentsv1alpha1.TLSActionDeny},
				},
			}
			tc.change(&rule)
			if _, err := CompileSNIRules(
				[]agentsv1alpha1.SecurityRule{rule},
			); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("compile error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCompileSecurityProfileNormalizesHTTPSDomains(t *testing.T) {
	priority := int32(10)
	compiled, err := CompileSecurityProfile(model.SecurityProfile{
		Name:      "profile",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Priority: &priority,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Name: "hosts",
				Match: []agentsv1alpha1.RuleMatch{
					{
						Domains: []string{"API.Example.COM.", "*.Example.com", "api.example.com"},
						Schemes: []string{"HTTPS"},
					},
					{Domains: []string{"http-only.example.com"}, Schemes: []string{"http"}},
				},
			}},
		},
	})
	if err != nil {
		t.Fatalf("compile SNI profiles: %v", err)
	}
	if compiled == nil || compiled.ResourceName() != "namespaced/demo/profile" {
		t.Fatalf("compiled profiles = %+v", compiled)
	}
	got := compiled.SNIPolicy.GetRules()[0]
	want := []string{"api.example.com", "*.example.com"}
	if got.GetAction() != extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION ||
		len(got.GetMatch().GetSni()) != len(want) {
		t.Fatalf("SNI rule = %+v", got)
	}
	for i := range want {
		if got.GetMatch().GetSni()[i] != want[i] {
			t.Fatalf("SNI hosts = %v, want %v", got.GetMatch().GetSni(), want)
		}
	}
}

func TestCompileSecurityProfileRejectsPartialWildcard(t *testing.T) {
	_, err := CompileSecurityProfile(model.SecurityProfile{
		Name:      "bad",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
			Name:  "bad",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*foo.example.com"}}},
		}}},
	})
	if err == nil {
		t.Fatal("partial wildcard was accepted")
	}
}

func securitySpec(priority *int32, selector map[string]string) agentsv1alpha1.SecurityProfileSpec {
	return agentsv1alpha1.SecurityProfileSpec{
		Priority: priority,
		Selector: metav1.LabelSelector{MatchLabels: selector},
		Rules: []agentsv1alpha1.SecurityRule{
			{Name: "rule", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}}},
		},
	}
}

func TestCompileSNIRulesMergesAdjacentActionsWithoutChangingPrecedence(t *testing.T) {
	rule := func(domain string, ports []int32, action agentsv1alpha1.TLSActionType) agentsv1alpha1.SecurityRule {
		return agentsv1alpha1.SecurityRule{
			Match:   []agentsv1alpha1.RuleMatch{{Domains: []string{domain}, Ports: ports}},
			Actions: agentsv1alpha1.SecurityRuleActions{TLS: &agentsv1alpha1.TLSAction{Action: action}},
		}
	}
	got, err := CompileSNIRules([]agentsv1alpha1.SecurityRule{
		rule("A.Example.com.", []int32{8443, 443, 443}, agentsv1alpha1.TLSActionPassthrough),
		rule("a.example.com", []int32{443, 8443}, agentsv1alpha1.TLSActionPassthrough),
		rule("c.example.com", []int32{443, 8443}, agentsv1alpha1.TLSActionPassthrough),
		rule("*.example.com", nil, agentsv1alpha1.TLSActionDeny),
		rule("b.example.com", []int32{443, 8443}, agentsv1alpha1.TLSActionPassthrough),
		rule("d.example.com", []int32{9443}, agentsv1alpha1.TLSActionPassthrough),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{
		{
			Match:  &extensionsv1.SniMatch{Sni: []string{"a.example.com", "c.example.com"}, Ports: []uint32{443, 8443}},
			Action: extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH,
		},
		{Match: &extensionsv1.SniMatch{Sni: []string{"*.example.com"}}, Action: extensionsv1.SniAction_SNI_ACTION_DENY},
		{
			Match:  &extensionsv1.SniMatch{Sni: []string{"b.example.com"}, Ports: []uint32{443, 8443}},
			Action: extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH,
		},
		{
			Match:  &extensionsv1.SniMatch{Sni: []string{"d.example.com"}, Ports: []uint32{9443}},
			Action: extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH,
		},
	}}
	if !proto.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
