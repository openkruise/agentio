// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package securityprofile

import (
	"encoding/json"
	"testing"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry/kubernetes/kruise"
)

func TestE2BMostSpecificTransformAndNativeOrder(t *testing.T) {
	regs, err := filter.Build(headermutation.Definition(), bypass.Definition())
	if err != nil {
		t.Fatal(err)
	}
	obj := &agents.Sandbox{ObjectMeta: metav1.ObjectMeta{
		Name:      "sandbox",
		Namespace: "tenant",
		Annotations: map[string]string{
			kruise.AnnotationSecurityProfile: `{"rules":[{"name":"tls-native","match":[{"domains":["irrelevant.example"]}],"actions":{"tls":{"action":"Deny"}}},{"name":"native","match":[{"domains":["*"]}],"actions":{"headerManipulation":{"set":[{"name":"x-native","value":"native"}]}}}]}`,
			kruise.AnnotationE2BNetwork:      `{"allow_internet_access":false,"network":{"allowOut":["*.example.com"],"rules":{"*.example.com":[{"transform":{"headers":{"X-Broad":"broad"}}}],"*.nested.example.com":[{"transform":{"headers":{"X-Tenant":"nested"}}}],"api.example.com":[{"transform":{"headers":{"X-Tenant":"first"}}},{"transform":{"headers":{"x-tenant":"{{ literal }}"}}}]}}}`,
		},
	}}
	local, err := NewSandboxProfile(obj)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.Project(regs); err != nil {
		t.Fatal(err)
	}
	policies, err := kruise.SandboxPolicies(obj)
	if err != nil {
		t.Fatal(err)
	}
	config := model.HTTPPolicy{E2BRuleOffset: policies.E2BRuleOffset}
	for _, rule := range policies.Profile().Rules {
		if rule.Actions.TLS == nil {
			config.Rules = append(config.Rules, rule)
		}
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	xds, err := FromXDS(&securityv1.SecurityProfile{Name: obj.Name, Namespace: obj.Namespace, PolicyJson: data, TcpPolicy: local.TCPPolicy}, "kruise:one", regs)
	if err != nil {
		t.Fatal(err)
	}
	for source, p := range map[string]*Profile{"local": local, "xds": xds} {
		for _, tc := range []struct {
			host string
			rule string
		}{
			{"api.example.com", "e2b-transform-0"},
			{"api.nested.example.com", "e2b-transform-1"},
			{"other.example.com", "e2b-transform-2"},
		} {
			t.Run(source+"/"+tc.host, func(t *testing.T) {
				req := testRequest(tc.host)
				req.Scheme = "https"
				bound, err := newBinder(regs, nil).bind([]*Profile{p}, req, inputs.Workload{})
				if err != nil {
					t.Fatal(err)
				}
				if len(bound.rules) != 3 || bound.rules[0].Rule.Name != "native" || bound.rules[1].Rule.Name != tc.rule || bound.rules[2].Rule.Name != "e2b-allow-https" {
					t.Fatalf("native, one transform, then bypass required: %+v", bound.rules)
				}
				if len(bound.units) != 4 || bound.units[3].CheckRequest == nil {
					t.Fatal("TCP checkpoint must follow all HTTP rules")
				}
				if tc.host == "api.example.com" {
					mutation := bound.rules[1].Cfgs[0].(headermutation.Config)
					if len(mutation.Request.Set) != 1 {
						t.Fatal("sequential assignments were not collapsed")
					}
					value, err := eval.RenderToString(mutation.Request.Set[0].Value, inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil))
					if err != nil || value != "{{ literal }}" {
						t.Fatalf("last assignment must remain literal: %q %v", value, err)
					}
				}
			})
		}
	}
}
