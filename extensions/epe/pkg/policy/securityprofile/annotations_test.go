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
	"encoding/json"
	"slices"
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

func TestSandboxHeaderTransformsRunInMergedOrder(t *testing.T) {
	regs, err := filter.Build(headermutation.Definition(), bypass.Definition())
	if err != nil {
		t.Fatal(err)
	}
	obj := &agents.Sandbox{ObjectMeta: metav1.ObjectMeta{
		Name:      "sandbox",
		Namespace: "tenant",
		Annotations: map[string]string{
			kruise.AnnotationSecurityProfile: `{"rules":[{"name":"tls-native","match":[{"domains":["irrelevant.example"]}],"actions":{"tls":{"action":"Deny"}}},{"name":"native","match":[{"domains":["*"]}],"actions":{"headerManipulation":{"set":[{"name":"x-native","value":"{{ .Pod.Name }}-native"}]}}}]}`,
			kruise.AnnotationE2BNetwork:      `{"allowInternetAccess":false,"network":{"allowOut":["*.example.com"],"rules":{"*.example.com":[{"transform":{"headers":{"X-Broad":"broad"}}}],"*.nested.example.com":[{"transform":{"headers":{"X-Tenant":"nested"}}}],"api.example.com":[{"transform":{"headers":{"X-Tenant":"first"}}},{"transform":{"headers":{"x-tenant":"{{ .Pod.Name }}-e2b"}}}]}}}`,
		},
	}}
	local, err := NewSandboxProfile(obj)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.Project(regs); err != nil {
		t.Fatal(err)
	}
	spec, err := kruise.SandboxSecurityProfile(obj)
	if err != nil {
		t.Fatal(err)
	}
	var config model.HTTPPolicy
	for _, rule := range spec.Rules {
		if rule.Actions.TLS == nil {
			config.Rules = append(config.Rules, rule)
		}
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	xds, err := FromXDS(
		&securityv1.SecurityProfile{
			Name:       obj.Name,
			Namespace:  obj.Namespace,
			PolicyJson: data,
			TcpPolicy:  local.TCPPolicy,
		},
		"kruise:one",
		regs,
	)
	if err != nil {
		t.Fatal(err)
	}
	for source, p := range map[string]*Profile{"local": local, "xds": xds} {
		for _, tc := range []struct {
			host  string
			rules []string
		}{
			{"api.example.com", []string{"native", "agentio-e2b-transform-0", "agentio-e2b-transform-2", "agentio-e2b-allow-web"}},
			{"api.nested.example.com", []string{"native", "agentio-e2b-transform-0", "agentio-e2b-transform-1", "agentio-e2b-allow-web"}},
			{"api.example.com.", []string{"native", "agentio-e2b-transform-0", "agentio-e2b-transform-2", "agentio-e2b-allow-web"}},
			{"other.example.com", []string{"native", "agentio-e2b-transform-0", "agentio-e2b-allow-web"}},
		} {
			t.Run(source+"/"+tc.host, func(t *testing.T) {
				req := testRequest(tc.host)
				req.Scheme = "https"
				bound, err := newBinder(regs, nil).bind([]*Profile{p}, req, inputs.Workload{})
				if err != nil {
					t.Fatal(err)
				}
				names := make([]string, 0, len(bound.rules))
				for _, rule := range bound.rules {
					names = append(names, rule.Rule.Name)
				}
				if !slices.Equal(names, tc.rules) {
					t.Fatalf("matched rules = %v, want %v", names, tc.rules)
				}
				if len(bound.units) != len(tc.rules)+1 || bound.units[len(tc.rules)].CheckRequest == nil {
					t.Fatal("TCP checkpoint must follow all HTTP rules")
				}
				if tc.host == "api.example.com" {
					scope := inputs.NewScope(
						inputs.Request{},
						inputs.Workload{Name: "sandbox"},
						inputs.Profile{},
						inputs.Rule{},
						nil,
					)
					for _, want := range []struct {
						ruleIndex int
						value     string
					}{
						{0, "sandbox-native"},
						{2, "sandbox-e2b"},
					} {
						mutation := bound.rules[want.ruleIndex].Cfgs[0].(headermutation.Config)
						if len(mutation.Request.Set) != 1 {
							t.Fatal("expected one header assignment per rule")
						}
						value, err := eval.RenderToString(mutation.Request.Set[0].Value, scope)
						if err != nil || value != want.value {
							t.Fatalf("rendered header = %q, want %q: %v", value, want.value, err)
						}
					}
				}
			})
		}
	}
}
