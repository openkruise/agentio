//go:build ignore

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

// Generate benchmark inputs and reference projections using the real Go compiler.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

type fixture struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	SNI    []byte `json:"sni"`
	TCP    []byte `json:"tcp"`
}

func main() {
	var fixtures []fixture
	for _, c := range []struct {
		name    string
		http    int
		tcp     int
		headers int
		value   int
		escaped bool
	}{
		{"empty", 0, 0, 0, 0, false},
		{"small", 8, 16, 2, 64, false},
		{"typical", 64, 128, 4, 128, false},
		{"tcp-heavy", 8, 1024, 2, 64, false},
		{"many-http", 256, 128, 4, 256, false},
		{"http-heavy", 64, 16, 16, 1024, false},
		{"http-heavy-escaped", 64, 16, 16, 1024, true},
	} {
		spec := agents.SecurityProfileSpec{}
		if c.http > 0 {
			for i, action := range []agents.TLSActionType{agents.TLSActionPassthrough, agents.TLSActionDeny} {
				spec.Rules = append(spec.Rules, agents.SecurityRule{
					Name: fmt.Sprintf("tls-%d", i),
					Match: []agents.RuleMatch{
						{Domains: []string{fmt.Sprintf("tls-%d.example.com", i)}, Ports: []int32{8443}},
					},
					Actions: agents.SecurityRuleActions{TLS: &agents.TLSAction{Action: action}},
				})
			}
		}
		for i := 0; i < c.http; i++ {
			value := strings.Repeat("x", c.value)
			if c.escaped {
				value = strings.Repeat("a\"\\b", c.value/4)
			}
			var headers []agents.HeaderValue
			for j := 0; j < c.headers; j++ {
				headers = append(headers, agents.HeaderValue{Name: fmt.Sprintf("x-bench-%d", j), Value: value})
			}
			schemes := []string{"https"}
			if i%4 == 0 {
				schemes = []string{"http"}
			}
			spec.Rules = append(spec.Rules, agents.SecurityRule{
				Name: fmt.Sprintf("http-%d", i),
				Match: []agents.RuleMatch{
					{
						Domains: []string{fmt.Sprintf("API-%d.Example.COM.", i), "*.example.com", "*.example.com"},
						Ports:   []int32{443},
						Schemes: schemes,
						Paths: []agents.PathMatch{
							{Type: agents.PathMatchTypePrefix, Value: "/v1/"},
						},
						Methods: []string{"POST"},
					},
				},
				Actions: agents.SecurityRuleActions{HeaderManipulation: &agents.HeaderManipulationAction{Set: headers}},
			})
		}
		for i := 0; i < c.tcp; i++ {
			cidr, action := fmt.Sprintf("198.51.100.%d/32", i%256), "deny"
			if i == c.tcp-1 {
				cidr, action = "192.0.2.1/32", "allow"
			}
			spec.TCPRules = append(spec.TCPRules, agents.TCPRule{
				Name:   fmt.Sprintf("tcp-%d", i),
				Action: action,
				Match:  []agents.TCPMatch{{CIDRs: []string{cidr}, Ports: []int32{443}}},
			})
		}
		compiled, err := policy.CompileSecurityProfile(
			model.SecurityProfile{UID: "bench-uid", Name: c.name, Namespace: "bench", Spec: spec},
		)
		if err != nil {
			panic(err)
		}
		source, err := json.Marshal(map[string]any{
			"apiVersion": "agents.kruise.io/v1alpha1",
			"kind":       "SecurityProfile",
			"metadata": map[string]any{
				"uid":        "bench-uid",
				"name":       c.name,
				"namespace":  "bench",
				"generation": 1,
			},
			"spec": spec,
		})
		if err != nil {
			panic(err)
		}
		sni, err := proto.Marshal(compiled.SNIPolicy)
		if err != nil {
			panic(err)
		}
		if sni == nil {
			sni = []byte{}
		}
		tcp, err := proto.Marshal(compiled.TCPPolicy)
		if err != nil {
			panic(err)
		}
		fixtures = append(fixtures, fixture{c.name, string(source), sni, tcp})
	}
	output, err := json.Marshal(fixtures)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], output, 0644); err != nil {
		panic(err)
	}
}
