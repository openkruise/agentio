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

func TestValidateAdditionalExtProcs(t *testing.T) {
	valid := func() *configv1.ExtProcProvider {
		return &configv1.ExtProcProvider{Name: "scanner", Service: "scanner.demo.svc"}
	}
	for _, tc := range []struct {
		name   string
		change func(*configv1.ExtProcProvider)
	}{
		{"missing name", func(p *configv1.ExtProcProvider) { p.Name = "" }},
		{"invalid name", func(p *configv1.ExtProcProvider) { p.Name = "a/b" }},
		{"missing service", func(p *configv1.ExtProcProvider) { p.Service = " " }},
		{"invalid port", func(p *configv1.ExtProcProvider) { p.Port = 65536 }},
		{"invalid timeout", func(p *configv1.ExtProcProvider) { p.MessageTimeout = "bad" }},
		{"zero timeout", func(p *configv1.ExtProcProvider) { p.MessageTimeout = "0s" }},
		{"negative timeout", func(p *configv1.ExtProcProvider) { p.MessageTimeout = "-1s" }},
		{"invalid mode", func(p *configv1.ExtProcProvider) { p.Request = &configv1.ProcessingModeOptions{HeaderMode: 42} }},
		{"invalid TLS", func(p *configv1.ExtProcProvider) {
			p.Tls = &configv1.ExtProcTLSSettings{Mode: configv1.ExtProcTLSSettings_MUTUAL}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid()
			tc.change(p)
			if ValidateAdditionalExtProcs([]*configv1.ExtProcProvider{p}) == nil {
				t.Fatal("invalid provider accepted")
			}
		})
	}
	for _, list := range [][]*configv1.ExtProcProvider{{nil}, {valid(), valid()}} {
		if ValidateAdditionalExtProcs(list) == nil {
			t.Fatal("invalid list accepted")
		}
	}
	for _, list := range [][]*configv1.ExtProcProvider{nil, {valid()}} {
		if err := ValidateAdditionalExtProcs(list); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExtProcServiceReference(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ref     *configv1.ServiceReference
		port    uint32
		invalid bool
	}{
		{name: "DNS"},
		{name: "reference", ref: &configv1.ServiceReference{Namespace: "system", Name: "epe"}},
		{name: "missing namespace", ref: &configv1.ServiceReference{Name: "epe"}, invalid: true},
		{name: "missing name", ref: &configv1.ServiceReference{Namespace: "system"}, invalid: true},
		{name: "empty reference", ref: &configv1.ServiceReference{}, invalid: true},
		{name: "invalid namespace", ref: &configv1.ServiceReference{Namespace: "System", Name: "epe"}, invalid: true},
		{name: "invalid name", ref: &configv1.ServiceReference{Namespace: "system", Name: "epe.other"}, invalid: true},
		{name: "invalid port", ref: &configv1.ServiceReference{Namespace: "system", Name: "epe"}, port: 65536, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &configv1.ExtProcProvider{
				Name:       "processor",
				Service:    "fallback.system.svc",
				ServiceRef: tc.ref,
				Port:       tc.port,
			}
			if err := ValidateExtProcServiceRef(provider); (err != nil) != tc.invalid {
				t.Fatalf("target error=%v, want invalid=%v", err, tc.invalid)
			}
			if err := ValidateAdditionalExtProcs([]*configv1.ExtProcProvider{provider}); (err != nil) != tc.invalid {
				t.Fatalf("additional processor error=%v, want invalid=%v", err, tc.invalid)
			}
		})
	}
	provider := &configv1.ExtProcProvider{
		Name:       "processor",
		ServiceRef: &configv1.ServiceReference{Namespace: "system", Name: "epe"},
	}
	if !ExtProcEnabled(provider) || ValidateAdditionalExtProcs([]*configv1.ExtProcProvider{provider}) != nil {
		t.Fatal("reference-only provider must be enabled and valid")
	}
}
