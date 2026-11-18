// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package securityprofile

import (
	"encoding/json"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
)

func TestHTTPCalloutProjection(t *testing.T) {
	regs, err := filter.Build(httpcallout.NewDefinition(httpcallout.Deps{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		action  string
		invalid bool
		check   func(*testing.T, httpcallout.Config)
	}{
		{
			name:   "metadata only",
			action: `{"provider":{"name":"scanner"},"request":{}}`,
			check: func(t *testing.T, c httpcallout.Config) {
				if c.Request == nil || c.Response != nil || c.Request.Body || c.Request.Headers.Mode != httpcallout.HeaderModeNone || c.FailOpen {
					t.Fatalf("config = %+v", c)
				}
			},
		},
		{
			name:   "independent phases",
			action: `{"provider":{"name":"scanner"},"request":{"headers":{"enabled":true,"filter":{"allowList":["X-ID"]}},"body":{"enabled":true,"maxBytes":3}},"response":{"headers":{"enabled":true,"filter":{"denyList":["Set-Cookie"]}},"body":{"enabled":true,"maxBytes":5}},"failStrategy":"Allow"}`,
			check: func(t *testing.T, c httpcallout.Config) {
				if !c.FailOpen || !c.Request.Body || !c.Response.Body || c.Request.MaxBodyBytes != 3 || c.Response.MaxBodyBytes != 5 || c.Request.Headers.Allowlist[0] != "x-id" || c.Response.Headers.Denylist[0] != "set-cookie" {
					t.Fatalf("config = %+v, request=%+v, response=%+v", c, c.Request, c.Response)
				}
			},
		},
		{
			name:   "all headers",
			action: `{"provider":{"name":"scanner"},"response":{"headers":{"enabled":true}},"failStrategy":"Ignore"}`,
			check: func(t *testing.T, c httpcallout.Config) {
				if c.Request != nil || !c.FailOpen || c.Response.Headers.Mode != httpcallout.HeaderModeAll {
					t.Fatalf("config = %+v", c)
				}
			},
		},
		{
			name:   "disabled settings ignored",
			action: `{"provider":{"name":"scanner"},"request":{"headers":{"filter":{}},"body":{"maxBytes":-1}}}`,
			check: func(t *testing.T, c httpcallout.Config) {
				if c.Request.Body || c.Request.Headers.Mode != httpcallout.HeaderModeNone {
					t.Fatalf("phase = %+v", c.Request)
				}
			},
		},
		{name: "no phase", action: `{"provider":{"name":"scanner"}}`, invalid: true},
		{name: "no provider", action: `{"request":{}}`, invalid: true},
		{name: "empty filter", action: `{"provider":{"name":"scanner"},"request":{"headers":{"enabled":true,"filter":{}}}}`, invalid: true},
		{name: "both lists", action: `{"provider":{"name":"scanner"},"request":{"headers":{"enabled":true,"filter":{"allowList":["x"],"denyList":["y"]}}}}`, invalid: true},
		{name: "invalid header", action: `{"provider":{"name":"scanner"},"request":{"headers":{"enabled":true,"filter":{"allowList":["bad header"]}}}}`, invalid: true},
		{name: "oversized limit", action: `{"provider":{"name":"scanner"},"request":{"body":{"enabled":true,"maxBytes":8388609}}}`, invalid: true},
		{name: "negative limit", action: `{"provider":{"name":"scanner"},"request":{"body":{"enabled":true,"maxBytes":-1}}}`, invalid: true},
		{name: "unknown strategy", action: `{"provider":{"name":"scanner"},"request":{},"failStrategy":"typo"}`, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var action v1alpha1.HTTPCalloutAction
			if err := json.Unmarshal([]byte(tc.action), &action); err != nil {
				t.Fatal(err)
			}
			profile := &Profile{
				Rules: []Rule{{Name: "scan", Actions: v1alpha1.SecurityRuleActions{HTTPCallout: &action}}},
			}
			err := profile.Project(regs)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid action accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg := profile.Projections[0].Cfgs[0].(httpcallout.Config)
			if cfg.Provider != "scanner" {
				t.Fatalf("provider=%q", cfg.Provider)
			}
			tc.check(t, cfg)
		})
	}
}

func TestHTTPCalloutPreservedWithOAuth2(t *testing.T) {
	var actions v1alpha1.SecurityRuleActions
	if err := json.Unmarshal(
		[]byte(
			`{"httpCallout":{"provider":{"name":"scanner"},"request":{}},"tokenTransformation":{"type":"OAuth2","credentialRef":{"credentialProvider":{"name":"identity"}},"oauth2":{"operation":{"resource":{}}}}}`,
		),
		&actions,
	); err != nil {
		t.Fatal(err)
	}
	payloads, err := payloadsFor(&Rule{Actions: actions})
	if err != nil {
		t.Fatal(err)
	}
	if payloads[httpcallout.FilterName] == nil {
		t.Fatal("OAuth2 discarded callout")
	}
}
