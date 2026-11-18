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
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

func TestScenario_HTTPCalloutPublicAPI(t *testing.T) {
	for _, kind := range []string{"SecurityProfile", "GlobalSecurityProfile"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var inv httpcallout.Invocation
				if err := json.NewDecoder(r.Body).Decode(&inv); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				calls.Add(1)
				if inv.Phase == httpcallout.PhaseRequest {
					if inv.Request.Body == nil || *inv.Request.Body != "abc" || inv.Request.Headers["x-id"] != "123" ||
						len(inv.Request.Headers) != 1 {
						t.Errorf("request disclosure = %+v", inv.Request)
					}
					if _, err := fmt.Fprint(
						w,
						`{"version":"0.1","action":"continue","request":{"headers":[{"operation":"set","name":"x-scanned","value":"yes"}]}}`,
					); err != nil {
						t.Error(err)
					}
				} else {
					if inv.Response.Body == nil || *inv.Response.Body != "12345" ||
						inv.Response.Headers["set-cookie"] != "" ||
						inv.Request.Body != nil ||
						len(inv.Request.Headers) != 0 {
						t.Errorf("response disclosure = %+v request=%+v", inv.Response, inv.Request)
					}
					if _, err := fmt.Fprint(
						w,
						`{"version":"0.1","action":"continue","response":{"headers":[{"operation":"set","name":"x-scanned","value":"yes"}]}}`,
					); err != nil {
						t.Error(err)
					}
				}
			}))
			defer endpoint.Close()
			providers := &extensionprovider.Registry{}
			defer providers.Close()
			if err := providers.Apply(
				&configv1.AgentioConfig{
					ExtensionProviders: []*configv1.ExtensionProvider{
						{
							Name: "scanner",
							Provider: &configv1.ExtensionProvider_HttpCallout{
								HttpCallout: &configv1.HTTPCalloutProvider{Url: endpoint.URL},
							},
						},
					},
				},
				nil,
			); err != nil {
				t.Fatal(err)
			}
			h := New(t, Options{Providers: providers})
			namespace := ""
			if kind == "SecurityProfile" {
				namespace = "  namespace: test-ns\n"
			}
			h.Fixture.ApplyYAML(fmt.Sprintf(`apiVersion: agents.kruise.io/v1alpha1
kind: %s
metadata:
  name: scanner
%sspec:
  selector: {}
  rules:
  - name: scan
    match:
    - domains: ["*"]
    actions:
      httpCallout:
        provider: {name: scanner}
        request:
          headers: {enabled: true, filter: {allowList: [x-id]}}
          body: {enabled: true, maxBytes: 3}
        response:
          headers: {enabled: true, filter: {denyList: [set-cookie]}}
          body: {enabled: true, maxBytes: 5}
`, kind, namespace))
			v := h.Run(
				t,
				enginetest.NewRequest("POST", "api.example.com", "/").
					Workload("test-ns", "sandbox", nil).
					Header("x-id", "123").
					Header("authorization", "secret").
					Body([]byte("abc")).
					ResponseHeaders(200).
					ResponseHeader("set-cookie", "secret").
					ResponseBody([]byte("12345")),
			)
			v.RequireHeader(t, "x-scanned", "yes")
			v.RequireResponseHeader(t, "x-scanned", "yes")
			if calls.Load() != 2 {
				t.Fatalf("calls=%d", calls.Load())
			}
		})
	}
}

func TestScenario_HTTPCalloutMissingProviderFailureStrategy(t *testing.T) {
	for _, strategy := range []string{"Block", "Allow", "Ignore"} {
		t.Run(strategy, func(t *testing.T) {
			h := New(t, Options{})
			h.Fixture.ApplyYAML(fmt.Sprintf(`apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata: {name: scanner, namespace: test-ns}
spec:
  selector: {}
  rules:
  - name: scan
    match:
    - domains: ["*"]
    actions:
      httpCallout:
        provider: {name: missing}
        request: {}
        failStrategy: %s
`, strategy))
			v := h.Run(t, enginetest.NewRequest("GET", "api.example.com", "/").Workload("test-ns", "sandbox", nil))
			if strategy == "Block" {
				v.RequireBlocked(t, http.StatusInternalServerError)
			} else {
				v.RequireBypassed(t)
			}
		})
	}
}
