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

package validation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAdmission(t *testing.T) {
	mux := http.NewServeMux()
	if err := Register(mux); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, kind, spec, wantError string
	}{
		{"empty profile", "SecurityProfile", `{}`, ""},
		{"global profile", "GlobalSecurityProfile", `{}`, ""},
		{"negative priority", "SecurityProfile", `{"priority":-1}`, "negative"},
		{"bad selector", "SecurityProfile", `{"selector":{"matchExpressions":[{"key":"app","operator":"Bad"}]}}`, "operator"},
		{"regex", "SecurityProfile", `{"rules":[{"name":"r","match":[{"paths":[{"type":"Regex","value":"["}]}]}]}`, "error"},
		{"audit CEL", "SecurityProfile", `{"audit":[{"name":"log","when":"unknownVariable","webhook":{"url":"http://audit"}}]}`, "unknownVariable"},
		{"filter parser", "SecurityProfile", `{"rules":[{"name":"r","actions":{"httpCallout":{"provider":{"name":"scanner"}}}}]}`, "L7"},
		{"unresolved reference allowed", "SecurityProfile", `{"inputs":[{"name":"config","configMap":{"name":"missing"}}]}`, ""},
		{"global input namespace", "GlobalSecurityProfile", `{"inputs":[{"name":"config","configMap":{"name":"missing"}}]}`, "namespace"},
		{"traffic", "TrafficPolicy", `{"egress":{"rules":[{"action":"allow","to":[{"cidr":"10.0.0.0/8"}]}]}}`, ""},
		{"global traffic", "GlobalTrafficPolicy", `{"ingress":{}}`, ""},
		{"unresolved service allowed", "TrafficPolicy", `{"egress":{"rules":[{"action":"allow","to":[{"service":{"name":"missing"}}]}]}}`, ""},
		{"bad CIDR", "TrafficPolicy", `{"egress":{"rules":[{"action":"allow","to":[{"cidr":"oops"}]}]}}`, "CIDR"},
		{"traffic priority", "TrafficPolicy", `{"priority":-1}`, "priority"},
		{"bad action", "TrafficPolicy", `{"egress":{"rules":[{"action":"drop"}]}}`, "action"},
		{"protocol", "TrafficPolicy", `{"egress":{"rules":[{"action":"allow","ports":[{"protocol":"BAD"}]}]}}`, "protocol"},
		{"port", "TrafficPolicy", `{"egress":{"rules":[{"action":"allow","ports":[{"port":65536}]}]}}`, "port"},
		{"range", "TrafficPolicy", `{"egress":{"rules":[{"action":"allow","ports":[{"port":100,"endPort":10}]}]}}`, "reversed"},
		{"ICMP", "TrafficPolicy", `{"egress":{"rules":[{"action":"allow","ports":[{"protocol":"ICMP","port":80}]}]}}`, "ICMP"},
		{"unknown kind", "Other", `{}`, "unrecognized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, operation := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update} {
				for _, dryRun := range []bool{false, true} {
					req := &admissionv1.AdmissionRequest{
						UID:       "request-uid",
						Operation: operation,
						Namespace: "demo",
						DryRun:    &dryRun,
						Kind: metav1.GroupVersionKind{
							Group:   "agents.kruise.io",
							Version: "v1alpha1",
							Kind:    tc.kind,
						},
						Object: runtime.RawExtension{
							Raw: []byte(`{"metadata":{"name":"test"},"spec":` + tc.spec + `}`),
						},
					}
					if strings.HasPrefix(tc.kind, "Global") {
						req.Namespace = ""
					}
					got := admit(t, mux, req)
					if got.Allowed != (tc.wantError == "") {
						t.Fatalf("allowed = %v, result = %+v", got.Allowed, got.Result)
					}
					if tc.wantError != "" &&
						(got.Result == nil || !strings.Contains(got.Result.Message, tc.wantError)) {
						t.Fatalf("result = %+v, want %q", got.Result, tc.wantError)
					}
				}
			}
		})
	}
	for _, req := range []*admissionv1.AdmissionRequest{
		{UID: "delete", Operation: admissionv1.Delete},
		{UID: "status", Operation: admissionv1.Update, SubResource: "status"},
	} {
		if got := admit(t, mux, req); !got.Allowed {
			t.Fatalf("excluded request denied: %+v", got)
		}
	}
}

func admit(t *testing.T, handler http.Handler, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	t.Helper()
	body, err := json.Marshal(
		admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Request:  req,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if review.Response == nil || review.Response.UID != req.UID {
		t.Fatalf("invalid response: %s", w.Body.String())
	}
	return review.Response
}
