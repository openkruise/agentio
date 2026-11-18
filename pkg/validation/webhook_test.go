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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestAdmission(t *testing.T) {
	mux := http.NewServeMux()
	Register(mux, nil)
	for _, tc := range []struct {
		name      string
		kind      string
		spec      string
		wantError string
	}{
		{"empty profile", "SecurityProfile", `{}`, ""},
		{"global profile", "GlobalSecurityProfile", `{}`, ""},
		{"negative priority", "SecurityProfile", `{"priority":-1}`, "negative"},
		{"bad selector", "SecurityProfile", `{"selector":{"matchExpressions":[{"key":"app","operator":"Bad"}]}}`, "operator"},
		{"regex", "SecurityProfile", `{"rules":[{"name":"r","match":[{"paths":[{"type":"Regex","value":"["}]}]}]}`, "error"},
		{"audit CEL syntax", "SecurityProfile", `{"audit":[{"name":"log","when":"request.","webhook":{"url":"http://audit"}}]}`, "CEL syntax"},
		{"consumer CEL context", "SecurityProfile", `{"audit":[{"name":"log","when":"customFunction(customVariable)","webhook":{"url":"http://audit"}}]}`, ""},
		{"callout API constraint", "SecurityProfile", `{"rules":[{"name":"r","actions":{"httpCallout":{"provider":{"name":"scanner"}}}}]}`, "phase"},
		{"consumer template context", "SecurityProfile", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"{{ customFunction .ConsumerField }}"}}}}]}`, ""},
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

func TestAdmissionProviderReferenceWarnings(t *testing.T) {
	stop := t.Context().Done()
	initial := model.AgentioConfiguration{Value: &configv1.AgentioConfig{}}
	configs := krt.NewStatic(&initial, true, krt.WithStop(stop))
	checker := NewReferenceChecker(ReferenceSources{
		AgentioConfig: configs.AsCollection(),
		ConfigMaps:    krt.NewStaticCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(stop)),
		Secrets:       krt.NewStaticCollection[*corev1.Secret](nil, nil, krt.WithStop(stop)),
		Services:      krt.NewStaticCollection[*corev1.Service](nil, nil, krt.WithStop(stop)),
		RootNamespace: "system",
	}, stop)
	mux := http.NewServeMux()
	Register(mux, checker)
	dryRun := true
	req := &admissionv1.AdmissionRequest{
		UID:       "provider-reference",
		Operation: admissionv1.Create,
		DryRun:    &dryRun,
		Namespace: "demo",
		Kind:      metav1.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: "SecurityProfile"},
		Object: runtime.RawExtension{Raw: []byte(`{
			"metadata":{"name":"policy"},
			"spec":{"rules":[{"name":"scan","actions":{"httpCallout":{"provider":{"name":"scanner"},"request":{}}}}]}
		}`)},
	}
	path := "spec.rules[0].actions.httpCallout.provider.name"
	for _, tc := range []struct {
		name    string
		config  string
		warning string
	}{
		{name: "missing", config: "{}", warning: "ProviderNotFound"},
		{
			name:    "wrong provider type",
			config:  "extensionProviders: [{name: scanner, credentialProvider: {url: https://scanner.example}}]",
			warning: "ProviderTypeMismatch",
		},
		{
			name:   "reference resolves after config update",
			config: "extensionProviders: [{name: scanner, httpCallout: {url: https://scanner.example}}]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.ApplyAgentioConfig(tc.config, &configv1.AgentioConfig{})
			if err != nil {
				t.Fatal(err)
			}
			configs.Set(&model.AgentioConfiguration{Value: cfg})
			got := admit(t, mux, req)
			if !got.Allowed {
				t.Fatalf("admission denied: %+v", got.Result)
			}
			if tc.warning == "" {
				if len(got.Warnings) != 0 {
					t.Fatalf("resolved reference warned: %v", got.Warnings)
				}
			} else if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "["+tc.warning+"] "+path) {
				t.Fatalf("warnings = %v, want %s for %s", got.Warnings, tc.warning, path)
			}
		})
	}
	req.Object.Raw = bytes.ReplaceAll(req.Object.Raw, []byte(`"scanner"`), []byte(`"bad/name"`))
	got := admit(t, mux, req)
	if got.Allowed || got.Result == nil || got.Result.Reason != metav1.StatusReasonInvalid || len(got.Warnings) != 0 {
		t.Fatalf("invalid provider name response = %+v", got)
	}
	if got.Result.Details == nil ||
		len(got.Result.Details.Causes) != 1 || got.Result.Details.Causes[0].Field != path {
		t.Fatalf("invalid provider name details = %+v, want field %s", got.Result.Details, path)
	}
}

func TestAdmissionReferenceWarningsUseCacheScope(t *testing.T) {
	stop := t.Context().Done()
	initial := model.AgentioConfiguration{Value: &configv1.AgentioConfig{}}
	mux := http.NewServeMux()
	pending := krt.NewStatic[bool](nil, false, krt.WithStop(stop))
	Register(mux, NewReferenceChecker(ReferenceSources{
		AgentioConfig: krt.NewStatic(&initial, true, krt.WithStop(stop)).AsCollection(),
		ConfigMaps:    krt.NewStaticCollection[*corev1.ConfigMap](pending.AsCollection(), nil, krt.WithStop(stop)),
		Secrets:       krt.NewStaticCollection[*corev1.Secret](nil, nil, krt.WithStop(stop)),
		Services:      krt.NewStaticCollection[*corev1.Service](nil, nil, krt.WithStop(stop)),
		RootNamespace: "system",
		ScopedSecrets: true,
	}, stop))
	for _, tc := range []struct {
		kind      string
		namespace string
		spec      string
		warning   string
	}{
		{"SecurityProfile", "system", `{"inputs":[{"name":"opts","configMap":{"name":"opts"}}]}`, ""},
		{"SecurityProfile", "demo", `{"rules":[{"name":"auth","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}}}}}]}`, "[RefNotPermitted] spec.rules[0].actions.tokenTransformation.credentialRef: Rule \"auth\": Secret demo/cred is outside the permitted namespace system"},
		{"SecurityProfile", "system", `{"rules":[{"name":"auth","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}}}}}]}`, "SecretNotFound"},
		{"GlobalTrafficPolicy", "", `{"egress":{"rules":[{"action":"allow","to":[{"service":{"name":"api"}}]}]}}`, "Service system/api not found"},
		{"TrafficPolicy", "demo", `{"egress":{"rules":[{"action":"allow","to":[{"fqdn":"api.example.com"}]}]}}`, ""},
	} {
		got := admit(t, mux, &admissionv1.AdmissionRequest{
			UID:       "reference-scope",
			Operation: admissionv1.Update,
			Namespace: tc.namespace,
			Kind:      metav1.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: tc.kind},
			Object:    runtime.RawExtension{Raw: []byte(`{"metadata":{"name":"test"},"spec":` + tc.spec + `}`)},
		})
		if !got.Allowed ||
			(tc.warning == "" && len(got.Warnings) != 0) ||
			(tc.warning != "" && (len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], tc.warning))) {
			t.Fatalf("%s %s response = %+v, want warning %q", tc.kind, tc.spec, got, tc.warning)
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
