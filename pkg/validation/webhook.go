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
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// Register installs /validate. References may be nil for static validation alone.
func Register(mux *http.ServeMux, references *ReferenceChecker) {
	webhook := &admission.Webhook{
		Handler: admission.HandlerFunc(func(_ context.Context, req admission.Request) admission.Response {
			if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update || req.SubResource != "" {
				return admission.Allowed("")
			}
			if req.Kind.Group != "agents.kruise.io" || req.Kind.Version != "v1alpha1" {
				return admission.Denied(fmt.Sprintf("unrecognized type %v", req.Kind))
			}
			var errs field.ErrorList
			var issues []ReferenceIssue
			var name string
			switch req.Kind.Kind {
			case "SecurityProfile", "GlobalSecurityProfile":
				var object agentsv1alpha1.SecurityProfile
				if err := json.Unmarshal(req.Object.Raw, &object); err != nil {
					return admission.Errored(http.StatusBadRequest, err)
				}
				name = object.Name
				profile := model.SecurityProfile{
					Name:      name,
					Namespace: req.Namespace,
					Global:    req.Kind.Kind == "GlobalSecurityProfile",
					Spec:      object.Spec,
				}
				errs = ValidateSecurityProfile(profile)
				if len(errs) == 0 && references != nil {
					issues = references.SecurityProfile(nil, profile)
				}
			case "TrafficPolicy", "GlobalTrafficPolicy":
				var object agentsv1alpha1.TrafficPolicy
				if err := json.Unmarshal(req.Object.Raw, &object); err != nil {
					return admission.Errored(http.StatusBadRequest, err)
				}
				name = object.Name
				errs = policy.ValidateTrafficPolicy(object.Spec)
				if len(errs) == 0 && references != nil {
					issues = references.TrafficPolicy(nil, model.TrafficPolicy{
						Name:      name,
						Namespace: req.Namespace,
						Global:    req.Kind.Kind == "GlobalTrafficPolicy",
						Spec:      object.Spec,
					})
				}
			default:
				return admission.Denied(fmt.Sprintf("unrecognized type %v", req.Kind))
			}
			if len(errs) != 0 {
				kind := schema.GroupKind{Group: req.Kind.Group, Kind: req.Kind.Kind}
				status := apierrors.NewInvalid(kind, name, errs).ErrStatus
				return admission.Response{AdmissionResponse: admissionv1.AdmissionResponse{Allowed: false, Result: &status}}
			}
			var warnings []string
			for _, issue := range issues {
				warnings = append(warnings, fmt.Sprintf("[%s] %s: %s", issue.Reason, issue.Field, issue.Message))
			}
			return admission.Allowed("").WithWarnings(warnings...)
		}),
	}
	mux.Handle("/validate", webhook)
	mux.Handle("/validate/", webhook)
}
