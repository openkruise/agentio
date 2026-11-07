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
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// Register installs the /validate admission endpoint on the shared HTTPS mux.
func Register(mux *http.ServeMux) {
	webhook := &admission.Webhook{
		Handler: admission.HandlerFunc(func(_ context.Context, req admission.Request) admission.Response {
			if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update || req.SubResource != "" {
				return admission.Allowed("")
			}
			if req.Kind.Group != "agents.kruise.io" || req.Kind.Version != "v1alpha1" {
				return admission.Denied(fmt.Sprintf("unrecognized type %v", req.Kind))
			}
			var err error
			switch req.Kind.Kind {
			case "SecurityProfile", "GlobalSecurityProfile":
				var object agentsv1alpha1.SecurityProfile
				if err = json.Unmarshal(req.Object.Raw, &object); err == nil {
					err = ValidateSecurityProfile(model.SecurityProfile{
						Name:      object.Name,
						Namespace: req.Namespace,
						Global:    req.Kind.Kind == "GlobalSecurityProfile",
						Spec:      object.Spec,
					})
				}
			case "TrafficPolicy", "GlobalTrafficPolicy":
				var object agentsv1alpha1.TrafficPolicy
				if err = json.Unmarshal(req.Object.Raw, &object); err == nil {
					err = policy.ValidateTrafficPolicy(object.Spec)
				}
			default:
				return admission.Denied(fmt.Sprintf("unrecognized type %v", req.Kind))
			}
			if err != nil {
				return admission.Denied(fmt.Sprintf("configuration is invalid: %v", err))
			}
			return admission.Allowed("")
		}),
	}
	mux.Handle("/validate", webhook)
	mux.Handle("/validate/", webhook)
}
