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
package admin

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// Kinds surfaced in ProfileView.Kind.
const (
	kindSecurityProfile       = "SecurityProfile"
	kindGlobalSecurityProfile = "GlobalSecurityProfile"
	// kindSandbox marks profiles compiled from a Sandbox's inline
	// security-rules annotation rather than a profile CRD.
	kindSandbox = "Sandbox"
)

// ProfileView is the serialized view of a single profile.
// By default only the identity fields are populated; the full-mode fields are
// filled when Full is requested.
type ProfileView struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Priority  int32  `json:"priority"`

	// Full-mode-only fields.
	CreationTimestamp *metav1.Time                  `json:"creationTimestamp,omitempty"`
	Spec              *v1alpha1.SecurityProfileSpec `json:"spec,omitempty"`
	// Error is set when full content could not be fetched for this profile;
	// the identity fields remain valid.
	Error string `json:"error,omitempty"`
}

// debugRequest is the input for the /debug/profiles endpoint when using POST.
// It accepts namespace, pod_labels, and full fields.
type debugRequest struct {
	// Namespace is the pod namespace. Required in match mode (when PodLabels is non-empty).
	Namespace string `json:"namespace"`
	// PodLabels is the pod label set to match selectors against. When non-empty,
	// triggers match mode and returns profiles in evaluation order.
	PodLabels map[string]string `json:"pod_labels,omitempty"`
	// PodName is the pod name. When set, match mode also includes the pod's
	// per-Sandbox inline rule profile, which is keyed by exact identity.
	PodName string `json:"pod_name,omitempty"`
	// Full requests the complete profile spec (fetched live from the
	// apiserver via the typed clientset) in addition to the identity fields.
	// Defaults to false.
	Full bool `json:"full,omitempty"`
}

// ListResponse is the /debug/profiles response.
type ListResponse struct {
	Count    int           `json:"count"`
	Profiles []ProfileView `json:"profiles"`
}

// errorResponse is the body returned for 4xx responses.
type errorResponse struct {
	Error string `json:"error"`
}
