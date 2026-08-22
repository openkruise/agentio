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

package spstatus

import (
	"fmt"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pkg/kube/krt"
)

// Condition reasons produced by ResolveRefs.
const (
	ReasonSecretNotFound     = "SecretNotFound"
	ReasonUnsupportedRefKind = "UnsupportedRefKind"
)

// RefError is one unresolved reference.
type RefError struct {
	Field   string
	Reason  string
	Message string
}

// ResolveRefs checks that every credentialRef in the profile points at
// something that exists. Only existence is verified; the data keys a
// credential must carry are a runtime concern owned by traffic-extension.
//
// CredentialRef with Kind=Secret must live in the profile's own namespace —
// cross-namespace references are disallowed by the API
// (securityprofile_types.go:244-246), so the lookup key is always
// "<profile namespace>/<ref name>".
//
// Kind=CredentialProvider cannot be verified from the control plane and is
// treated as resolved.
func ResolveRefs(
	ctx krt.HandlerContext,
	sp *agentsv1alpha1.SecurityProfile,
	secrets krt.Collection[*corev1.Secret],
) []RefError {
	if sp == nil {
		return nil
	}
	var errs []RefError
	for i, rule := range sp.Spec.Rules {
		tt := rule.Actions.TokenTransformation
		if tt == nil {
			continue
		}
		field := fmt.Sprintf("spec.rules[%d].actions.tokenTransformation.credentialRef", i)
		switch tt.CredentialRef.Kind {
		case agentsv1alpha1.CredentialRefKindSecret:
			nn := types.NamespacedName{Namespace: sp.Namespace, Name: tt.CredentialRef.Name}
			if krt.FetchOne(ctx, secrets, krt.FilterObjectName(nn)) == nil {
				errs = append(errs, RefError{
					Field:  field + ".name",
					Reason: ReasonSecretNotFound,
					Message: fmt.Sprintf("Secret %q not found in namespace %q",
						tt.CredentialRef.Name, sp.Namespace),
				})
			}
		case agentsv1alpha1.CredentialRefKindCredentialProvider:
			// Not verifiable from the control plane.
		default:
			errs = append(errs, RefError{
				Field:   field + ".kind",
				Reason:  ReasonUnsupportedRefKind,
				Message: fmt.Sprintf("unsupported credentialRef kind %q", tt.CredentialRef.Kind),
			})
		}
	}
	return errs
}
