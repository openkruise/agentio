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

// credentialref.go is CRD compatibility, not policy. CredentialRef carries a
// deprecated flat kind/name/namespace spelling alongside the typed
// secret/credentialProvider union, and collapsing the two is the adapter's
// job: the tokentransform filter's schema accepts only the typed form, so
// this knowledge must not travel with the payload.
package securityprofile

import (
	"fmt"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// NormalizeCredentialRef returns ref with only the typed union populated,
// rejecting the combinations the CRD's own schema validation cannot
// express. Rejecting is the point: an unreadable credentialRef must fail
// the rule closed rather than resolve to some default source.
func NormalizeCredentialRef(ref v1alpha1.CredentialRef) (v1alpha1.CredentialRef, error) {
	hasSecret := ref.Secret != nil
	hasProvider := ref.CredentialProvider != nil
	if hasSecret && hasProvider {
		return v1alpha1.CredentialRef{}, fmt.Errorf("credentialRef must not set both secret and credentialProvider")
	}
	if hasSecret || hasProvider {
		if ref.Kind != "" || ref.Name != "" || ref.Namespace != "" {
			return v1alpha1.CredentialRef{}, fmt.Errorf("typed credentialRef must not be combined with deprecated fields")
		}
		if hasSecret {
			if ref.Secret.Name == "" {
				return v1alpha1.CredentialRef{}, fmt.Errorf("credentialRef.secret.name is empty")
			}
			return v1alpha1.CredentialRef{Secret: ref.Secret}, nil
		}
		if ref.CredentialProvider.Name == "" {
			return v1alpha1.CredentialRef{}, fmt.Errorf("credentialRef.credentialProvider.name is empty")
		}
		return v1alpha1.CredentialRef{CredentialProvider: ref.CredentialProvider}, nil
	}

	if ref.Name == "" {
		return v1alpha1.CredentialRef{}, fmt.Errorf("credentialRef.name is empty")
	}
	switch ref.Kind {
	case v1alpha1.CredentialRefKindSecret:
		return v1alpha1.CredentialRef{
			Secret: &v1alpha1.SecretCredentialRef{Name: ref.Name, Namespace: ref.Namespace},
		}, nil
	case v1alpha1.CredentialRefKindCredentialProvider:
		// The deprecated spelling has no parameters field, so a provider
		// reached through it can only ever be parameterless.
		return v1alpha1.CredentialRef{
			CredentialProvider: &v1alpha1.CredentialProviderRef{Name: ref.Name},
		}, nil
	default:
		return v1alpha1.CredentialRef{}, fmt.Errorf("unsupported credentialRef kind: %s", ref.Kind)
	}
}
