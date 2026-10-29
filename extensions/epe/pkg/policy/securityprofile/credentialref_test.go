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
	"reflect"
	"strings"
	"testing"

	"k8s.io/utils/ptr"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// Normalization is what lets the tokentransform filter accept only the
// typed union: every deprecated spelling must arrive here and leave as one
// of the two typed branches, or fail.
func TestNormalizeCredentialRef(t *testing.T) {
	tests := []struct {
		name        string
		ref         v1alpha1.CredentialRef
		want        v1alpha1.CredentialRef
		expectError string
	}{
		{
			name: "deprecated secret becomes typed secret",
			ref: v1alpha1.CredentialRef{
				Kind:      v1alpha1.CredentialRefKindSecret,
				Name:      "legacy-secret",
				Namespace: "tenant-a",
			},
			want: v1alpha1.CredentialRef{Secret: &v1alpha1.SecretCredentialRef{
				Name:      "legacy-secret",
				Namespace: "tenant-a",
			}},
		},
		{
			// The deprecated spelling has no parameters field, so a provider
			// reached through it is necessarily parameterless.
			name: "deprecated provider becomes typed provider",
			ref: v1alpha1.CredentialRef{
				Kind: v1alpha1.CredentialRefKindCredentialProvider,
				Name: "legacy-provider",
			},
			want: v1alpha1.CredentialRef{CredentialProvider: &v1alpha1.CredentialProviderRef{
				Name: "legacy-provider",
			}},
		},
		{
			name: "typed secret passes through",
			ref: v1alpha1.CredentialRef{Secret: &v1alpha1.SecretCredentialRef{
				Name:      "typed-secret",
				Namespace: "tenant-a",
			}},
			want: v1alpha1.CredentialRef{Secret: &v1alpha1.SecretCredentialRef{
				Name:      "typed-secret",
				Namespace: "tenant-a",
			}},
		},
		{
			name: "typed provider keeps its parameters",
			ref: v1alpha1.CredentialRef{CredentialProvider: &v1alpha1.CredentialProviderRef{
				Name:       "typed-provider",
				Parameters: map[string]v1alpha1.ValueSource{"scope": {Value: ptr.To("readonly")}},
			}},
			want: v1alpha1.CredentialRef{CredentialProvider: &v1alpha1.CredentialProviderRef{
				Name:       "typed-provider",
				Parameters: map[string]v1alpha1.ValueSource{"scope": {Value: ptr.To("readonly")}},
			}},
		},
		{
			name: "both typed sources",
			ref: v1alpha1.CredentialRef{
				Secret:             &v1alpha1.SecretCredentialRef{Name: "secret"},
				CredentialProvider: &v1alpha1.CredentialProviderRef{Name: "provider"},
			},
			expectError: "must not set both",
		},
		{
			name: "typed and deprecated fields",
			ref: v1alpha1.CredentialRef{
				Secret: &v1alpha1.SecretCredentialRef{Name: "secret"},
				Kind:   v1alpha1.CredentialRefKindSecret,
				Name:   "legacy-secret",
			},
			expectError: "must not be combined",
		},
		{
			name:        "empty typed secret name",
			ref:         v1alpha1.CredentialRef{Secret: &v1alpha1.SecretCredentialRef{}},
			expectError: "secret.name is empty",
		},
		{
			name:        "empty typed provider name",
			ref:         v1alpha1.CredentialRef{CredentialProvider: &v1alpha1.CredentialProviderRef{}},
			expectError: "credentialProvider.name is empty",
		},
		{
			name:        "empty deprecated name",
			ref:         v1alpha1.CredentialRef{Kind: v1alpha1.CredentialRefKindSecret},
			expectError: "credentialRef.name is empty",
		},
		{
			name:        "unsupported deprecated kind",
			ref:         v1alpha1.CredentialRef{Kind: "Unknown", Name: "ref"},
			expectError: "unsupported credentialRef kind",
		},
		{
			name:        "no source at all",
			ref:         v1alpha1.CredentialRef{},
			expectError: "credentialRef.name is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeCredentialRef(tt.ref)
			if tt.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectError) {
					t.Fatalf("NormalizeCredentialRef error = %v, want substring %q", err, tt.expectError)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeCredentialRef: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("NormalizeCredentialRef = %#v, want %#v", got, tt.want)
			}
			// The deprecated fields must be gone, not merely unread: the
			// filter's schema has no place to put them.
			if got.Kind != "" || got.Name != "" || got.Namespace != "" {
				t.Errorf("deprecated fields survived normalization: %#v", got)
			}
		})
	}
}
