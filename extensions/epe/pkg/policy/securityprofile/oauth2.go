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

package securityprofile

import (
	"encoding/json"
	"fmt"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
)

// oauth2Payload projects the public operation union to the filter's neutral
// payload. Cross-field policy constraints are checked here instead of CRD CEL.
func oauth2Payload(a *v1alpha1.TokenTransformationAction) (json.RawMessage, error) {
	if a.OAuth2 == nil {
		return nil, fmt.Errorf("OAuth2 configuration is required")
	}
	if a.ApiKey != nil {
		return nil, fmt.Errorf("OAuth2 cannot be combined with apiKey configuration")
	}
	if a.FailStrategy != "" && a.FailStrategy != v1alpha1.FailStrategyBlock {
		return nil, fmt.Errorf("OAuth2 requires the Block failure strategy")
	}
	ref, err := NormalizeCredentialRef(a.CredentialRef)
	if err != nil {
		return nil, err
	}
	if ref.CredentialProvider == nil || len(ref.CredentialProvider.Parameters) != 0 {
		return nil, fmt.Errorf("OAuth2 requires a parameter-free CredentialProvider reference")
	}
	var operation string
	var grants []string
	count := 0
	if a.OAuth2.Operation.DeviceAuthorization != nil {
		operation = credential.OAuth2OperationDeviceAuthorization
		count++
	}
	if token := a.OAuth2.Operation.Token; token != nil {
		operation = credential.OAuth2OperationToken
		grants = token.AllowedGrantTypes
		count++
	}
	if a.OAuth2.Operation.Resource != nil {
		operation = credential.OAuth2OperationResource
		count++
	}
	if count != 1 {
		return nil, fmt.Errorf("exactly one OAuth2 operation is required")
	}
	// Marshal RawExtension through its public JSON contract so both decoded Raw
	// values and typed Object values preserve application response fields.
	return json.Marshal(struct {
		CredentialProviderName string                         `json:"credentialProviderName"`
		Operation              string                         `json:"operation"`
		AllowedGrantTypes      []string                       `json:"allowedGrantTypes,omitempty"`
		CustomResponse         *v1alpha1.OAuth2CustomResponse `json:"customResponse,omitempty"`
	}{ref.CredentialProvider.Name, operation, grants, a.OAuth2.CustomResponse})
}
