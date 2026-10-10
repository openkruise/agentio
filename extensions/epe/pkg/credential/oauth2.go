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

package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxOAuth2ResponseBytes = 1 << 20

// OAuth2 operations describe endpoint roles, not Identity RPC names.
const (
	OAuth2OperationDeviceAuthorization = "DeviceAuthorization"
	OAuth2OperationToken               = "Token"
	OAuth2OperationResource            = "Resource"
)

// OAuth2 grant types use their exact protocol values.
const (
	OAuth2GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	OAuth2GrantAuthorizationCode = "authorization_code"
	OAuth2GrantRefreshToken      = "refresh_token"
	OAuth2GrantClientCredentials = "client_credentials"
	OAuth2GrantPassword          = "password"
)

// OAuth2 statuses are the credential service's session and token outcomes.
const (
	OAuth2StatusReady             = "Ready"
	OAuth2StatusAuthorized        = "Authorized"
	OAuth2StatusInProgress        = "InProgress"
	OAuth2StatusFailed            = "Failed"
	OAuth2StatusDenied            = "Denied"
	OAuth2StatusExpired           = "Expired"
	OAuth2StatusRecoveryRequired  = "RecoveryRequired"
	OAuth2StatusNotAuthorized     = "NotAuthorized"
	OAuth2StatusInsufficientScope = "InsufficientScope"
)

// OAuth2 error codes are shared by credential integration and protocol replies.
const (
	OAuth2ErrorInvalidRequest         = "invalid_request"
	OAuth2ErrorUnsupportedGrantType   = "unsupported_grant_type"
	OAuth2ErrorTemporarilyUnavailable = "temporarily_unavailable"
	OAuth2ErrorAuthorizationPending   = "authorization_pending"
	OAuth2ErrorSlowDown               = "slow_down"
	OAuth2ErrorInsufficientScope      = "insufficient_scope"
	OAuth2ErrorInvalidToken           = "invalid_token"
)

const (
	apiActionCreateOAuth2DeviceSession  = "CreateOAuth2DeviceSession"
	apiActionPollOAuth2DeviceSession    = "PollOAuth2DeviceSession"
	apiActionGetOAuth2DeviceAccessToken = "GetOAuth2DeviceAccessToken"
)

// OAuth2Request selects the provider and resource using trusted identity.
// Operation and GrantType describe protocol semantics, not service RPC names.
// Parameters contains selected public OAuth parameters in their standard spelling.
type OAuth2Request struct {
	Operation              string
	GrantType              string
	CredentialProviderName string
	ResourceID             string
	IdempotencyKey         string
	Parameters             map[string]string
}

// OAuth2Response is the service's public authorization-session/token view. It
// deliberately has no application secret, refresh token, or upstream device code.
type OAuth2Response struct {
	HTTPStatus                    int            `json:"-"`
	RequestID                     string         `json:"requestId"`
	Status                        string         `json:"status"`
	AuthorizationRequired         *bool          `json:"authorizationRequired"`
	AuthorizationInProgress       bool           `json:"authorizationInProgress"`
	DeviceSessionID               string         `json:"deviceSessionId"`
	UserCode                      string         `json:"userCode"`
	VerificationURI               string         `json:"verificationUri"`
	VerificationURIComplete       string         `json:"verificationUriComplete"`
	AuthorizationExpiresInSeconds int64          `json:"authorizationExpiresInSeconds"`
	PollIntervalSeconds           int64          `json:"pollIntervalSeconds"`
	RetryAfterSeconds             int64          `json:"retryAfterSeconds"`
	AccessToken                   string         `json:"accessToken"`
	TokenType                     string         `json:"tokenType"`
	AccessTokenExpiresInSeconds   int64          `json:"accessTokenExpiresInSeconds"`
	Scope                         *string        `json:"scope"`
	Outcome                       *OAuth2Outcome `json:"outcome"`
}

// OAuth2Outcome carries the final retry and authorization decision.
type OAuth2Outcome struct {
	Retryable                *bool        `json:"retryable"`
	RequiresNewAuthorization *bool        `json:"requiresNewAuthorization"`
	OAuth2Error              *OAuth2Error `json:"oauth2Error"`
}

// OAuth2Error is the final error view. Private status codes and upstream
// causes are intentionally not decoded, so they cannot replace this view.
type OAuth2Error struct {
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
	HTTPStatus       int    `json:"httpStatus"`
}

// CallOAuth2 performs exactly one request and never caches tokens or
// sessions. The caller retains its Create idempotency key if it elects to retry.
// Non-200 responses are decoded too: their final OAuth status can differ from
// the transport status. No raw body or credential is included in diagnostics.
func (c *Client) CallOAuth2(
	ctx context.Context,
	accessToken string,
	request OAuth2Request,
) (*OAuth2Response, error) {
	if accessToken == "" || strings.ContainsAny(accessToken, "\r\n") {
		return nil, fmt.Errorf("OAuth2 request requires a valid Sandbox identity token")
	}
	if request.ResourceID == "" || len(request.ResourceID) > 253 ||
		request.CredentialProviderName == "" || len(request.CredentialProviderName) > 253 {
		return nil, fmt.Errorf("OAuth2 request requires a resource and credential provider")
	}
	// This integration targets Identity's existing device-session contract.
	// Protocol filters use neutral operations; unsupported service capabilities
	// are explicit OAuth errors, never speculative RPC names or authorizing reads.
	bodyFields := map[string]string{
		"credentialProviderName": request.CredentialProviderName,
		"resourceId":             request.ResourceID,
	}
	var action string
	switch {
	case request.Operation == OAuth2OperationDeviceAuthorization:
		action = apiActionCreateOAuth2DeviceSession
		bodyFields["idempotencyKey"] = request.IdempotencyKey
		bodyFields["scopes"] = request.Parameters["scope"]
	case request.Operation == OAuth2OperationToken && request.GrantType == OAuth2GrantDeviceCode:
		action = apiActionPollOAuth2DeviceSession
		bodyFields["deviceSessionId"] = request.Parameters["device_code"]
	case request.Operation == OAuth2OperationResource || (request.Operation == OAuth2OperationToken && request.GrantType == OAuth2GrantRefreshToken):
		action = apiActionGetOAuth2DeviceAccessToken
		if scope, ok := request.Parameters["scope"]; ok {
			bodyFields["scopes"] = scope
		}
	default:
		no := false
		return &OAuth2Response{HTTPStatus: http.StatusBadRequest,
			Status: OAuth2StatusFailed,
			Outcome: &OAuth2Outcome{
				Retryable:                &no,
				RequiresNewAuthorization: &no,
				OAuth2Error: &OAuth2Error{
					ErrorCode:        OAuth2ErrorUnsupportedGrantType,
					ErrorDescription: "The credential service integration does not support this OAuth operation.",
					HTTPStatus:       http.StatusBadRequest,
				},
			}}, nil
	}
	body, err := json.Marshal(bodyFields)
	if err != nil {
		return nil, fmt.Errorf("encode OAuth request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.providerURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create OAuth2 request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Api-Action-Name", action)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send OAuth2 request: %w", err)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxOAuth2ResponseBytes+1))
	err = errors.Join(err, resp.Body.Close())
	if err != nil {
		return nil, fmt.Errorf("read OAuth2 response: %w", err)
	}
	if len(body) > maxOAuth2ResponseBytes {
		return nil, fmt.Errorf("OAuth2 response exceeds size limit")
	}
	var result OAuth2Response
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid OAuth2 response")
	}
	result.HTTPStatus = resp.StatusCode
	return &result, nil
}
