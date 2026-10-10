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

package oauth2

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// CustomResponse adds application-specific fields to standard OAuth replies.
// Extensions must be JSON objects and cannot replace protocol fields.
type CustomResponse struct {
	Success               json.RawMessage `json:"success,omitempty"`
	Error                 json.RawMessage `json:"error,omitempty"`
	AuthorizationRequired json.RawMessage `json:"authorizationRequired,omitempty"`
}

func validateResponse(response *CustomResponse) error {
	if response == nil {
		return nil
	}
	for _, extension := range []json.RawMessage{response.Success, response.Error, response.AuthorizationRequired} {
		if extension == nil {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(extension, &fields); err != nil || fields == nil {
			return fmt.Errorf("OAuth response extensions must be JSON objects")
		}
		for name := range fields {
			switch name {
			case "access_token", "refresh_token", "token_type", "expires_in", "scope",
				"error", "error_description", "error_uri", "device_code", "user_code",
				"verification_uri", "verification_uri_complete", "interval":
				return fmt.Errorf("OAuth response cannot override standard field %q", name)
			}
		}
	}
	return nil
}

func addFields(body map[string]any, extension json.RawMessage) error {
	if extension == nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(extension, &fields); err != nil {
		return fmt.Errorf("decode OAuth response extension: %w", err)
	}
	for name, value := range fields {
		body[name] = value
	}
	return nil
}

func (f *Filter) protocolReply(
	grantType string,
	r *credential.OAuth2Response,
	response *CustomResponse,
) (filter.Action, error) {
	if r == nil {
		return oauthErrorReply(
			502,
			credential.OAuth2ErrorTemporarilyUnavailable,
			"Incomplete credential service response.",
			response,
			false,
		)
	}
	switch f.cfg.Operation {
	case credential.OAuth2OperationDeviceAuthorization:
		if r.HTTPStatus == 200 && !hasFinalError(r) {
			return f.deviceAuthorizationReply(r, response)
		}
	case credential.OAuth2OperationToken:
		expected := credential.OAuth2StatusReady
		if grantType == credential.OAuth2GrantDeviceCode {
			expected = credential.OAuth2StatusAuthorized
		}
		if usableToken(r, expected) {
			return tokenReply(grantType, r, response)
		}
	}
	return grantFailureReply(grantType, r, response)
}

func (f *Filter) deviceAuthorizationReply(
	r *credential.OAuth2Response,
	response *CustomResponse,
) (filter.Action, error) {
	inProgress := r.Status == credential.OAuth2StatusInProgress && r.AuthorizationRequired != nil &&
		*r.AuthorizationRequired && r.VerificationURI != ""
	alreadyAuthorized := (f.cfg.AllowAuthorizedSession == nil || *f.cfg.AllowAuthorizedSession) &&
		r.Status == credential.OAuth2StatusAuthorized &&
		r.AuthorizationRequired != nil &&
		!*r.AuthorizationRequired
	if r.DeviceSessionID == "" || r.UserCode == "" || r.AuthorizationExpiresInSeconds <= 0 ||
		r.PollIntervalSeconds < 0 || r.AccessToken != "" || !(inProgress || alreadyAuthorized) {
		return oauthErrorReply(
			502,
			credential.OAuth2ErrorTemporarilyUnavailable,
			"Incomplete device authorization response.",
			response,
			false,
		)
	}
	body := map[string]any{
		"device_code":      r.DeviceSessionID,
		"user_code":        r.UserCode,
		"verification_uri": r.VerificationURI,
		"expires_in":       r.AuthorizationExpiresInSeconds,
	}
	if r.PollIntervalSeconds > 0 {
		body["interval"] = r.PollIntervalSeconds
	}
	if r.VerificationURIComplete != "" {
		body["verification_uri_complete"] = r.VerificationURIComplete
	}
	return jsonReply(200, body)
}

func tokenReply(grantType string, r *credential.OAuth2Response, response *CustomResponse) (filter.Action, error) {
	body := map[string]any{"access_token": "unused", "token_type": "Bearer"}
	if grantType != credential.OAuth2GrantClientCredentials {
		body["refresh_token"] = "unused"
	}
	if r.AccessTokenExpiresInSeconds > 0 {
		body["expires_in"] = r.AccessTokenExpiresInSeconds
	}
	if r.Scope != nil {
		body["scope"] = *r.Scope
	}
	if response != nil {
		if err := addFields(body, response.Success); err != nil {
			return filter.Action{}, err
		}
	}
	return jsonReply(200, body)
}

func grantFailureReply(
	grantType string,
	r *credential.OAuth2Response,
	response *CustomResponse,
) (filter.Action, error) {
	if !validFailure(r) {
		return oauthErrorReply(
			502,
			credential.OAuth2ErrorTemporarilyUnavailable,
			"Incomplete credential service response.",
			response,
			false,
		)
	}
	outcome := r.Outcome
	e := outcome.OAuth2Error
	waiting := e.ErrorCode == credential.OAuth2ErrorAuthorizationPending ||
		e.ErrorCode == credential.OAuth2ErrorSlowDown
	if waiting &&
		(grantType != credential.OAuth2GrantDeviceCode || r.Status != credential.OAuth2StatusInProgress || !*outcome.Retryable || *outcome.RequiresNewAuthorization) {
		return oauthErrorReply(
			502,
			credential.OAuth2ErrorTemporarilyUnavailable,
			"Conflicting device authorization outcome.",
			response,
			false,
		)
	}
	action, err := oauthErrorReply(e.HTTPStatus, e.ErrorCode, e.ErrorDescription, response,
		!*outcome.Retryable && *outcome.RequiresNewAuthorization)
	if err == nil && grantType == credential.OAuth2GrantDeviceCode && r.RetryAfterSeconds > 0 {
		reply, _ := action.Reply()
		reply.HeaderOps = append(reply.HeaderOps, filter.HeaderOp{
			Kind:  filter.HeaderSet,
			Name:  "retry-after",
			Value: strconv.FormatInt(r.RetryAfterSeconds, 10),
		})
		action = filter.Stop(reply)
	}
	return action, err
}

func hasFinalError(r *credential.OAuth2Response) bool {
	return r.Outcome != nil && r.Outcome.OAuth2Error != nil
}

func usableToken(r *credential.OAuth2Response, status string) bool {
	return r != nil && r.HTTPStatus == 200 && r.Status == status && !hasFinalError(r) &&
		r.AccessToken != "" && strings.IndexFunc(r.AccessToken, func(c rune) bool { return c < 0x21 || c == 0x7f }) < 0 &&
		strings.EqualFold(r.TokenType, "Bearer") && r.AccessTokenExpiresInSeconds >= 0
}

func validFailure(r *credential.OAuth2Response) bool {
	if !hasFinalError(r) || r.Outcome.Retryable == nil || r.Outcome.RequiresNewAuthorization == nil {
		return false
	}
	e := r.Outcome.OAuth2Error
	if e.ErrorCode == "" || e.HTTPStatus < 400 || e.HTTPStatus > 599 {
		return false
	}
	switch r.Status {
	case credential.OAuth2StatusInProgress, credential.OAuth2StatusFailed, credential.OAuth2StatusDenied,
		credential.OAuth2StatusExpired, credential.OAuth2StatusRecoveryRequired,
		credential.OAuth2StatusNotAuthorized, credential.OAuth2StatusInsufficientScope:
		return true
	case "":
		return r.HTTPStatus >= 400 && r.HTTPStatus <= 599
	default:
		return false
	}
}

func resourceFailure(r *credential.OAuth2Response, response *CustomResponse) (filter.Action, error) {
	if r == nil || !validFailure(r) {
		return resourceUnavailable(response)
	}
	if r.Status == credential.OAuth2StatusInsufficientScope {
		return resourceError(
			403,
			credential.OAuth2ErrorInsufficientScope,
			"The credential has insufficient scope.",
			response,
			false,
		)
	}
	if r.Status == credential.OAuth2StatusNotAuthorized || *r.Outcome.RequiresNewAuthorization {
		return resourceError(
			401,
			credential.OAuth2ErrorInvalidToken,
			"No authorized credential is available.",
			response,
			true,
		)
	}
	return resourceUnavailable(response)
}

func resourceUnavailable(response *CustomResponse) (filter.Action, error) {
	return oauthErrorReply(
		503,
		credential.OAuth2ErrorTemporarilyUnavailable,
		"Credential service is unavailable.",
		response,
		false,
	)
}

func resourceError(
	status int,
	code, description string,
	response *CustomResponse,
	requiresAuthorization bool,
) (filter.Action, error) {
	action, err := oauthErrorReply(status, code, description, response, requiresAuthorization)
	if err != nil {
		return action, err
	}
	reply, _ := action.Reply()
	reply.HeaderOps = append(reply.HeaderOps, filter.HeaderOp{Kind: filter.HeaderSet,
		Name:  "www-authenticate",
		Value: "Bearer error=" + strconv.Quote(code)})
	return filter.Stop(reply), nil
}

func oauthErrorReply(
	status int,
	errorCode, description string,
	response *CustomResponse,
	requiresAuthorization bool,
) (filter.Action, error) {
	body := map[string]any{"error": errorCode, "error_description": description}
	if response != nil {
		if err := addFields(body, response.Error); err != nil {
			return filter.Action{}, err
		}
		if requiresAuthorization {
			if err := addFields(body, response.AuthorizationRequired); err != nil {
				return filter.Action{}, err
			}
		}
	}
	return jsonReply(status, body)
}

func responseHeaders(contentType string) []filter.HeaderOp {
	return []filter.HeaderOp{
		{Kind: filter.HeaderSet, Name: "content-type", Value: contentType},
		{Kind: filter.HeaderSet, Name: "cache-control", Value: "no-store"},
		{Kind: filter.HeaderSet, Name: "pragma", Value: "no-cache"},
	}
}

func jsonReply(status int, value any) (filter.Action, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return filter.Action{}, err
	}
	return filter.Stop(filter.Reply{Status: status, HeaderOps: responseHeaders("application/json"), Body: body}), nil
}
