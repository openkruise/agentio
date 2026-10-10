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

// Package oauth2 brokers standard OAuth operations selected by policy.
package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// FilterName identifies the OAuth protocol filter in the engine.
const FilterName = "oauth2"

// Source obtains authorization sessions and credentials from a trusted service.
type Source interface {
	CallOAuth2(context.Context, string, credential.OAuth2Request) (*credential.OAuth2Response, error)
}

// Config is the filter's policy-neutral payload. Policy adapters select the
// endpoint role and provider; the filter never infers them from a host or path.
type Config struct {
	CredentialProviderName string          `json:"credentialProviderName"`
	Operation              string          `json:"operation"`
	AllowedGrantTypes      []string        `json:"allowedGrantTypes,omitempty"`
	AllowAuthorizedSession *bool           `json:"allowAuthorizedSession,omitempty"`
	CustomResponse         *CustomResponse `json:"customResponse,omitempty"`
}

// Filter brokers OAuth responses and injects credentials into resource requests.
type Filter struct {
	filter.PassThrough
	cfg    Config
	source Source
}

// OnRequestHeaders injects a resource token or requests the OAuth endpoint body.
func (f *Filter) OnRequestHeaders(ctx context.Context, st *filter.Stream) (filter.Action, error) {
	if st.Request.Scheme != "https" || st.Request.Method == http.MethodConnect {
		return oauthErrorReply(
			403,
			credential.OAuth2ErrorInvalidRequest,
			"OAuth requires a verified HTTPS target.",
			f.cfg.CustomResponse,
			false,
		)
	}
	switch f.cfg.Operation {
	case credential.OAuth2OperationResource:
		result, err := f.call(ctx, st, "", nil)
		if err != nil {
			log.FromContext(ctx).Error(err, "OAuth credential request failed",
				"operation", f.cfg.Operation, "credentialProvider", f.cfg.CredentialProviderName)
			return resourceUnavailable(f.cfg.CustomResponse)
		}
		if usableToken(result, credential.OAuth2StatusReady) {
			return filter.Continue(filter.SetHeader("authorization", "Bearer "+result.AccessToken)), nil
		}
		return resourceFailure(result, f.cfg.CustomResponse)
	}
	if st.Request.Method != http.MethodPost {
		return oauthErrorReply(
			400,
			credential.OAuth2ErrorInvalidRequest,
			"The OAuth endpoint requires POST.",
			f.cfg.CustomResponse,
			false,
		)
	}
	return filter.NeedBody(), nil
}

// OnRequestBody decodes the standard parameters and returns a local OAuth reply.
func (f *Filter) OnRequestBody(ctx context.Context, st *filter.Stream, body filter.Body) (filter.Action, error) {
	if f.cfg.Operation == credential.OAuth2OperationResource {
		return filter.Continue(), nil
	}
	mediaType, _, err := mime.ParseMediaType(st.Request.Headers["content-type"])
	if err != nil || !body.Complete {
		return oauthErrorReply(
			400,
			credential.OAuth2ErrorInvalidRequest,
			"A complete OAuth request is required.",
			f.cfg.CustomResponse,
			false,
		)
	}
	var params url.Values
	if mediaType == "application/x-www-form-urlencoded" {
		params, err = url.ParseQuery(string(body.Bytes))
	} else if mediaType == "application/json" {
		params, err = jsonParameters(body.Bytes)
	} else {
		err = fmt.Errorf("unsupported Content-Type")
	}
	if err != nil {
		return oauthErrorReply(
			400,
			credential.OAuth2ErrorInvalidRequest,
			"Malformed OAuth request or unsupported Content-Type.",
			f.cfg.CustomResponse,
			false,
		)
	}
	return f.process(ctx, st, params)
}

func jsonParameters(body []byte) (url.Values, error) {
	// Decode a token stream so duplicate JSON keys cannot be silently discarded.
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("OAuth JSON must be an object")
	}
	values := make(url.Values)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("decode OAuth parameter: %w", err)
		}
		name := key.(string)
		if _, exists := values[name]; exists {
			return nil, fmt.Errorf("duplicate OAuth parameter")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("OAuth parameters must be strings: %w", err)
		}
		values[name] = []string{value}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("decode OAuth object: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing OAuth JSON")
	}
	return values, nil
}

func (f *Filter) process(ctx context.Context, st *filter.Stream, params url.Values) (filter.Action, error) {
	for _, values := range params {
		if len(values) != 1 {
			return oauthErrorReply(
				400,
				credential.OAuth2ErrorInvalidRequest,
				"OAuth parameters must not be repeated.",
				f.cfg.CustomResponse,
				false,
			)
		}
	}
	response := f.cfg.CustomResponse
	grantType := ""
	switch f.cfg.Operation {
	case credential.OAuth2OperationToken:
		grantType = params.Get("grant_type")
		if grantType == "" {
			return oauthErrorReply(
				400,
				credential.OAuth2ErrorInvalidRequest,
				"The grant_type parameter is required.",
				response,
				false,
			)
		}
		allowed := len(f.cfg.AllowedGrantTypes) == 0 || slices.Contains(f.cfg.AllowedGrantTypes, grantType)
		if !allowed || grantType == credential.OAuth2GrantPassword {
			return oauthErrorReply(
				400,
				credential.OAuth2ErrorUnsupportedGrantType,
				"The grant is not permitted.",
				response,
				false,
			)
		}
		var required string
		switch grantType {
		case credential.OAuth2GrantDeviceCode:
			required = "device_code"
		case credential.OAuth2GrantAuthorizationCode:
			required = "code"
		case credential.OAuth2GrantRefreshToken:
			required = "refresh_token"
		}
		if required != "" && params.Get(required) == "" {
			return oauthErrorReply(
				400,
				credential.OAuth2ErrorInvalidRequest,
				"A required OAuth parameter is missing.",
				response,
				false,
			)
		}
	}
	result, err := f.call(ctx, st, grantType, params)
	if err != nil {
		log.FromContext(ctx).Error(err, "OAuth credential request failed",
			"operation", f.cfg.Operation, "credentialProvider", f.cfg.CredentialProviderName)
		return oauthErrorReply(
			502,
			credential.OAuth2ErrorTemporarilyUnavailable,
			"Credential service is unavailable.",
			response,
			false,
		)
	}
	return f.protocolReply(grantType, result, response)
}

func (f *Filter) call(
	ctx context.Context,
	st *filter.Stream,
	grantType string,
	params url.Values,
) (*credential.OAuth2Response, error) {
	if f.source == nil || st.Peer.Token == nil || st.Peer.Token.AccessToken == "" ||
		st.Peer.Token.SandboxClientID == "" {
		return nil, fmt.Errorf("OAuth identity or credential connection is unavailable")
	}
	request := credential.OAuth2Request{
		Operation:              f.cfg.Operation,
		GrantType:              grantType,
		CredentialProviderName: f.cfg.CredentialProviderName,
		ResourceID:             st.Peer.Token.SandboxClientID,
		Parameters:             make(map[string]string),
	}
	var names []string
	switch request.Operation {
	case credential.OAuth2OperationDeviceAuthorization:
		names = []string{"scope"}
		request.Parameters["scope"] = params.Get("scope")
		request.IdempotencyKey = uuid.NewString()
	case credential.OAuth2OperationToken:
		switch grantType {
		case credential.OAuth2GrantDeviceCode:
			names = []string{"device_code"}
		case credential.OAuth2GrantAuthorizationCode:
			names = []string{"code", "redirect_uri", "code_verifier"}
		case credential.OAuth2GrantRefreshToken, credential.OAuth2GrantClientCredentials:
			names = []string{"scope"}
		}
	}
	for _, name := range names {
		if values, ok := params[name]; ok {
			request.Parameters[name] = values[0]
		}
	}
	return f.source.CallOAuth2(ctx, st.Peer.Token.AccessToken, request)
}
