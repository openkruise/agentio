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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpclient"
)

func TestOAuth2WireFieldsAndNoCache(t *testing.T) {
	scopes := "docx:document offline_access"
	emptyScopes := ""
	for _, tc := range []struct {
		action  string
		request OAuth2Request
		fields  map[string]any
	}{
		{"CreateOAuth2DeviceSession", OAuth2Request{Operation: "DeviceAuthorization", CredentialProviderName: "feishu", ResourceID: "sandbox", IdempotencyKey: "logical-create", Parameters: map[string]string{"scope": scopes}},
			map[string]any{"credentialProviderName": "feishu", "resourceId": "sandbox", "idempotencyKey": "logical-create", "scopes": "docx:document offline_access"}},
		{"CreateOAuth2DeviceSession", OAuth2Request{Operation: "DeviceAuthorization", CredentialProviderName: "feishu", ResourceID: "sandbox", IdempotencyKey: "logical-create", Parameters: map[string]string{"scope": emptyScopes}},
			map[string]any{"credentialProviderName": "feishu", "resourceId": "sandbox", "idempotencyKey": "logical-create", "scopes": ""}},
		{"PollOAuth2DeviceSession", OAuth2Request{Operation: "Token", GrantType: "urn:ietf:params:oauth:grant-type:device_code", CredentialProviderName: "feishu", ResourceID: "sandbox", Parameters: map[string]string{"device_code": "dcs1.service-handle"}},
			map[string]any{"credentialProviderName": "feishu", "resourceId": "sandbox", "deviceSessionId": "dcs1.service-handle"}},
		{"GetOAuth2DeviceAccessToken", OAuth2Request{Operation: "Resource", CredentialProviderName: "feishu", ResourceID: "sandbox"},
			map[string]any{"credentialProviderName": "feishu", "resourceId": "sandbox"}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if r.Method != "POST" || r.URL.Path != "/" || r.Header.Get("X-Api-Action-Name") != tc.action ||
					r.Header.Get("Authorization") != "Bearer trusted-identity" ||
					r.Header.Get("Content-Type") != "application/json" ||
					!reflect.DeepEqual(body, tc.fields) {
					t.Errorf("unsafe identity request: %s %s, %v, %v", r.Method, r.URL.Path, r.Header, body)
				}
				if _, err := io.WriteString(
					w,
					`{"status":"Ready","accessToken":"current-token","tokenType":"Bearer","accessTokenExpiresInSeconds":43,"scope":"","cacheExpiresInSeconds":3600,"refreshToken":"private-rt","deviceCode":"private-idp-device-code"}`,
				); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client := NewClient(server.URL, server.Client(), nil, nil)
			for range 2 {
				result, err := client.CallOAuth2(t.Context(), "trusted-identity", tc.request)
				if err != nil {
					t.Fatal(err)
				}
				if result.HTTPStatus != 200 || result.AccessTokenExpiresInSeconds != 43 || result.Scope == nil ||
					*result.Scope != "" {
					t.Fatalf("decoded response = %+v", result)
				}
				encoded, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), "private-") {
					t.Fatalf("decoded a private response field: %s", encoded)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("OAuth call was cached: calls = %d", calls.Load())
			}
		})
	}
}

func TestOAuth2DecodesRequestFailureFinalView(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		if _, err := io.WriteString(
			w,
			`{"code":"private-top-code","message":"private-top-message","outcome":{"retryable":true,"requiresNewAuthorization":false,"oauth2Error":{"errorCode":"invalid_request","errorDescription":"final description","httpStatus":429},"upstreamOAuth2Error":{"errorCode":"authorization_pending","httpStatus":400}}}`,
		); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	result, err := NewClient(
		server.URL,
		server.Client(),
		nil,
		nil,
	).CallOAuth2(t.Context(), "trusted", OAuth2Request{Operation: "Resource", ResourceID: "sandbox", CredentialProviderName: "feishu"})
	if err != nil {
		t.Fatal(err)
	}
	if result.HTTPStatus != 503 || result.Outcome.OAuth2Error.HTTPStatus != 429 ||
		result.Outcome.OAuth2Error.ErrorCode != "invalid_request" {
		t.Fatalf("final view = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-top") || strings.Contains(string(encoded), "authorization_pending") {
		t.Fatalf("decoded private cause: %s", encoded)
	}
}

func TestOAuth2DoesNotFollowRedirect(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }),
	)
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	_, err := NewClient(
		server.URL,
		httpclient.New(httpclient.DefaultOptions()),
		nil,
		nil,
	).CallOAuth2(t.Context(), "trusted", OAuth2Request{Operation: "Resource", ResourceID: "sandbox", CredentialProviderName: "feishu"})
	if err == nil || destinationCalls.Load() != 0 {
		t.Fatalf("redirect: err=%v, destination calls=%d", err, destinationCalls.Load())
	}
}

func TestOAuth2CancellationAndMalformedBodyAreBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.WriteString(w, `<html>private-token-and-secret</html>`); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, server.Client(), nil, nil)
	req := OAuth2Request{Operation: "Resource", ResourceID: "sandbox", CredentialProviderName: "feishu"}
	_, err := client.CallOAuth2(t.Context(), "trusted", req)
	if err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("malformed body leaked: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = client.CallOAuth2(ctx, "trusted", req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context not honored: %v", err)
	}
}

func TestOAuth2UnsupportedIntegrationDoesNotCallDeviceAPIs(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := NewClient(server.URL, server.Client(), nil, nil)
	for _, request := range []OAuth2Request{
		{Operation: "Token", GrantType: "authorization_code"},
		{Operation: "Token", GrantType: "client_credentials"},
		{Operation: "Token", GrantType: "urn:example:grant"},
	} {
		request.ResourceID, request.CredentialProviderName = "sandbox", "provider"
		result, err := client.CallOAuth2(t.Context(), "trusted", request)
		if err != nil || result.HTTPStatus != 400 || result.Outcome == nil || result.Outcome.OAuth2Error == nil {
			t.Fatalf("result=%+v, err=%v", result, err)
		}
		if *result.Outcome.RequiresNewAuthorization || *result.Outcome.Retryable {
			t.Fatal("unsupported operation requested authorization or retry")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsupported protocol was sent to a device-specific API")
	}
}
