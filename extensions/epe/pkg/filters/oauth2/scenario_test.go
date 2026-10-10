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

package oauth2_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/oauth2"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpclient"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

// This scenario connects the real protocol filter, ext_proc adapter, and HTTP
// credential client without a SecurityProfile API or production registration.
func TestScenarioOAuthCredentialBoundary(t *testing.T) {
	for _, tc := range []struct {
		name        string
		operation   string
		contentType string
		body        string
		action      string
		response    string
		fields      map[string]string
	}{
		{"device", credential.OAuth2OperationDeviceAuthorization, "application/x-www-form-urlencoded", "scope=doc.read&client_secret=private",
			"CreateOAuth2DeviceSession", `{"status":"InProgress","authorizationRequired":true,"deviceSessionId":"public-session","userCode":"USER","verificationUri":"https://issuer.example.test/approve","authorizationExpiresInSeconds":300,"pollIntervalSeconds":5}`,
			map[string]string{"scopes": "doc.read"}},
		{"poll", credential.OAuth2OperationToken, "application/x-www-form-urlencoded", "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=public-session",
			"PollOAuth2DeviceSession", `{"status":"Authorized","accessToken":"real-current-token","tokenType":"Bearer"}`,
			map[string]string{"deviceSessionId": "public-session"}},
		{"refresh", credential.OAuth2OperationToken, "application/json; charset=utf-8", `{"grant_type":"refresh_token","refresh_token":"unused","client_secret":"private","client_id":"untrusted"}`,
			"GetOAuth2DeviceAccessToken", `{"status":"Ready","accessToken":"real-current-token","tokenType":"Bearer","refreshToken":"private-refresh","appSecret":"private-secret"}`,
			map[string]string{}},
		{"unsupported grant", credential.OAuth2OperationToken, "application/x-www-form-urlencoded", "grant_type=client_credentials",
			"", "", nil},
		{"resource", credential.OAuth2OperationResource, "", "", "GetOAuth2DeviceAccessToken",
			`{"status":"Ready","accessToken":"real-current-token","tokenType":"Bearer"}`, map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var fields map[string]string
				if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
					t.Error(err)
				}
				if r.Header.Get("Authorization") != "Bearer trusted-identity" ||
					r.Header.Get("X-Api-Action-Name") != tc.action ||
					fields["resourceId"] != "trusted-resource" ||
					fields["credentialProviderName"] != "provider" {
					t.Errorf("unsafe Identity request: headers=%v fields=%v", r.Header, fields)
				}
				delete(fields, "resourceId")
				delete(fields, "credentialProviderName")
				if tc.operation == credential.OAuth2OperationDeviceAuthorization {
					if fields["idempotencyKey"] == "" {
						t.Error("Create is missing its idempotency key")
					}
					delete(fields, "idempotencyKey")
				}
				if !reflect.DeepEqual(fields, tc.fields) {
					t.Errorf("unexpected OAuth parameters: got %v, want %v", fields, tc.fields)
				}
				if _, err := io.WriteString(w, tc.response); err != nil {
					t.Error(err)
				}
			}))
			defer identity.Close()
			client := credential.NewClient(identity.URL, httpclient.New(httpclient.DefaultOptions()), nil, nil)
			payload, err := json.Marshal(oauth2.Config{CredentialProviderName: "provider", Operation: tc.operation})
			if err != nil {
				t.Fatal(err)
			}
			h := enginetest.NewSingleFilter(
				t,
				enginetest.SingleFilter{Definition: oauth2.Definition(client), Payload: string(payload)},
			)
			request := enginetest.NewRequest(http.MethodPost, "unrelated.example.test", "/arbitrary").Scheme("https").
				Peer("default", "sandbox", nil).SandboxToken("request", "trusted-identity", "trusted-resource").
				Header("authorization", "Bearer unused").Header("content-type", tc.contentType)
			if tc.body != "" {
				request.Body([]byte(tc.body))
			}
			verdict := h.Run(t, request)
			if verdict.Err != nil {
				t.Fatal(verdict.Err)
			}
			if tc.operation == credential.OAuth2OperationResource {
				verdict.RequireHeader(t, "authorization", "Bearer real-current-token")
				if verdict.Kind != enginetest.VerdictMutated || verdict.RequestBodyChanged ||
					verdict.ModeOverride != nil {
					t.Fatalf("resource was locally answered or its body changed: %+v", verdict)
				}
			} else {
				status := http.StatusOK
				if tc.action == "" {
					status = http.StatusBadRequest
				}
				verdict.RequireBlockedBody(t, status, "")
				if verdict.ModeOverride.GetRequestBodyMode() != extProcV3.ProcessingMode_BUFFERED ||
					strings.Contains(
						verdict.ImmediateBody,
						"real-current-token",
					) || strings.Contains(verdict.ImmediateBody, "private-") {
					t.Fatalf("incorrect body negotiation or credential leak: %+v", verdict)
				}
				var body map[string]any
				if err := json.Unmarshal([]byte(verdict.ImmediateBody), &body); err != nil {
					t.Fatal(err)
				}
				switch {
				case tc.action == "":
					if body["error"] != "unsupported_grant_type" {
						t.Fatalf("unsupported grant reply: %v", body)
					}
				case tc.operation == credential.OAuth2OperationToken:
					if body["access_token"] != "unused" || body["refresh_token"] != "unused" {
						t.Fatalf("workload tokens: %v", body)
					}
				default:
					if body["device_code"] != "public-session" {
						t.Fatalf("public device session: %v", body)
					}
				}
			}
			wantCalls := 1
			if tc.action == "" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("Identity calls=%d, want %d", calls, wantCalls)
			}
		})
	}
}
