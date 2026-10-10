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
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
)

type call struct {
	bearer  string
	request credential.OAuth2Request
}
type fakeSource struct {
	result *credential.OAuth2Response
	err    error
	calls  []call
}

func (s *fakeSource) CallOAuth2(
	_ context.Context,
	bearer string,
	request credential.OAuth2Request,
) (*credential.OAuth2Response, error) {
	s.calls = append(s.calls, call{bearer, request})
	return s.result, s.err
}
func requestStream(host, path, contentType string) *filter.Stream {
	return &filter.Stream{
		Peer: filter.Peer{
			Token: &filter.SandboxToken{AccessToken: "trusted-identity", SandboxClientID: "trusted-resource"},
		},
		Request: httpreq.HTTPRequest{Host: host,
			Path:    path,
			Method:  "POST",
			Scheme:  "https",
			Port:    9443,
			Headers: map[string]string{"content-type": contentType, "authorization": "Bearer tool-token"}},
	}
}
func replyJSON(t *testing.T, action filter.Action, status int) map[string]any {
	t.Helper()
	reply, ok := action.Reply()
	if !ok || reply.Status != status {
		t.Fatalf("reply=%+v, present=%v; want %d", reply, ok, status)
	}
	var body map[string]any
	if err := json.Unmarshal(reply.Body, &body); err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{}
	for _, op := range reply.HeaderOps {
		headers[op.Name] = op.Value
	}
	if headers["cache-control"] != "no-store" || headers["pragma"] != "no-cache" {
		t.Fatalf("cacheable response: %v", headers)
	}
	if strings.Contains(string(reply.Body), "real-current-token") {
		t.Fatal("real credential reached workload")
	}
	return body
}
func successfulToken(status string) *credential.OAuth2Response {
	return &credential.OAuth2Response{HTTPStatus: 200,
		Status:                      status,
		AccessToken:                 "real-current-token",
		TokenType:                   "Bearer",
		AccessTokenExpiresInSeconds: 47,
		Scope:                       new("granted-scope")}
}
func failure(status, code string, retryable, reauthorize bool) *credential.OAuth2Response {
	return &credential.OAuth2Response{HTTPStatus: 200,
		Status: status,
		Outcome: &credential.OAuth2Outcome{
			Retryable:                new(retryable),
			RequiresNewAuthorization: new(reauthorize),
			OAuth2Error: &credential.OAuth2Error{
				ErrorCode:        code,
				ErrorDescription: "final description",
				HTTPStatus:       400,
			},
		}}
}
func extension(text string) json.RawMessage { return json.RawMessage(text) }
func tokenConfig(grant string) Config {
	return Config{
		CredentialProviderName: "configured-provider",
		Operation:              credential.OAuth2OperationToken,
		AllowedGrantTypes:      []string{grant},
	}
}
func runBody(t *testing.T, f *Filter, st *filter.Stream, body string) filter.Action {
	t.Helper()
	action, err := f.OnRequestHeaders(t.Context(), st)
	if err != nil || action.Kind() != filter.KindNeedBody {
		t.Fatalf("headers: %+v, %v", action, err)
	}
	action, err = f.OnRequestBody(t.Context(), st, filter.Body{Bytes: []byte(body), Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func TestStandardGrantsOnUnrelatedEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name  string
		grant string
		body  string
		want  map[string]string
	}{
		{"device", credential.OAuth2GrantDeviceCode, "grant_type=" + url.QueryEscape(credential.OAuth2GrantDeviceCode) + "&device_code=session&client_secret=private&client_id=untrusted",
			map[string]string{"device_code": "session"}},
		{"refresh", "refresh_token", "grant_type=refresh_token&refresh_token=unused&client_secret=private",
			map[string]string{}},
		{"authorization code with PKCE", "authorization_code", "grant_type=authorization_code&code=broker-handle&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&code_verifier=verifier&client_id=untrusted",
			map[string]string{"code": "broker-handle", "redirect_uri": "http://127.0.0.1:9999/cb", "code_verifier": "verifier"}},
		{"client credentials", "client_credentials", "grant_type=client_credentials&scope=service.read&client_secret=private",
			map[string]string{"scope": "service.read"}},
	} {
		for _, host := range []string{"issuer.example.test", "login.other.test"} {
			t.Run(tc.name+"/"+host, func(t *testing.T) {
				status := "Ready"
				if tc.grant == credential.OAuth2GrantDeviceCode {
					status = "Authorized"
				}
				source := &fakeSource{result: successfulToken(status)}
				f := &Filter{cfg: tokenConfig(tc.grant), source: source}
				st := requestStream(host, "/arbitrary/exchange", "application/x-www-form-urlencoded")
				got := replyJSON(t, runBody(t, f, st, tc.body), 200)
				if got["access_token"] != "unused" || got["token_type"] != "Bearer" {
					t.Fatalf("token reply=%v", got)
				}
				if tc.grant == "client_credentials" {
					if _, ok := got["refresh_token"]; ok {
						t.Fatal("client credentials issued a refresh token")
					}
				} else if got["refresh_token"] != "unused" {
					t.Fatalf("refresh=%v", got)
				}
				if _, ok := got["code"]; ok {
					t.Fatal("application code appeared in standard response")
				}
				if len(source.calls) != 1 {
					t.Fatalf("calls=%d", len(source.calls))
				}
				call := source.calls[0]
				if call.request.Operation != "Token" || call.request.GrantType != tc.grant ||
					call.bearer != "trusted-identity" ||
					call.request.ResourceID != "trusted-resource" ||
					call.request.CredentialProviderName != "configured-provider" ||
					!reflect.DeepEqual(call.request.Parameters, tc.want) {
					t.Fatalf("unsafe request=%+v", call)
				}
			})
		}
	}
}

func TestDeviceAuthorizationAndExplicitFastClaim(t *testing.T) {
	response := &credential.OAuth2Response{HTTPStatus: 200,
		Status:                        "InProgress",
		AuthorizationRequired:         new(true),
		DeviceSessionID:               "session",
		UserCode:                      "USER",
		VerificationURI:               "https://login.example.test/verify",
		AuthorizationExpiresInSeconds: 300,
		PollIntervalSeconds:           5}
	cfg := Config{
		CredentialProviderName: "configured-provider",
		Operation:              credential.OAuth2OperationDeviceAuthorization,
		AllowAuthorizedSession: new(false),
	}
	source := &fakeSource{result: response}
	f := &Filter{cfg: cfg, source: source}
	got := replyJSON(
		t,
		runBody(
			t,
			f,
			requestStream("issuer.example.test", "/device", "application/x-www-form-urlencoded"),
			"client_secret=private",
		),
		200,
	)
	if got["device_code"] != "session" || source.calls[0].request.Parameters["scope"] != "" ||
		source.calls[0].request.IdempotencyKey == "" {
		t.Fatalf("device reply=%v, calls=%+v", got, source.calls)
	}
	response.Status = "Authorized"
	response.AuthorizationRequired = new(false)
	response.VerificationURI = ""
	replyJSON(
		t,
		runBody(t, f, requestStream("issuer.example.test", "/device", "application/x-www-form-urlencoded"), ""),
		502,
	)
	f.cfg.AllowAuthorizedSession = nil
	replyJSON(
		t,
		runBody(t, f, requestStream("issuer.example.test", "/device", "application/x-www-form-urlencoded"), ""),
		200,
	)
}

func TestJSONCompatibilityIsPolicyOnly(t *testing.T) {
	cfg := tokenConfig("refresh_token")
	cfg.CustomResponse = &CustomResponse{
		Success:               extension("{\"code\":0}"),
		Error:                 extension("{\"code\":20050}"),
		AuthorizationRequired: extension("{\"code\":20026}")}
	source := &fakeSource{result: successfulToken("Ready")}
	f := &Filter{cfg: cfg, source: source}
	st := requestStream("arbitrary.test", "/token", "application/json; charset=utf-8")
	got := replyJSON(
		t,
		runBody(
			t,
			f,
			st,
			"{\"grant_type\":\"refresh_token\",\"refresh_token\":\"unused\",\"client_secret\":\"private\"}",
		),
		200,
	)
	if got["code"] != float64(0) {
		t.Fatalf("extension=%v", got)
	}
	source.result = failure("NotAuthorized", "invalid_grant", false, true)
	got = replyJSON(t, runBody(t, f, st, "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"unused\"}"), 400)
	if got["code"] != float64(20026) {
		t.Fatalf("reauthorize=%v", got)
	}
	source.err = errors.New("private identity token and secret")
	reply := runBody(t, f, st, "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"unused\"}")
	got = replyJSON(t, reply, 502)
	if got["code"] != float64(20050) || strings.Contains(got["error_description"].(string), "private") {
		t.Fatalf("unsafe error=%v", got)
	}
}

func TestCredentialFailuresAreLoggedWithoutExposingRequestCredentials(t *testing.T) {
	for _, tc := range []struct {
		operation string
		status    int
	}{
		{credential.OAuth2OperationToken, 502},
		{credential.OAuth2OperationResource, 503},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			var logs strings.Builder
			logger := funcr.New(func(_, line string) { logs.WriteString(line) }, funcr.Options{})
			ctx := log.IntoContext(t.Context(), logger)
			cfg := tokenConfig(credential.OAuth2GrantRefreshToken)
			cfg.Operation = tc.operation
			f := &Filter{cfg: cfg, source: &fakeSource{err: errors.New("credential service timed out")}}
			st := requestStream("issuer.example.test", "/token", "application/x-www-form-urlencoded")
			action, err := f.OnRequestHeaders(ctx, st)
			if err == nil && action.Kind() == filter.KindNeedBody {
				action, err = f.OnRequestBody(ctx, st, filter.Body{
					Bytes:    []byte("grant_type=refresh_token&refresh_token=unused&client_secret=private"),
					Complete: true,
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			body := replyJSON(t, action, tc.status)
			if body["error"] != "temporarily_unavailable" ||
				strings.Contains(body["error_description"].(string), "timed out") {
				t.Fatalf("internal failure reached the workload: %v", body)
			}
			for _, value := range []string{"credential service timed out", tc.operation, cfg.CredentialProviderName} {
				if !strings.Contains(logs.String(), value) {
					t.Fatalf("missing diagnostic %q in %s", value, logs.String())
				}
			}
			for _, private := range []string{"trusted-identity", "tool-token", "client_secret", "private"} {
				if strings.Contains(logs.String(), private) {
					t.Fatalf("request credential reached the log: %s", logs.String())
				}
			}
		})
	}
}

func TestMalformedOrUnsupportedRequestsNeverCallIdentity(t *testing.T) {
	for _, tc := range []struct {
		body        string
		contentType string
	}{
		{"grant_type=authorization_code", "application/x-www-form-urlencoded"},
		{"grant_type=client_credentials", "application/x-www-form-urlencoded"},
		{"grant_type=refresh_token", "application/x-www-form-urlencoded"},
		{"grant_type=authorization_code&grant_type=authorization_code&code=handle", "application/x-www-form-urlencoded"},
		{"{\"grant_type\":\"authorization_code\",\"grant_type\":\"authorization_code\",\"code\":\"handle\"}", "application/json"},
		{"{\"grant_type\":\"authorization_code\",\"code\":\"handle\"}]", "application/json"},
		{"{\"grant_type\":\"authorization_code\",\"code\":123}", "application/json"},
		{"grant_type=authorization_code&code=handle", "application/json"},
		{"{\"grant_type\":\"authorization_code\",\"code\":\"handle\"}", "application/x-www-form-urlencoded"},
		{"grant_type=authorization_code&code=handle", ""},
		{"grant_type=authorization_code&code=handle", "text/plain"},
		{"grant_type=authorization_code&code=handle", "application/json; charset"},
	} {
		t.Run(tc.body+"/"+tc.contentType, func(t *testing.T) {
			s := &fakeSource{result: successfulToken("Ready")}
			f := &Filter{cfg: tokenConfig("authorization_code"), source: s}
			replyJSON(t, runBody(t, f, requestStream("any.test", "/exchange", tc.contentType), tc.body), 400)
			if len(s.calls) != 0 {
				t.Fatal("invalid request reached identity")
			}
		})
	}
}

func TestResourceInjectionUsesIdentityOnEveryRequest(t *testing.T) {
	for _, incoming := range []string{"Bearer unused", "Bearer arbitrary", ""} {
		s := &fakeSource{result: successfulToken("Ready")}
		f := &Filter{
			cfg:    Config{CredentialProviderName: "provider", Operation: credential.OAuth2OperationResource},
			source: s,
		}
		st := requestStream("api.unrelated.test", "/items", "")
		st.Request.Headers["authorization"] = incoming
		for range 2 {
			action, err := f.OnRequestHeaders(t.Context(), st)
			if err != nil || action.Kind() != filter.KindContinue {
				t.Fatalf("injection=%+v, %v", action, err)
			}
			if !action.Equal(filter.Continue(filter.SetHeader("authorization", "Bearer real-current-token"))) {
				t.Fatalf("header=%v", action.Mutations())
			}
		}
		if len(s.calls) != 2 || st.Request.Headers["authorization"] != incoming {
			t.Fatal("cached token or mutated read-only request")
		}
	}
}

func TestFinalOutcomesAndStandardOptionalTokenFields(t *testing.T) {
	f := &Filter{cfg: tokenConfig(credential.OAuth2GrantDeviceCode)}
	for _, tc := range []struct {
		status     string
		code       string
		retry      bool
		reauth     bool
		httpStatus int
	}{
		{"InProgress", "authorization_pending", true, false, 400},
		{"InProgress", "slow_down", true, false, 400},
		{"Denied", "access_denied", false, true, 400},
		{"RecoveryRequired", "authorization_pending", false, true, 502},
	} {
		action, err := f.protocolReply(
			credential.OAuth2GrantDeviceCode,
			failure(tc.status, tc.code, tc.retry, tc.reauth),
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		replyJSON(t, action, tc.httpStatus)
	}
	r := successfulToken("Ready")
	r.Scope = nil
	r.AccessTokenExpiresInSeconds = 0
	action, err := f.protocolReply("authorization_code", r, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := replyJSON(t, action, 200)
	if _, ok := got["expires_in"]; ok {
		t.Fatal("invented expiry")
	}
	if _, ok := got["scope"]; ok {
		t.Fatal("invented scope")
	}
	for _, tc := range []struct {
		state  string
		status int
	}{
		{"NotAuthorized", 401}, {"InsufficientScope", 403}, {"Failed", 503},
	} {
		action, err := resourceFailure(failure(tc.state, "invalid_grant", false, tc.state != "Failed"), nil)
		if err != nil {
			t.Fatal(err)
		}
		replyJSON(t, action, tc.status)
	}
}

func TestOptionalGrantRestrictionAndDefaultAuthorizedSession(t *testing.T) {
	for _, grants := range [][]string{nil, {}, {"refresh_token"}, {"authorization_code"}} {
		source := &fakeSource{result: successfulToken("Ready")}
		cfg := tokenConfig("refresh_token")
		cfg.AllowedGrantTypes = grants
		f := &Filter{cfg: cfg, source: source}
		status := 200
		if len(grants) > 0 && grants[0] != "refresh_token" {
			status = 400
		}
		got := replyJSON(
			t,
			runBody(
				t,
				f,
				requestStream("issuer.test", "/token", "application/x-www-form-urlencoded"),
				"grant_type=refresh_token&refresh_token=unused",
			),
			status,
		)
		if status == 400 && (len(source.calls) != 0 || got["error"] != "unsupported_grant_type") {
			t.Fatal("disallowed grant reached Identity")
		}
	}
	for _, grant := range []string{"", "password"} {
		source := &fakeSource{result: successfulToken("Ready")}
		f := &Filter{cfg: Config{Operation: credential.OAuth2OperationToken}, source: source}
		replyJSON(
			t,
			runBody(
				t,
				f,
				requestStream("issuer.test", "/token", "application/x-www-form-urlencoded"),
				"grant_type="+grant,
			),
			400,
		)
		if len(source.calls) != 0 {
			t.Fatal("invalid grant reached Identity")
		}
	}
	for _, allow := range []*bool{nil, new(true), new(false)} {
		cfg := Config{
			CredentialProviderName: "provider",
			Operation:              credential.OAuth2OperationDeviceAuthorization,
			AllowAuthorizedSession: allow,
		}
		source := &fakeSource{
			result: &credential.OAuth2Response{
				HTTPStatus:                    200,
				Status:                        "Authorized",
				AuthorizationRequired:         new(false),
				DeviceSessionID:               "session",
				UserCode:                      "USER",
				AuthorizationExpiresInSeconds: 300,
			},
		}
		f := &Filter{cfg: cfg, source: source}
		status := 200
		if allow != nil && !*allow {
			status = 502
		}
		replyJSON(
			t,
			runBody(t, f, requestStream("issuer.test", "/device", "application/x-www-form-urlencoded"), ""),
			status,
		)
	}
}

func TestTokenContentTypeSelectsDecoder(t *testing.T) {
	cfg := tokenConfig(credential.OAuth2GrantRefreshToken)
	for _, tc := range []struct {
		contentType string
		body        string
	}{
		{"application/x-www-form-urlencoded", "grant_type=refresh_token&refresh_token=unused"},
		{"application/x-www-form-urlencoded; charset=utf-8", "grant_type=refresh_token&refresh_token=unused"},
		{"application/json", `{"grant_type":"refresh_token","refresh_token":"unused"}`},
		{"application/json; charset=utf-8", `{"grant_type":"refresh_token","refresh_token":"unused"}`},
	} {
		t.Run(tc.contentType, func(t *testing.T) {
			source := &fakeSource{result: successfulToken("Ready")}
			f := &Filter{cfg: cfg, source: source}
			got := replyJSON(t, runBody(t, f, requestStream("issuer.test", "/token", tc.contentType), tc.body), 200)
			if len(source.calls) != 1 || source.calls[0].request.GrantType != credential.OAuth2GrantRefreshToken ||
				got["access_token"] != "unused" {
				t.Fatalf("decoder failed: reply=%v calls=%+v", got, source.calls)
			}
			if _, ok := got["code"]; ok {
				t.Fatal("Content-Type introduced an application-specific response field")
			}
		})
	}
}
