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

package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// OAuth traffic uses HTTPS; the separate HTTP listener exposes the credential
// service contract and test-driver controls, never the client's OAuth endpoints.
type oauth2Fixture struct {
	mu            sync.Mutex
	token         string
	state         string
	pendingStatus int
	pendingCode   string
	calls         map[string]int
	originCalls   int
	rejectedCalls int
	bypassCalls   int
}

func newOAuth2Fixture() *oauth2Fixture {
	return &oauth2Fixture{
		token:         "oauth2-fixture-private-" + rand.Text(),
		state:         "NotAuthorized",
		pendingStatus: http.StatusBadRequest,
		pendingCode:   "authorization_pending",
		calls:         map[string]int{},
	}
}

func (f *oauth2Fixture) identity(w http.ResponseWriter, r *http.Request) {
	var fields map[string]string
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		http.Error(w, "invalid credential request", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Authorization") != "Bearer epe-e2e-access" || fields["resourceId"] != "epe-e2e-client" ||
		fields["credentialProviderName"] != "oauth2-e2e" {
		http.Error(w, "untrusted credential selection", http.StatusForbidden)
		return
	}
	action := r.Header.Get("X-Api-Action-Name")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[action]++
	var reply map[string]any
	switch action {
	case "CreateOAuth2DeviceSession":
		if fields["idempotencyKey"] == "" || fields["scopes"] != "fixture.read" || len(fields) != 4 {
			http.Error(w, "invalid create parameters", http.StatusBadRequest)
			return
		}
		f.state = "InProgress"
		reply = map[string]any{
			"status":                        "InProgress",
			"authorizationRequired":         true,
			"deviceSessionId":               "fixture-session",
			"userCode":                      "FIXTURE-CODE",
			"verificationUri":               "https://approve.example.test/device",
			"authorizationExpiresInSeconds": 300,
			"pollIntervalSeconds":           1,
		}
	case "PollOAuth2DeviceSession":
		if fields["deviceSessionId"] != "fixture-session" || len(fields) != 3 {
			http.Error(w, "invalid poll parameters", http.StatusBadRequest)
			return
		}
		if f.state != "Authorized" {
			reply = f.failure("InProgress", f.pendingCode, f.pendingStatus, true, false)
			reply["retryAfterSeconds"] = 1
		} else {
			reply = f.credential("Authorized")
		}
	case "GetOAuth2DeviceAccessToken":
		if len(fields) != 2 {
			http.Error(w, "private client parameters reached the credential service", http.StatusBadRequest)
			return
		}
		if f.state != "Authorized" {
			reply = f.failure("NotAuthorized", "invalid_token", http.StatusUnauthorized, false, true)
		} else {
			reply = f.credential("Ready")
		}
	default:
		http.Error(w, "unknown credential action", http.StatusBadRequest)
		return
	}
	f.write(w, reply)
}

func (f *oauth2Fixture) credential(state string) map[string]any {
	return map[string]any{
		"status":                      state,
		"accessToken":                 f.token,
		"tokenType":                   "Bearer",
		"accessTokenExpiresInSeconds": 60,
		"scope":                       "fixture.read",
		"cacheExpiresInSeconds":       0,
		// Deliberate canaries: these private fields must not be projected to clients.
		"refreshToken": "oauth2-fixture-private-refresh",
		"appSecret":    "oauth2-fixture-private-secret",
	}
}

func (f *oauth2Fixture) failure(state, code string, status int, retry, reauthorize bool) map[string]any {
	return map[string]any{
		"status": state,
		"outcome": map[string]any{
			"retryable":                retry,
			"requiresNewAuthorization": reauthorize,
			"oauth2Error": map[string]any{
				"errorCode":        code,
				"errorDescription": "Fixture authorization outcome.",
				"httpStatus":       status,
			},
		},
	}
}

func (f *oauth2Fixture) controlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /identity", f.identity)
	mux.HandleFunc("POST /authorize", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.state = "Authorized"
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /pending", func(w http.ResponseWriter, r *http.Request) {
		status, err := strconv.Atoi(r.URL.Query().Get("status"))
		code := r.URL.Query().Get("error")
		if err != nil || (status != 200 && status != 400) || (code != "authorization_pending" && code != "slow_down") {
			http.Error(w, "invalid pending outcome", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.state = "InProgress"
		f.pendingStatus = status
		f.pendingCode = code
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /observations", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.write(
			w,
			map[string]any{
				"calls":         f.calls,
				"originCalls":   f.originCalls,
				"rejectedCalls": f.rejectedCalls,
				"bypassCalls":   f.bypassCalls,
			},
		)
	})
	return mux
}

func (f *oauth2Fixture) resourceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/probe":
			f.write(w, map[string]any{"ready": true})
		case "/resource":
			f.originCalls++
			if r.Header.Get("Authorization") != "Bearer "+f.token {
				f.rejectedCalls++
				http.Error(w, "upstream credential required", http.StatusForbidden)
				return
			}
			// Never echo the injected credential back into the untrusted caller.
			f.write(w, map[string]any{"authenticated": true, "data": "fixture document"})
		default:
			f.bypassCalls++
			http.Error(w, "OAuth request bypassed EPE", http.StatusTeapot)
		}
	})
}

func (*oauth2Fixture) write(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		return
	}
}

func serveOAuth2Fixture(port int, certificate, key string) error {
	f := newOAuth2Fixture()
	control := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           f.controlHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	resource := &http.Server{
		Addr:              fmt.Sprintf(":%d", port+1),
		Handler:           f.resourceHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errors := make(chan error, 2)
	go func() { errors <- control.ListenAndServe() }()
	go func() { errors <- resource.ListenAndServeTLS(certificate, key) }()
	return <-errors
}
