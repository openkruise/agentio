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
package httpcallout

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
)

// calloutInvocation builds a valid request-phase invocation for client tests.
func calloutInvocation(t *testing.T) Invocation {
	t.Helper()
	cfg := testConfig(t, Config{Request: &PhaseConfig{Body: true}})
	inv, err := buildRequestInvocation(
		cfg,
		testUnitID(),
		testStream(),
		filter.Body{Bytes: []byte("body"), Complete: true},
	)
	if err != nil {
		t.Fatalf("buildRequestInvocation: %v", err)
	}
	return inv
}

// decisionFor is what a well-behaved endpoint answers with. It takes no
// invocation: a decision restates nothing from the exchange it answers.
func decisionFor() Decision {
	return Decision{
		Version: ProtocolVersion,
		Action:  actionPtr(ActionContinue),
	}
}

func serveDecision(t *testing.T, handler http.HandlerFunc) *testHTTPClient {
	t.Helper()
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r.WithContext(withServerShutdown(r.Context(), done)))
	}))
	t.Cleanup(server.Close)
	// Registered after server.Close so it runs first: Cleanup is LIFO, and
	// Server.Close waits for in-flight handlers. Abandoning a request
	// client-side does not cancel the handler's context, so a handler parked on
	// Done would deadlock Close unless this releases it first.
	t.Cleanup(func() { close(done) })

	return newTestHTTPClient(t, server.URL)
}

type testHTTPClient struct {
	*HTTPClient
	registry *extensionprovider.Registry
	config   *configv1.HTTPCalloutProvider
	endpoint string
}

func newTestHTTPClient(t *testing.T, endpoint string) *testHTTPClient {
	t.Helper()
	registry := &extensionprovider.Registry{}
	t.Cleanup(registry.Close)
	client := &testHTTPClient{
		HTTPClient: NewHTTPClient(registry),
		registry:   registry,
		config:     &configv1.HTTPCalloutProvider{Url: endpoint, Timeout: "500ms"},
		endpoint:   endpoint,
	}
	client.configure(t)
	return client
}

func (c *testHTTPClient) configure(t *testing.T) {
	t.Helper()
	if err := c.registry.Apply(&configv1.AgentioConfig{ExtensionProviders: []*configv1.ExtensionProvider{{
		Name:     "scanner",
		Provider: &configv1.ExtensionProvider_HttpCallout{HttpCallout: c.config},
	}}}, nil); err != nil {
		t.Fatal(err)
	}
}

// withServerShutdown makes the handler's Done fire at test cleanup as well as on
// real request cancellation.
func withServerShutdown(parent context.Context, done <-chan struct{}) context.Context {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
		}
		cancel()
	}()
	return ctx
}

func TestHTTPClientPostsTheInvocationAsJSON(t *testing.T) {
	inv := calloutInvocation(t)
	var (
		gotMethod      string
		gotContentType string
		gotAccept      string
		gotPath        string
		gotBody        Invocation
	)
	client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_ = json.NewEncoder(w).Encode(decisionFor())
	})

	got, err := client.Call(context.Background(), "scanner", inv)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !reflect.DeepEqual(got, decisionFor()) {
		t.Errorf("decision = %#v, want %#v", got, decisionFor())
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
	if gotPath != "/" {
		t.Errorf("path = %q, want the endpoint path", gotPath)
	}
	if !reflect.DeepEqual(gotBody, inv) {
		t.Errorf("decoded invocation = %#v, want %#v", gotBody, inv)
	}
}

// The provider timeout bounds calls even when the caller has no deadline.
func TestHTTPClientHonoursTheProviderTimeout(t *testing.T) {
	inv := calloutInvocation(t)
	client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	client.config.Timeout = "50ms"
	client.configure(t)

	start := time.Now()
	_, err := client.Call(context.Background(), "scanner", inv)
	if err == nil {
		t.Fatal("Call succeeded against a hanging endpoint, want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Call took %v, want it bounded by the provider timeout", elapsed)
	}
	assertHidesEndpointBody(t, err, client.endpoint, "")
}

func TestHTTPClientRejectsNon2xx(t *testing.T) {
	inv := calloutInvocation(t)
	const leaked = "internal scanner stack trace at /opt/scanner/main.py"
	for _, status := range []int{http.StatusNoContent, http.StatusMovedPermanently, http.StatusBadRequest, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
				if status == http.StatusNoContent {
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(leaked))
			})
			_, err := client.Call(context.Background(), "scanner", inv)
			if status == http.StatusNoContent {
				// 204 is 2xx but carries no decision; it must still fail.
				if err == nil {
					t.Fatal("Call accepted an empty 204, want an error")
				}
				return
			}
			if err == nil {
				t.Fatalf("Call accepted status %d, want an error", status)
			}
			if !strings.Contains(err.Error(), http.StatusText(status)) && !strings.Contains(err.Error(), "status") {
				t.Errorf("error = %q, want it to name the status", err.Error())
			}
			assertHidesEndpointBody(t, err, client.endpoint, leaked)
		})
	}
}

func TestHTTPClientRejectsUnparseableBody(t *testing.T) {
	inv := calloutInvocation(t)
	const leaked = "<html>scanner-internal.corp.example.com is down</html>"
	client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(leaked))
	})

	_, err := client.Call(context.Background(), "scanner", inv)
	if err == nil {
		t.Fatal("Call accepted a non-JSON body, want an error")
	}
	assertHidesEndpointBody(t, err, client.endpoint, leaked)
}

// The limit comes from the environment and never permits a truncated decision,
// even when the prefix is valid JSON. Non-positive values must not disable it.
func TestHTTPClientResponseLimit(t *testing.T) {
	inv := calloutInvocation(t)
	raw, err := json.Marshal(decisionFor())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		configured string
		limit      int
		bodyBytes  int
	}{
		{name: "below", configured: "64", limit: 64, bodyBytes: 63},
		{name: "exact", configured: "64", limit: 64, bodyBytes: 64},
		{name: "oversized", configured: "64", limit: 64, bodyBytes: 65},
		{name: "zero", configured: "0", limit: 1 << 20, bodyBytes: 1<<20 + 1},
		{name: "negative", configured: "-1", limit: 1 << 20, bodyBytes: 1<<20 + 1},
		{name: "invalid", configured: "invalid", limit: 1 << 20, bodyBytes: 1<<20 + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HTTP_CALLOUT_MAX_RESPONSE_BYTES", tc.configured)
			body := string(raw) + strings.Repeat(" ", tc.bodyBytes-len(raw))
			client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.WriteString(w, body); err != nil {
					t.Error(err)
				}
			})
			// Existing clients keep their limit after construction.
			t.Setenv("HTTP_CALLOUT_MAX_RESPONSE_BYTES", "1")
			got, err := client.Call(context.Background(), "scanner", inv)
			if tc.bodyBytes <= tc.limit {
				if err != nil || !reflect.DeepEqual(got, decisionFor()) {
					t.Fatalf("decision within limit: got %#v, error %v", got, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), strconv.Itoa(tc.limit)+" byte limit") {
				t.Fatalf("oversized decision: got error %v, want limit %d", err, tc.limit)
			}
		})
	}
}

// TestHTTPClientDoesNotRetry pins the no-retry rule: a callout may have taken a
// side effect already, so a second attempt would double it.
func TestHTTPClientDoesNotRetry(t *testing.T) {
	inv := calloutInvocation(t)
	var calls atomic.Int32
	client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	if _, err := client.Call(context.Background(), "scanner", inv); err == nil {
		t.Fatal("Call succeeded, want an error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("endpoint saw %d calls, want exactly 1", got)
	}
}

// TestHTTPClientDoesNotFollowRedirects pins that a 3xx is a failure rather than
// a hop to wherever the endpoint points: following one would let the configured
// endpoint redirect the invocation, body and all, to an unvalidated URL.
func TestHTTPClientDoesNotFollowRedirects(t *testing.T) {
	inv := calloutInvocation(t)
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		_ = json.NewEncoder(w).Encode(decisionFor())
	}))
	t.Cleanup(target.Close)

	client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})

	if _, err := client.Call(context.Background(), "scanner", inv); err == nil {
		t.Fatal("Call followed a redirect, want an error")
	}
	if got := elsewhere.Load(); got != 0 {
		t.Fatalf("redirect target saw %d calls, want 0", got)
	}
}

func TestHTTPClientReportsATransportFailureWithoutTheEndpoint(t *testing.T) {
	inv := calloutInvocation(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := server.URL
	server.Close()

	client := newTestHTTPClient(t, endpoint)
	_, err := client.Call(context.Background(), "scanner", inv)
	if err == nil {
		t.Fatal("Call reached a closed listener, want an error")
	}
	assertHidesEndpointBody(t, err, endpoint, "")
}

func TestHTTPClientHonoursCallerCancellation(t *testing.T) {
	inv := calloutInvocation(t)
	client := serveDecision(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	client.config.Timeout = "30s"
	client.configure(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, err := client.Call(ctx, "scanner", inv); err == nil {
		t.Fatal("Call ignored the cancelled caller context, want an error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Call took %v, want the caller's cancellation to win", elapsed)
	}
}

// assertHidesEndpointBody pins the hygiene rule from tokentransform's blockReply:
// a callout error is logged, but it must not name the endpoint or quote the
// remote's response text, because the framework-generated deny is what the
// untrusted client sees.
func assertHidesEndpointBody(t *testing.T, err error, endpoint, remoteText string) {
	t.Helper()
	if strings.Contains(err.Error(), endpoint) {
		t.Errorf("error = %q, want it to omit the endpoint URL %q", err.Error(), endpoint)
	}
	if remoteText != "" && strings.Contains(err.Error(), remoteText) {
		t.Errorf("error = %q, want it to omit the remote response text", err.Error())
	}
}
