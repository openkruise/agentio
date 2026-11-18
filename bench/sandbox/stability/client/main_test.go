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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagementAPIAndSnapshot(t *testing.T) {
	r, w := io.Pipe()
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	})
	client := newClient(nil, w)
	handler := client.handler()
	call := func(method, path, body string, wantCode int) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, path, strings.NewReader(body)))
		if response.Code != wantCode {
			t.Fatalf("%s %s returned %d, want %d: %s", method, path, response.Code, wantCode, response.Body)
		}
		return response
	}

	if got := strings.TrimSpace(call(http.MethodGet, "/health", "", 200).Body.String()); got != `{"healthy":true}` {
		t.Fatalf("health response = %s", got)
	}
	call(http.MethodPost, "/start", `{"rate":0,"duration":60,"client_index":7}`, 200)
	call(http.MethodPost, "/start", `{"rate":120}`, 409)
	call(http.MethodPost, "/config", `{"scheme":"ftp"}`, 400)
	call(http.MethodPost, "/config", `{"cold_fraction":0.4}`, 200)

	client.record("hot", "sample.load.test", 2*time.Millisecond, time.Millisecond, observation{
		status:    200,
		errorType: "PolicyViolation",
		err:       errors.New("unexpected allow"),
		stage:     "body",
	})
	client.record("hot", "sample.load.test", 3*time.Millisecond, time.Millisecond, observation{
		status:    503,
		errorType: "AssertionError",
		err:       errors.New("unavailable"),
		stage:     "headers",
	})
	client.record("generator", "", 0, 0, observation{errorType: "RuntimeError", err: errors.New("queue full")})

	var got snapshot
	if err := json.Unmarshal(call(http.MethodGet, "/status", "", 200).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Config.Rate != 0 || got.Config.Scheme != "https" || got.Config.ColdFraction != 0.4 ||
		got.Config.ClientIndex != 7 {
		t.Fatalf("config = %+v", got.Config)
	}
	hot := got.Groups["hot"]
	if hot.Requests != 2 || hot.Errors != 2 || hot.Histogram[19] != 1 || hot.Histogram[29] != 1 ||
		hot.QueueHistogram[9] != 2 || hot.Statuses["503"] != 1 || hot.ErrorTypes["PolicyViolation"] != 1 ||
		hot.ErrorTypes["AssertionError"] != 1 {
		t.Fatalf("unexpected hot stats: %+v", hot)
	}
	generator := got.Groups["generator"]
	if generator.Requests != 1 || generator.Errors != 1 || generator.Histogram[0] != 1 ||
		len(generator.Statuses) != 0 {
		t.Fatalf("unexpected generator stats: %+v", generator)
	}

	call(http.MethodPost, "/stop", "{}", 200)
	var complete struct {
		Event string   `json:"event"`
		Stats snapshot `json:"stats"`
	}
	if err := json.NewDecoder(r).Decode(&complete); err != nil {
		t.Fatal(err)
	}
	if complete.Event != "run-complete" || !complete.Stats.Stopped || complete.Stats.Queue != 0 {
		t.Fatalf("unexpected final result: %+v", complete)
	}
}

func TestHTTPSProbeChecksTrustAndKeepsHTTP1(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || !strings.HasPrefix(r.Host, "127.0.0.1:") || r.URL.RequestURI() != "/deny?revision=1" {
			t.Errorf("unexpected request: %s %s %s", r.Proto, r.Host, r.URL)
		}
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
		if _, err := io.WriteString(w, "policy denied"); err != nil {
			t.Error(err)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	address := server.Listener.Addr().(*net.TCPAddr)
	body := `{"host":"127.0.0.1","port":` + strconv.Itoa(address.Port) + `,"path":"/deny?revision=1"}`
	var result struct {
		Status      int          `json:"status"`
		Body        string       `json:"body"`
		ErrorType   string       `json:"error_type"`
		Certificate *certificate `json:"certificate"`
	}

	handler := newClient(roots, io.Discard).handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(body)))
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || result.Status != 451 || result.Body != "policy denied" || result.ErrorType != "" ||
		result.Certificate == nil || result.Certificate.Serial == "" || result.Certificate.NotAfter == "" ||
		result.Certificate.NotBefore != "" {
		t.Fatalf("probe response: %s", response.Body)
	}
	wrongName := strings.Replace(body, "127.0.0.1", "localhost", 1)
	failed := httptest.NewRecorder()
	handler.ServeHTTP(failed, httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(wrongName)))
	if failed.Code != 200 || !bytes.Contains(failed.Body.Bytes(), []byte(`"error_type":"SSLCertVerificationError"`)) {
		t.Fatalf("wrong hostname was accepted: %s", failed.Body)
	}
}

func TestTLSProtocolFailureIsReportedSeparately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	address := server.Listener.Addr().(*net.TCPAddr)
	req := request{Host: "127.0.0.1", Scheme: "https", Port: address.Port, Path: "/"}
	var slot *connection
	defer closeConnection(&slot)
	result := exchange(t.Context(), req, x509.NewCertPool(), &slot)
	if result.err == nil || result.stage != "connect" || result.errorType != "SSLError" {
		t.Fatalf("unexpected handshake classification: %+v", result)
	}
}

func TestReuseDoesNotRetryStaleConnection(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		number := requests.Add(1)
		if number == 2 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := io.WriteString(w, "ok"); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	address := server.Listener.Addr().(*net.TCPAddr)
	req := request{Host: "127.0.0.1", Scheme: "http", Port: address.Port, Path: "/"}
	var hot *connection
	defer closeConnection(&hot)
	if result := exchange(context.Background(), req, nil, &hot); result.err != nil || hot == nil {
		t.Fatalf("could not warm a connection: %+v", result)
	}
	first := hot
	if result := exchange(context.Background(), req, nil, &hot); result.err == nil || hot != nil {
		t.Fatalf("reset was hidden or connection reused after failure: %+v", result)
	}
	if result := exchange(context.Background(), req, nil, &hot); result.err != nil || hot == nil || hot == first {
		t.Fatalf("next request did not reconnect: %+v", result)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("origin received %d requests, want 3", got)
	}
}

func TestWorkloadGroupsAndPolicyAssertions(t *testing.T) {
	client := newClient(nil, io.Discard)
	client.config.ColdFraction = 1
	client.config.Mixed = true
	client.config.Fault = true
	client.config.Group = "a"
	client.config.ClientIndex = 7
	first, group, cold := client.nextRequest(0, 0)
	if first.Host != "host-000007.load.test" || group != "domain-first" || !cold {
		t.Fatalf("first workload = %+v %q %v", first, group, cold)
	}
	for _, tt := range []struct {
		seq   int
		path  string
		group string
	}{
		{7, "/deny", "domain-first"},
		{20, "/stream", "stream"},
		{30, "/download", "download"},
		{40, "/upload", "upload"},
		{11, "/fault", "fault"},
		{10, "/allow", "long-tail"},
	} {
		got, group, _ := client.nextRequest(0, tt.seq)
		if got.Path != tt.path || group != tt.group {
			t.Fatalf("sequence %d: got %s %s, want %s %s", tt.seq, got.Path, group, tt.path, tt.group)
		}
	}
	for _, tt := range []struct {
		path     string
		code     int
		body     string
		wantType string
	}{
		{"/deny", 200, "", "PolicyViolation"},
		{"/deny", 451, "", ""},
		{"/allow", 503, "", "AssertionError"},
		{"/allow", 200, `{"marker":"STABILITY-UPSTREAM","host":"host-000007.load.test:8443","tls_sni":"host-000007.load.test","headers":{"X-Stability-Client":["7"],"X-Policy-Group":["b"]}}`, "PolicyViolation"},
		{"/allow", 200, `{"marker":"STABILITY-UPSTREAM","host":"host-000007.load.test:8443","tls_sni":"host-000007.load.test","headers":{"X-Stability-Client":["7"],"X-Policy-Group":["a"]}}`, ""},
		{"/download", 200, "short", "AssertionError"},
	} {
		req := first
		req.Path = tt.path
		got := observation{status: tt.code, body: []byte(tt.body)}
		got.check(req)
		if got.errorType != tt.wantType {
			t.Fatalf("%s status %d: got %q, want %q", tt.path, tt.code, got.errorType, tt.wantType)
		}
	}
}
