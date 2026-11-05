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
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/bench/load"
)

func TestContinuousTrafficChangesRateWithoutRepreparingClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rate")
	if err := os.WriteFile(path, []byte("100"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &runner{options: options{TrafficRateFile: path, Duration: time.Minute}}
	var rates []int
	result, err := r.continuousTraffic(t.Context(), func(rate, requests int, _ time.Duration) (load.Result, error) {
		rates = append(rates, rate)
		next := "200"
		if len(rates) == 2 {
			next = "-1"
		}
		if err := os.WriteFile(path, []byte(next), 0600); err != nil {
			t.Fatal(err)
		}
		if len(rates) == 1 {
			return load.Result{Operations: requests}, context.DeadlineExceeded
		}
		return load.Result{Operations: requests}, nil
	})
	if err != nil || !reflect.DeepEqual(rates, []int{100, 200}) || result.(map[string]int)["operations"] != 3000 {
		t.Fatalf("rates=%v result=%v err=%v", rates, result, err)
	}
}

// A TCP/TLS success is insufficient: the test adapter must check both CONNECT
// authorization and the exact HTTP response carried inside the tunnel.
func TestRequestChecksTunnelAndBackend(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connect   int
		inner     int
		body      string
		wantError bool
		traffic   bool
	}{
		{"allowed", 200, 200, "sandbox-scale-ok\n", false, false},
		{"connect_denied", 403, 200, "sandbox-scale-ok\n", true, false},
		{"policy_denied", 200, 451, "denied", true, false},
		{"wrong_backend", 200, 200, "other-service\n", true, false},
		{"traffic_policy_denied", 200, 403, `{"code":"epe_egress_denied","message":"Outbound destination is denied by policy.","requestID":"dynamic-id"}`, false, true},
		{"traffic_wrong_error", 200, 403, `{"code":"other","message":"Outbound destination is denied by policy."}`, true, true},
		{"traffic_malformed_error", 200, 403, `not json`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "CONNECT" || req.Host != "backend:8080" ||
					req.Header.Get("X-Agentio-Sandbox-Id") != "kruise:sandbox-000042" {
					t.Errorf("incorrect tunnel request: %s %s %v", req.Method, req.Host, req.Header)
				}
				w.WriteHeader(tc.connect)
				w.(http.Flusher).Flush()
				if tc.connect != 200 {
					return
				}
				reader := bufio.NewReader(req.Body)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						t.Errorf("read inner request: %v", err)
						return
					}
					if line == "\r\n" {
						break
					}
				}
				if _, err := fmt.Fprintf(
					w,
					"HTTP/1.1 %d response\r\nContent-Length: %d\r\n\r\n%s",
					tc.inner,
					len(tc.body),
					tc.body,
				); err != nil {
					t.Errorf("write inner response: %v", err)
				}
			}))
			server.EnableHTTP2 = true
			var connections atomic.Int64
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			r := &runner{
				options: options{
					Gateway:        strings.TrimPrefix(server.URL, "https://"),
					Target:         "backend:8080",
					Path:           "/",
					ExpectedStatus: 200,
					ExpectedBody:   "sandbox-scale-ok\n",
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if tc.traffic {
				r.PolicyKind = "traffic"
				r.ExpectedStatus = http.StatusForbidden
			}
			defer cancel()
			err := r.request(ctx, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, 42)
			if (err != nil) != tc.wantError {
				t.Fatalf("request error=%v, want error=%t", err, tc.wantError)
			}
			transport := r.gatewayTransport(&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
			defer transport.CloseIdleConnections()
			for range 2 {
				err := r.requestOn(ctx, transport.RoundTrip, 42)
				if (err != nil) != tc.wantError {
					t.Fatalf("reused request error=%v, want error=%t", err, tc.wantError)
				}
			}
			if got := connections.Load(); got != 2 {
				t.Fatalf("TLS connections=%d, want one fresh and one reused", got)
			}
		})
	}
}
