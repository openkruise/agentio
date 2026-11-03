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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A TCP/TLS success is insufficient: the test adapter must check both CONNECT
// authorization and the exact HTTP response carried inside the tunnel.
func TestRequestChecksTunnelAndBackend(t *testing.T) {
	for _, test := range []struct {
		name      string
		connect   int
		inner     int
		body      string
		wantError bool
	}{
		{"allowed", 200, 200, "sandbox-scale-ok\n", false},
		{"connect_denied", 403, 200, "sandbox-scale-ok\n", true},
		{"policy_denied", 200, 451, "denied", true},
		{"wrong_backend", 200, 200, "other-service\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "CONNECT" || req.Host != "backend:8080" ||
					req.Header.Get("X-Agentio-Sandbox-Uid") != "kruise:sandbox-000042" {
					t.Errorf("incorrect tunnel request: %s %s %v", req.Method, req.Host, req.Header)
				}
				w.WriteHeader(test.connect)
				w.(http.Flusher).Flush()
				if test.connect != 200 {
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
					test.inner,
					len(test.body),
					test.body,
				); err != nil {
					t.Errorf("write inner response: %v", err)
				}
			}))
			server.EnableHTTP2 = true
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
			defer cancel()
			err := r.request(ctx, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, 42)
			if (err != nil) != test.wantError {
				t.Fatalf("request error=%v, want error=%t", err, test.wantError)
			}
		})
	}
}
