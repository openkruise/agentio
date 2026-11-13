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

package hbone

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectHeadersAndBidirectionalStream(t *testing.T) {
	for _, id := range []string{"kruise:delivery", ""} {
		t.Run(id, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 || r.Method != http.MethodConnect || r.Host != "192.0.2.1:443" {
					t.Errorf("unexpected CONNECT: %s %s %s", r.Proto, r.Method, r.Host)
				}
				if values, present := r.Header["X-Agentio-Sandbox-Id"]; present != (id != "") ||
					r.Header.Get("X-Agentio-Sandbox-Id") != id {
					t.Errorf("Sandbox ID presence=%t values=%v, want %q", present, values, id)
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				body := make([]byte, 4)
				if _, err := io.ReadFull(r.Body, body); err != nil {
					t.Error(err)
					return
				}
				if _, err := fmt.Fprintf(w, "reply:%s", body); err != nil {
					t.Error(err)
				}
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			headers := make(http.Header)
			if id != "" {
				headers.Set("X-Agentio-Sandbox-Id", id)
			}
			conn, status, err := Dial(
				ctx,
				strings.TrimPrefix(server.URL, "https://"),
				"192.0.2.1:443",
				&tls.Config{RootCAs: roots, NextProtos: []string{"h2"}},
				headers,
			)
			if err != nil || status != http.StatusOK {
				t.Fatalf("CONNECT status=%d error=%v", status, err)
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
			}()
			if _, err := io.WriteString(conn, "ping"); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(conn)
			if err != nil || string(body) != "reply:ping" {
				t.Fatalf("tunnel response %q, error=%v", body, err)
			}
		})
	}
}

func TestConnectRejectionAndCancellation(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status == http.StatusForbidden {
					w.WriteHeader(status)
					return
				}
				cancel()
				<-r.Context().Done()
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			conn, got, err := Dial(
				ctx,
				strings.TrimPrefix(server.URL, "https://"),
				"192.0.2.1:443",
				&tls.Config{RootCAs: roots, NextProtos: []string{"h2"}},
				nil,
			)
			if conn != nil {
				t.Fatalf("rejected or canceled CONNECT returned a stream, close error=%v", conn.Close())
			}
			if status == http.StatusForbidden && (err != nil || got != status) {
				t.Fatalf("CONNECT status=%d error=%v", got, err)
			}
			if status == http.StatusOK && err == nil {
				t.Fatal("canceled CONNECT succeeded")
			}
		})
	}
}
