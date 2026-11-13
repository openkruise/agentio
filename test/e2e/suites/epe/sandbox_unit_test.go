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

package epe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestSandboxHTTPSResponseSurvivesTunnelCleanup(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
		if _, err := io.WriteString(w, "sandbox-blocked"); err != nil {
			t.Error(err)
		}
	}))
	defer origin.Close()
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() {
			if err := upstream.Close(); err != nil {
				t.Error(err)
			}
		}()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		go func() {
			if _, err := io.Copy(upstream, r.Body); err != nil {
				t.Logf("CONNECT upload ended: %v", err)
			}
		}()
		buffer := make([]byte, 4096)
		for {
			n, readErr := upstream.Read(buffer)
			if n > 0 {
				if _, err := w.Write(buffer[:n]); err != nil {
					t.Logf("CONNECT download ended: %v", err)
					return
				}
				w.(http.Flusher).Flush()
			}
			if readErr != nil {
				return
			}
		}
	}))
	gateway.EnableHTTP2 = true
	gateway.StartTLS()
	defer gateway.Close()
	roots := x509.NewCertPool()
	roots.AddCert(gateway.Certificate())
	host, port, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	f := sandboxPolicyFixture{gateway: strings.TrimPrefix(gateway.URL, "https://"), serverIP: host}
	caller := sandboxCaller{tls: &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}}}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	reply, err := f.request(ctx, caller, "kruise:delivery-test", "/sandbox-block", port, true)
	if err != nil {
		t.Fatal(err)
	}
	if reply.status != http.StatusUnavailableForLegalReasons || reply.body != "sandbox-blocked" || reply.peer == nil {
		t.Fatalf("unexpected HTTPS policy response: %+v", reply)
	}
}

func TestSandboxTLSRejectionEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"EOF", fmt.Errorf("inner TLS handshake: %w", io.EOF), true},
		{"truncated handshake", io.ErrUnexpectedEOF, true},
		{"stream canceled by gateway", http2.StreamError{StreamID: 1, Code: http2.ErrCodeCancel}, true},
		{"TLS alert", errors.New("remote error: tls: access denied"), true},
		{"success", nil, false},
		{"deadline", fmt.Errorf("inner TLS handshake: %w", context.DeadlineExceeded), false},
		{"dial timeout", &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}, false},
		{"DNS failure", &net.DNSError{Err: "not found", Name: "server"}, false},
		{"unrelated reset", http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol}, false},
		{"transport failure", errors.New("connection refused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sandboxTLSRejected(tc.err); got != tc.want {
				t.Fatalf("policy rejection=%t, want %t for %v", got, tc.want, tc.err)
			}
		})
	}
}
