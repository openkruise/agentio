// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testOptions() *options {
	return flags(flag.NewFlagSet("test", flag.ContinueOnError))
}

func TestInputValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*options)
	}{
		{"unknown mode", func(o *options) { o.mode = "udp" }},
		{"zero duration", func(o *options) { o.seconds = 0 }},
		{"zero rate", func(o *options) { o.rate = 0 }},
		{"negative workers", func(o *options) { o.concurrency = -1 }},
		{"zero targets", func(o *options) { o.targets = 0 }},
		{"negative body", func(o *options) { o.body = -1 }},
		{"negative profiles", func(o *options) { o.profiles = -1 }},
		{"unknown targets mode", func(o *options) { o.targetMode = "random" }},
		{"invalid URL", func(o *options) { o.endpoint = "localhost:80" }},
		{"rotating target port", func(o *options) { o.targetMode = "names" }},
		{"TLS missing CA", func(o *options) { o.endpoint = "https://localhost/" }},
		{"invalid TCP endpoint", func(o *options) { o.mode = "tcp" }},
		{"serve missing certificate", func(o *options) { o.mode = "serve" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := testOptions()
			tc.change(o)
			if err := o.validate(); err == nil {
				t.Fatal("expected input rejection")
			}
		})
	}
	if err := testOptions().validate(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSVerifiesTrustAndServerName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "target.test:443" {
			t.Errorf("authority=%q", r.Host)
		}
		w.Header().Set("X-Policy", "applied")
		if _, err := w.Write([]byte("ok\n")); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(
		caFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	o := testOptions()
	o.endpoint = server.URL
	o.authority = "target.test:443"
	o.caFile = caFile
	o.tlsServerName = server.Certificate().DNSNames[0]
	o.expectPolicy = true
	operation, cleanup, err := o.httpOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := operation(context.Background(), 0); err != nil {
		t.Fatalf("trusted certificate rejected: %v", err)
	}
	o.tlsServerName = "wrong.test"
	operation, cleanup, err = o.httpOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := operation(context.Background(), 0); err == nil {
		t.Fatal("wrong TLS server name accepted")
	}
	config, err := o.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.ServerName = server.Certificate().DNSNames[0]
	config.RootCAs = x509.NewCertPool()
	transport := &http.Transport{TLSClientConfig: config}
	defer transport.CloseIdleConnections()
	if response, err := (&http.Client{Transport: transport}).Get(server.URL); err == nil {
		closeResource(response.Body)
		t.Fatal("untrusted certificate accepted")
	}
}

func TestOriginPolicyAndBodyValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		policy    string
		wantError bool
	}{
		{"valid", "ok\n", "applied", false},
		{"missing policy", "ok\n", "", true},
		{"wrong origin", "unexpected\n", "applied", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Policy", tc.policy)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			o := testOptions()
			o.endpoint = server.URL
			o.expectPolicy = true
			operation, cleanup, err := o.httpOperation()
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if err := operation(context.Background(), 0); (err != nil) != tc.wantError {
				t.Fatalf("operation error=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestHTTP2RejectsHTTP1Fallback(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("server_http2_%t", enabled), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write([]byte("ok\n")); err != nil {
					t.Error(err)
				}
			}))
			server.EnableHTTP2 = enabled
			server.StartTLS()
			defer server.Close()
			caFile := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(
				caFile,
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
				0600,
			); err != nil {
				t.Fatal(err)
			}
			o := testOptions()
			o.endpoint = server.URL
			o.caFile = caFile
			o.tlsServerName = server.Certificate().DNSNames[0]
			o.h2 = true
			operation, cleanup, err := o.httpOperation()
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			err = operation(t.Context(), 0)
			if enabled && err != nil {
				t.Fatal(err)
			}
			if !enabled && (err == nil || !strings.Contains(err.Error(), "expected HTTP/2")) {
				t.Fatalf("HTTP/1 fallback was not rejected: %v", err)
			}
		})
	}
}

func TestPersistentTCPSkipsCanceledQueuedOperation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(listener)
	firstRead := make(chan struct{})
	release := make(chan struct{})
	serverDone := make(chan struct{})
	var payloads atomic.Int32
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer closeResource(conn)
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
			return
		}
		for {
			payload := make([]byte, 5)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
			if payloads.Add(1) == 1 {
				close(firstRead)
				<-release
			}
			if _, err := conn.Write(payload); err != nil {
				return
			}
		}
	}()
	o := testOptions()
	o.endpoint = listener.Addr().String()
	o.stream = true
	operation, cleanup, err := o.tcpOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	firstDone := make(chan error, 1)
	go func() { firstDone <- operation(t.Context(), 0) }()
	<-firstRead
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	secondDone := make(chan error, 1)
	go func() { secondDone <- operation(ctx, 0) }()
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued operation error=%v, want cancellation", err)
	}
	if got := payloads.Load(); got != 1 {
		t.Fatalf("origin received %d payloads, want 1", got)
	}
	cleanup()
	<-serverDone
}

func TestTCPRespectsContextDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(listener)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer closeResource(conn)
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
			return
		}
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Error(err)
		}
	}()
	o := testOptions()
	o.endpoint = listener.Addr().String()
	operation, cleanup, err := o.tcpOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := operation(ctx, 0); err == nil {
		t.Fatal("unresponsive origin unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("context deadline did not bound TCP I/O: %s", elapsed)
	}
	<-serverDone
}

func TestPersistentTCPRecoversOnNextOperationAfterDisconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(listener)
	var connections atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer closeResource(conn)
				if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
					return
				}
				if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
					return
				}
				payload := make([]byte, 5)
				if _, err := io.ReadFull(conn, payload); err != nil {
					return
				}
				if _, err := conn.Write(payload); err != nil {
					t.Error(err)
				}
			}()
		}
	}()
	o := testOptions()
	o.mode = "tcp"
	o.endpoint = listener.Addr().String()
	o.stream = true
	operation, cleanup, err := o.tcpOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := operation(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := operation(context.Background(), 0); err == nil {
		t.Fatal("closed tunnel unexpectedly succeeded")
	}
	if err := operation(context.Background(), 0); err != nil {
		t.Fatalf("next operation failed to reconnect: %v", err)
	}
	if got := connections.Load(); got != 2 {
		t.Fatalf("connections=%d, want 2", got)
	}
	closeResource(listener)
	<-done
}

func TestIPTargetsUseTheRoutedTestRange(t *testing.T) {
	hosts := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts <- r.Host
		if _, err := w.Write([]byte("ok\n")); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	o := testOptions()
	o.endpoint = server.URL
	o.targetMode = "ips"
	o.authority = "19201"
	o.targets = 131072
	if err := o.validate(); err != nil {
		t.Fatal(err)
	}
	operation, cleanup, err := o.httpOperation()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, tc := range []struct {
		index int
		host  string
	}{
		{0, "10.200.0.0:19201"},
		{255, "10.200.0.255:19201"},
		{256, "10.200.1.0:19201"},
		{32767, "10.200.127.255:19201"},
		{65536, "10.201.0.0:19201"},
		{131071, "10.201.255.255:19201"},
	} {
		if err := operation(context.Background(), tc.index); err != nil {
			t.Fatal(err)
		}
		if got := <-hosts; got != tc.host {
			t.Fatalf("index %d generated %q, want %q", tc.index, got, tc.host)
		}
	}
	o.targets = 131073
	if err := o.validate(); err == nil {
		t.Fatal("accepted IP target count outside routed test range")
	}
}
