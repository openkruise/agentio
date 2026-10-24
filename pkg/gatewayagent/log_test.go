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

package gatewayagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type logBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}
func captureGatewayLogs(t *testing.T) *logBuffer {
	t.Helper()
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	b := &logBuffer{}
	c := FromEnvironment()
	c.LogAsJSON = true
	if err := ConfigureLogging(c, b); err != nil {
		t.Fatal(err)
	}
	return b
}
func TestADSSessionLogs(t *testing.T) {
	logs := captureGatewayLogs(t)
	p := &xdsProxy{config: testConfig(t)}
	received, finished := p.observeSession(t.Context())
	if logs.String() != "" {
		t.Fatal("logged connection before receiving a response")
	}
	received()
	received()
	finished(status.Error(codes.Unavailable, "upstream disconnected"), "relay")
	for _, err := range []error{io.EOF, context.Canceled, status.Error(codes.Canceled, "closed")} {
		_, done := p.observeSession(t.Context())
		done(err, "relay")
	}
	if strings.Count(logs.String(), "received first control-plane response") != 1 ||
		strings.Count(logs.String(), "stream failed") != 1 {
		t.Fatal(logs.String())
	}
	if !strings.Contains(logs.String(), p.config.Proxy.DiscoveryAddress) ||
		!strings.Contains(logs.String(), "Unavailable") {
		t.Fatal(logs.String())
	}
	var connectionID any
	var firstDuration float64
	for i, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		duration, ok := record["duration"].(float64)
		if !ok || duration <= 0 || record["connection_id"] == nil {
			t.Fatalf("missing session timing or identity: %s", line)
		}
		if i == 0 {
			connectionID, firstDuration = record["connection_id"], duration
		} else if record["connection_id"] != connectionID || duration < firstDuration {
			t.Fatalf("termination does not match the established session: %s", line)
		}
	}
	nextReceived, nextFinished := p.observeSession(t.Context())
	nextReceived()
	nextFinished(nil, "relay")
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	var next map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &next); err != nil {
		t.Fatal(err)
	}
	if next["connection_id"] == nil || next["connection_id"] == connectionID {
		t.Fatalf("reconnection reused session identity: %v", next)
	}
}

func TestADSSessionTerminationLogLevel(t *testing.T) {
	const maxAge = `closing transport due to: connection error: desc = "error reading from server: EOF", received prior goaway: code: NO_ERROR, debug data: "max_age"`
	for _, tc := range []struct {
		name  string
		err   error
		level string
	}{
		{"max age", status.Error(codes.Unavailable, maxAge), "DEBUG"},
		{"wrapped max age", fmt.Errorf("receive: %w", status.Error(codes.Unavailable, maxAge)), "DEBUG"},
		{"server EOF", status.Error(codes.Unavailable, "connection error: error reading from server: EOF"), "DEBUG"},
		{"transport closing", status.Error(codes.Unavailable, "transport is closing"), "DEBUG"},
		{"client disconnected", status.Error(codes.Unavailable, "client disconnected"), "DEBUG"},
		{"normal GOAWAY", status.Error(codes.Unavailable, "received prior goaway: code: NO_ERROR"), "DEBUG"},
		{"normal reset", status.Error(codes.Internal, "stream terminated by RST_STREAM with error code: NO_ERROR"), "DEBUG"},
		{"connection refused", status.Error(codes.Unavailable, "dial tcp: connect: connection refused"), "WARN"},
		{"unexpected reset", status.Error(codes.Unavailable, "connection reset by peer"), "WARN"},
		{"abnormal GOAWAY", status.Error(codes.Unavailable, "received prior goaway: code: ENHANCE_YOUR_CALM"), "WARN"},
		{"abnormal GOAWAY with EOF", status.Error(codes.Unavailable,
			strings.ReplaceAll(maxAge, `code: NO_ERROR, debug data: "max_age"`,
				`code: ENHANCE_YOUR_CALM, debug data: "too_many_pings"`)), "WARN"},
		{"abnormal GOAWAY with transport closing", status.Error(codes.Unavailable,
			`closing transport due to: transport is closing, received prior goaway: code: INTERNAL_ERROR, debug data: ""`), "WARN"},
		{"deadline", status.Error(codes.DeadlineExceeded, "context deadline exceeded"), "WARN"},
		{"internal error", status.Error(codes.Internal, "transport is closing"), "WARN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureGatewayLogs(t)
			c := FromEnvironment()
			t.Cleanup(func() {
				if err := ConfigureLogging(c, logs); err != nil {
					t.Fatal(err)
				}
			})
			debug := c
			debug.AgentLogLevel, debug.LogAsJSON = "debug", true
			if err := ConfigureLogging(debug, logs); err != nil {
				t.Fatal(err)
			}
			p := &xdsProxy{config: testConfig(t)}
			_, finished := p.observeSession(t.Context())
			finished(tc.err, "relay")
			var record map[string]any
			if err := json.Unmarshal([]byte(logs.String()), &record); err != nil {
				t.Fatal(err)
			}
			if record["level"] != tc.level {
				t.Fatalf("level = %v, want %s: %s", record["level"], tc.level, logs.String())
			}
			if record["error"] != tc.err.Error() || record["stage"] != "relay" ||
				record["code"] != status.Code(tc.err).String() || record["address"] != p.config.Proxy.DiscoveryAddress {
				t.Fatalf("missing termination details: %s", logs.String())
			}
		})
	}
}

func TestReadinessTransitionLogs(t *testing.T) {
	logs := captureGatewayLogs(t)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprintln(
			w,
			"cluster_manager.cds.update_success: 1\nlistener_manager.lds.update_success: 1\nserver.state: 0\nlistener_manager.workers_started: 1",
		); err != nil {
			t.Error(err)
		}
	}))
	defer admin.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(admin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig(t)
	c.IP = "127.0.0.1"
	c.Proxy.AdminPort = int32(n)
	c.StatusPort = freePort(t)
	var reason atomic.Value
	reason.Store("certificate pending")
	var draining atomic.Bool
	stop, _, err := startStatus(t.Context(), c, nil, func() {}, &draining, func() error {
		if v := reason.Load().(string); v != "" {
			return errors.New(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for _, state := range []string{"certificate pending", "certificate pending", "certificate expired", "", "", "certificate expired", ""} {
		reason.Store(state)
		response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz/ready", c.StatusPort))
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			t.Fatal(err)
		}
		want := http.StatusOK
		if state != "" {
			want = http.StatusServiceUnavailable
		}
		if response.StatusCode != want {
			t.Fatalf("status %d, want %d", response.StatusCode, want)
		}
	}
	if strings.Count(logs.String(), "gateway is waiting for readiness") != 2 ||
		strings.Count(logs.String(), "gateway is not ready") != 1 ||
		strings.Count(logs.String(), "gateway is ready") != 2 {
		t.Fatal(logs.String())
	}
	if !strings.Contains(logs.String(), "certificate pending") ||
		!strings.Contains(logs.String(), "certificate expired") {
		t.Fatal(logs.String())
	}
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		want := "INFO"
		if record["msg"] == "gateway is not ready" {
			want = "WARN"
		}
		if record["level"] != want {
			t.Fatalf("readiness transition level = %v, want %s: %s", record["level"], want, line)
		}
	}
}
func TestTrustBundleLogRecovery(t *testing.T) {
	logs := captureGatewayLogs(t)
	issuer := newTestCA(t)
	c := testConfig(t)
	c.RootCertFile = filepath.Join(t.TempDir(), "root.pem")
	c.metrics = newAgentMetrics()
	if err := os.WriteFile(c.RootCertFile, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	m := &identityManager{config: c, root: rootSecret(issuer.root)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	changed := make(chan struct{}, 1)
	go func() {
		defer close(done)
		m.watchRoots(ctx, changed)
	}()
	defer func() {
		cancel()
		<-done
	}()
	deadline := time.Now().Add(5 * time.Second)
	for testutil.ToFloat64(c.metrics.rootReloadFailures) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("root watcher did not retry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	bundle := append(bytes.Clone(issuer.root), newTestCA(t).root...)
	if err := os.WriteFile(c.RootCertFile, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("root update not delivered")
	}
	cancel()
	<-done
	if strings.Count(logs.String(), "trust bundle reload failed") != 1 ||
		strings.Count(logs.String(), "trust bundle reload recovered") != 1 ||
		strings.Count(logs.String(), "trust bundle updated") != 1 {
		t.Fatal(logs.String())
	}
}

func TestCertificateFailureLogsRemainingValidity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
	}{
		{"initial issuance", 0},
		{"valid certificate", time.Hour},
		{"expired certificate", -time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureGatewayLogs(t)
			issuer := newTestCA(t)
			issuer.fail.Store(true)
			c := testConfig(t)
			c.CAAddress = issuer.serve(t)
			c.ECCCurve = "P256"
			c.RootCertFile = filepath.Join(t.TempDir(), "root.pem")
			c.CARootCertFile = c.RootCertFile
			c.TokenFile = filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(c.RootCertFile, issuer.root, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(c.TokenFile, []byte("test-token"), 0600); err != nil {
				t.Fatal(err)
			}
			m := &identityManager{config: c, root: rootSecret(issuer.root), done: make(chan struct{})}
			if tc.lifetime != 0 {
				m.expires = time.Now().Add(tc.lifetime)
			}
			ctx, cancel := context.WithCancel(t.Context())
			go m.run(ctx)
			defer func() {
				cancel()
				<-m.done
			}()
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(logs.String(), "gateway certificate renewal failed") {
				if time.Now().After(deadline) {
					t.Fatal("missing certificate failure log")
				}
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			<-m.done
			for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
				var record map[string]any
				if err := json.Unmarshal([]byte(line), &record); err != nil {
					t.Fatal(err)
				}
				if record["msg"] != "gateway certificate renewal failed" {
					continue
				}
				remaining, ok := record["certificate_remaining"].(float64)
				if !ok || record["certificate_valid"] != (tc.lifetime > 0) ||
					(tc.lifetime == 0 && remaining != 0) || (tc.lifetime > 0 && remaining <= 0) ||
					(tc.lifetime < 0 && remaining >= 0) {
					t.Fatalf("incorrect certificate risk information: %s", line)
				}
			}
		})
	}
}

func TestSDSNackLogFields(t *testing.T) {
	logs := captureGatewayLogs(t)
	s := &localSDS{identity: &identityManager{}}
	s.recordNack(
		&discovery.DiscoveryRequest{
			ResourceNames: []string{"default"},
			ResponseNonce: "nonce-1",
			ErrorDetail: &rpcstatus.Status{
				Code:    int32(codes.InvalidArgument),
				Message: "sensitive certificate contents",
			},
		},
	)
	var record map[string]any
	if err := json.Unmarshal([]byte(logs.String()), &record); err != nil {
		t.Fatal(err)
	}
	if record["nonce"] != "nonce-1" || record["code"] != float64(codes.InvalidArgument) ||
		!strings.Contains(logs.String(), "default") ||
		strings.Contains(logs.String(), "sensitive certificate") {
		t.Fatal(logs.String())
	}
}
func TestRuntimeFailureLogsJSON(t *testing.T) {
	logs := captureGatewayLogs(t)
	t.Setenv("AGENTIO_GATEWAY_CONFIG", "{\"logAsJSON\":true}")
	t.Setenv("POD_NAME", "")
	if err := Command(t.Context(), nil, io.Discard, logs); err == nil {
		t.Fatal("expected invalid runtime identity")
	}
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("non-JSON log: %s", line)
		}
	}
	if strings.Count(logs.String(), "gateway agent failed") != 1 ||
		!strings.Contains(logs.String(), "\"level\":\"ERROR\"") {
		t.Fatal(logs.String())
	}
}
