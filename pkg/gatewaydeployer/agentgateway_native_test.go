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

package gatewaydeployer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/internal/testutil"
)

func TestAgentgatewayNativeGeneratedConfiguration(t *testing.T) {
	binary := os.Getenv("AGENTIO_AGENTGATEWAY_BINARY")
	schema := os.Getenv("AGENTIO_AGENTGATEWAY_SCHEMA")
	if binary == "" && schema == "" {
		t.Skip("set AGENTIO_AGENTGATEWAY_BINARY or AGENTIO_AGENTGATEWAY_SCHEMA to validate generated configuration")
	}
	gw, _ := agentgatewayFixture()
	for _, settings := range []string{
		"{}",
		`http: {routing: {fallback: {timeout: 10s, retries: {attempts: 2, retryOn: '503,unavailable', perTryTimeout: 1s, backoff: 0.01s}}, hostOverrides: [{hosts: ['*.example.com'], settings: {timeout: 30s}}]}}`,
		`serviceEntries: [{hosts: [api.example], endpoints: [{address: 192.0.2.1}, {address: 192.0.2.2}]}]`,
		`extProc: {service: processor.example, port: 9002, response: {headerMode: SEND}}`,
		`http: {acceptHttp10: false}`,
		`http: {streamIdleTimeout: 0s}
tcp: {idleTimeout: 0s}
tls: {origination: {minProtocolVersion: TLSV1_2, maxProtocolVersion: TLSV1_3}}`,
		`extProc: {serviceRef: {name: processor, namespace: system}, request: {attributes: [request.method]}, response: {headerMode: SEND, attributes: [response.code, response.headers]}}`,
		`extProc: {service: processor.example, request: {attributes: ["filter_state['agentio.workload.uid']"]}}`,
	} {
		t.Run(settings, func(t *testing.T) {
			content, err := agentgatewayEgressConfig(
				agentgatewaySettings(t, settings),
				extractServicePorts(*gw),
				agentgatewayConfigInputs{},
			)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if schema != "" {
				validateAgentgatewaySchema(t, ctx, schema, content)
			}
			if binary == "" {
				return
			}
			if output, err := exec.CommandContext(ctx, binary, "--validate-only", "-c", content).
				CombinedOutput(); err != nil {
				t.Fatalf("native validation failed: %v\n%s", err, output)
			}
		})
	}
}

func validateAgentgatewaySchema(t *testing.T, ctx context.Context, schema, content string) {
	t.Helper()
	python := valueOrDefault(os.Getenv("AGENTIO_SCHEMA_PYTHON"), "python3")
	command := exec.CommandContext(
		ctx,
		python,
		"-c",
		`import json,sys; from jsonschema import Draft202012Validator; Draft202012Validator(json.load(open(sys.argv[1]))).validate(json.load(sys.stdin))`,
		schema,
	)
	command.Stdin = bytes.NewBufferString(content)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("v1.7.0 schema validation failed: %v\n%s", err, output)
	}
}

// The official generic CONNECT transport supplies the original destination to
// the same generated internal binds. Production HBONE/CA coverage lives in the e2e suite.
func TestAgentgatewayNativeGeneratedHTTP(t *testing.T) {
	binary := os.Getenv("AGENTIO_AGENTGATEWAY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_AGENTGATEWAY_BINARY to run native forwarding")
	}
	var attempts atomic.Int32
	var exhausted atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Host", r.Host)
		w.Header().Set("X-Origin-Processor", r.Header.Get("X-Generated-Request"))
		if r.URL.Path == "/retry" && attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/exhaust" {
			exhausted.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/slow" {
			time.Sleep(150 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()
	processorListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	processor := grpc.NewServer()
	var sawAttributes atomic.Bool
	extproc.RegisterExternalProcessorServer(processor, &nativeTestProcessor{attributes: &sawAttributes})
	serveErr := make(chan error, 1)
	go func() { serveErr <- processor.Serve(processorListener) }()
	t.Cleanup(func() {
		processor.Stop()
		if err := <-serveErr; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	})
	_, rawPort, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	gw, _ := agentgatewayFixture()
	ports := append(extractServicePorts(*gw), corev1.ServicePort{Name: "origin", Port: int32(port)})
	settings := agentgatewaySettings(t, `
serviceEntries:
- hosts: [static.invalid, retry.invalid, slow.invalid]
  endpoints: [{address: 127.0.0.1}]
http:
  routing:
    fallback:
      retries: {attempts: 2, retryOn: '503', backoff: 0.001s}
    hostOverrides:
    - hosts: [slow.invalid]
      settings: {timeout: 0.02s}
`)
	settings.ExtProc = &configv1.ExtProcProvider{
		Service:  "127.0.0.1",
		Port:     uint32(processorListener.Addr().(*net.TCPAddr).Port),
		Response: &configv1.ProcessingModeOptions{HeaderMode: configv1.HeaderSendMode_SEND},
	}
	content, err := agentgatewayEgressConfig(settings, ports, agentgatewayConfigInputs{})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		t.Fatal(err)
	}
	address := nativeTestAddress(t)
	_, gatewayPort, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	gatewayPortNumber, err := strconv.Atoi(gatewayPort)
	if err != nil {
		t.Fatal(err)
	}
	outer := config["binds"].([]any)[0].(map[string]any)
	outer["port"] = gatewayPortNumber
	outer["protocol"] = "HTTP"
	outer["tunnelProtocol"] = "connect"
	outer["listeners"] = []any{map[string]any{
		"protocol": "HTTP",
		"routes":   []any{map[string]any{"policies": map[string]any{"directResponse": map[string]any{"status": 200}}}},
	}}
	ready := nativeTestAddress(t)
	config["config"] = map[string]any{
		"adminAddr":     "127.0.0.1:0",
		"statsAddr":     "127.0.0.1:0",
		"readinessAddr": ready,
		"dns":           map[string]any{"lookupFamily": "V4Only"},
		"backend":       map[string]any{"allowDynamicLoopback": true},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cmd := exec.CommandContext(ctx, binary, "-c", string(encoded))
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := cmd.Wait(); err != nil {
			t.Logf("native gateway stopped: %v", err)
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	client := &http.Client{Timeout: time.Second}
	testutil.WaitFor(t, 10*time.Second, func() bool {
		resp, err := client.Get("http://" + ready + "/healthz/ready")
		if err != nil {
			return false
		}
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
		return resp.StatusCode == http.StatusOK
	}, "native gateway readiness")
	for _, tc := range []struct {
		name   string
		host   string
		path   string
		status int
	}{
		{"Host selects upstream instead of original IP", "localhost", "/", 200},
		{"intercepted port overrides Host port", "localhost:1", "/", 200},
		{"static entry overrides DNS", "static.invalid", "/", 200},
		{"retry count excludes original attempt", "retry.invalid", "/retry", 200},
		{"retry budget stops after two retries", "retry.invalid", "/exhaust", 503},
		{"host override timeout", "slow.invalid", "/slow", 504},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := connection.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			transport := &http2.Transport{}
			cc, err := transport.NewClientConn(connection)
			if err != nil {
				t.Fatal(err)
			}
			target := net.JoinHostPort("192.0.2.1", rawPort)
			inner := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", tc.path, tc.host)
			reader, writer := io.Pipe()
			defer func() {
				if err := writer.Close(); err != nil {
					t.Error(err)
				}
			}()
			response, err := cc.RoundTrip(&http.Request{
				Method:        http.MethodConnect,
				URL:           &url.URL{Scheme: "http", Host: target},
				Host:          target,
				Body:          reader,
				ContentLength: -1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			if response.StatusCode != 200 {
				t.Fatalf("CONNECT returned %d", response.StatusCode)
			}
			if _, err := io.WriteString(writer, inner); err != nil {
				t.Fatal(err)
			}
			result, err := http.ReadResponse(bufio.NewReader(response.Body), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := result.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			if result.StatusCode != tc.status {
				t.Fatalf("HTTP status = %d, want %d", result.StatusCode, tc.status)
			}
			if tc.status == 200 && result.Header.Get("X-Origin-Host") != tc.host {
				t.Fatalf("Host was rewritten: %v", result.Header)
			}
			if tc.status == 200 &&
				(result.Header.Get("X-Origin-Processor") != "yes" || result.Header.Get("X-Generated-Response") != "yes") {
				t.Fatalf("generated ext-proc settings did not process both header phases: %v", result.Header)
			}
		})
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("origin attempts = %d, want 3", got)
	}
	if got := exhausted.Load(); got != 3 {
		t.Fatalf("exhausted retry budget made %d attempts, want 3", got)
	}
	if !sawAttributes.Load() {
		t.Fatal("ext-proc did not receive destination attributes")
	}
}

type nativeTestProcessor struct {
	extproc.UnimplementedExternalProcessorServer
	attributes *atomic.Bool
}

func (p *nativeTestProcessor) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	for {
		request, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := "x-generated-response"
		if request.GetRequestHeaders() != nil {
			name = "x-generated-request"
			if request.Attributes["envoy.filters.http.ext_proc"].GetFields()["destination.port"].GetNumberValue() > 0 {
				p.attributes.Store(true)
			}
		}
		headers := &extproc.HeadersResponse{Response: &extproc.CommonResponse{
			HeaderMutation: &extproc.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{{
				Header: &corev3.HeaderValue{Key: name, RawValue: []byte("yes")},
			}}},
		}}
		response := &extproc.ProcessingResponse{}
		if request.GetRequestHeaders() != nil {
			response.Response = &extproc.ProcessingResponse_RequestHeaders{RequestHeaders: headers}
		} else {
			response.Response = &extproc.ProcessingResponse_ResponseHeaders{ResponseHeaders: headers}
		}
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func nativeTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
