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
package extproc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/contentguard"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// Identity injection is confined to this transport fixture. Production caller
// identity extraction is covered separately; all processing uses Server.Process.
type fixtureIdentityStream struct {
	extProcPb.ExternalProcessor_ProcessServer
}

func (s fixtureIdentityStream) Recv() (*extProcPb.ProcessingRequest, error) {
	r, err := s.ExternalProcessor_ProcessServer.Recv()
	if err == nil && r.GetRequestHeaders() != nil {
		r.Attributes = map[string]*structpb.Struct{attributes.ExtProcAttrsKey: {Fields: map[string]*structpb.Value{
			attributes.FilterStateWorkloadName:      structpb.NewStringValue("fixture"),
			attributes.FilterStateWorkloadNamespace: structpb.NewStringValue("test"),
		}}}
		// Force both a complete body and a partial body to arrive before the
		// header response in the cases below.
		time.Sleep(100 * time.Millisecond)
	}
	return r, err
}

type fixtureIdentityServer struct{ *Server }

func (s fixtureIdentityServer) Process(stream extProcPb.ExternalProcessor_ProcessServer) error {
	return s.Server.Process(fixtureIdentityStream{stream})
}

type contentRecordChannel chan filter.ContentRecord

func (c contentRecordChannel) Log(_ context.Context, st *filter.Stream, _ *filter.StreamInfo) {
	r, _ := st.Info.Content(filter.UnitID{Name: "capture"})
	c <- r
}

// TestEnvoyStreamedCapture runs only when a real Envoy binary is explicitly
// supplied. It exercises dynamic mode negotiation, not a static-streamed fixture.
func TestEnvoyStreamedCapture(t *testing.T) {
	binary := os.Getenv("EPE_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set EPE_ENVOY_BINARY for real Envoy transport coverage")
	}
	probe := filter.Define(filter.Descriptor[bool]{
		Name:         "streamed-fixture",
		Phases:       filter.DispatchedPhases,
		SubscribesOf: func(bool) filter.Phase { return filter.PhaseResponseHeaders },

		New: func(filter.RuleConfig[bool]) filter.Filter { return &streamingFixtureFilter{} },
	}, func(json.RawMessage) (bool, error) { return true, nil })
	regs, err := filter.Build(contentguard.Definition(), probe)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := regs[0].Parse(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	records := make(contentRecordChannel, 10)
	server := NewServer(ServerDeps{
		Registrations: regs,
		StreamLoggers: []filter.StreamLogger{records},
		Resolve: func(_ context.Context, _ inputs.Pod, req *httpreq.HTTPRequest) (engine.Resolution, error) {
			cfgs := []any{cfg, nil}
			if req.Path != "/" {
				cfgs[1] = true
			}
			return engine.Resolution{Units: []engine.Unit{{ID: filter.UnitID{Name: "capture"}, Cfgs: cfgs}}}, nil
		},
	})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	extProcPb.RegisterExternalProcessorServer(grpcServer, fixtureIdentityServer{server})
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Log(err)
		}
	}()
	t.Cleanup(grpcServer.Stop)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("X-Request-Trailer", r.Trailer.Get("X-End"))
		if r.URL.Path == "/deny-response" {
			if _, err := io.WriteString(w, "good"); err != nil {
				t.Log(err)
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
			if _, err := io.WriteString(w, "BLOCK"); err != nil {
				t.Log(err)
			}
			return
		}
		if r.URL.Path == "/response-trailers" {
			w.Header().Set("Trailer", "X-End")
		}
		if _, err := w.Write(body); err != nil {
			t.Log(err)
		}
		if r.URL.Path == "/response-trailers" {
			w.Header().Set("X-End", "yes")
		}
	}))
	t.Cleanup(origin.Close)
	_, originPort, err := net.SplitHostPort(origin.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, grpcPort, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	if err := reserve.Close(); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`{
 "static_resources": {
  "listeners":[{"name":"test","address":{"socket_address":{"address":"127.0.0.1","port_value":%d}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{
   "@type":"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager","stat_prefix":"test","http_protocol_options":{"enable_trailers":true},
   "route_config":{"name":"test","virtual_hosts":[{"name":"test","domains":["*"],"routes":[{"match":{"prefix":"/"},"route":{"cluster":"origin","timeout":"5s"}}]}]},
   "http_filters":[{"name":"envoy.filters.http.ext_proc","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor",
    "grpc_service":{"envoy_grpc":{"cluster_name":"epe"}},"allow_mode_override":true,"failure_mode_allow":false,"message_timeout":"2s",
    "processing_mode":{"request_header_mode":"SEND","response_header_mode":"SKIP","request_body_mode":"NONE","response_body_mode":"NONE"}}},
    {"name":"envoy.filters.http.router","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]
  }}]}]}],
  "clusters":[
   {"name":"origin","http_protocol_options":{"enable_trailers":true},"connect_timeout":"1s","type":"STATIC","load_assignment":{"cluster_name":"origin","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":%s}}}}]}]}},
   {"name":"epe","connect_timeout":"1s","type":"STATIC","http2_protocol_options":{},"load_assignment":{"cluster_name":"epe","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":%s}}}}]}]}}
  ]
 }
}`, port, originPort, grpcPort)
	path := filepath.Join(t.TempDir(), "envoy.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", path, "--concurrency", "1", "--log-level", "error", "--disable-hot-restart")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Log(err)
		}
		if err := cmd.Wait(); err != nil {
			if exitErr, ok := errors.AsType[*exec.ExitError](err); !ok || exitErr == nil {
				t.Error(err)
			}
		}
	})
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Envoy did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	client := &http.Client{Timeout: 7 * time.Second}
	defer client.CloseIdleConnections()
	payload := []byte(`{"model":"qwen","messages":[{"role":"user","content":"hello"}]}`)
	for _, scenario := range []string{"complete-before-headers", "partial-before-headers", "trailers", "large-body"} {
		t.Run(scenario, func(t *testing.T) {
			requestPayload := payload
			wantStatus := "complete"
			if scenario == "large-body" {
				requestPayload = []byte(
					`{"model":"qwen","messages":[{"role":"user","content":"` + strings.Repeat("x", 2<<20) + `"}]}`,
				)
				wantStatus = "too_large"
			}
			var reader io.Reader = bytes.NewReader(requestPayload)
			var writer *io.PipeWriter
			if scenario == "partial-before-headers" || scenario == "trailers" {
				var pipe *io.PipeReader
				pipe, writer = io.Pipe()
				reader = pipe
			}
			req, err := http.NewRequest(http.MethodPost, "http://"+address+"/", reader)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			if scenario == "trailers" {
				req.Trailer = http.Header{"X-End": []string{"yes"}}
			}
			if writer != nil {
				go func() {
					if _, err := writer.Write(payload[:10]); err != nil {
						if closeErr := writer.CloseWithError(err); closeErr != nil {
							t.Log(closeErr)
						}
						return
					}
					time.Sleep(300 * time.Millisecond)
					if _, err := writer.Write(payload[10:]); err != nil {
						if closeErr := writer.CloseWithError(err); closeErr != nil {
							t.Log(closeErr)
						}
						return
					}
					if err := writer.Close(); err != nil {
						t.Log(err)
					}
				}()
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			got, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != 200 || !bytes.Equal(got, requestPayload) {
				t.Fatalf("response: status=%d bytes=%d err=%v", resp.StatusCode, len(got), err)
			}
			if scenario == "trailers" && resp.Header.Get("X-Request-Trailer") != "yes" {
				t.Fatal("request trailer lost")
			}
			select {
			case record := <-records:
				if record.Status != wantStatus || record.BytesSeen != int64(len(requestPayload)) {
					t.Fatalf("capture: %+v", record)
				}
			case <-time.After(time.Second):
				t.Fatal("no capture record")
			}
		})
	}
	for _, path := range []string{"/response", "/response-trailers", "/mutate-response", "/deny-request", "/deny-response"} {
		t.Run(path, func(t *testing.T) {
			requestBody := payload
			if path == "/deny-request" {
				requestBody = bytes.ReplaceAll(payload, []byte("hello"), []byte("BLOCK"))
			}
			resp, err := client.Post("http://"+address+path, "application/json", bytes.NewReader(requestBody))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			got, readErr := io.ReadAll(resp.Body)
			switch path {
			case "/deny-request":
				if resp.StatusCode != 403 {
					t.Fatalf("status=%d body=%q", resp.StatusCode, got)
				}
			case "/deny-response":
				if readErr == nil || resp.StatusCode != 200 || string(got) != "good" {
					t.Fatalf("late rejection: status=%d body=%q err=%v", resp.StatusCode, got, readErr)
				}
			case "/mutate-response":
				if readErr != nil || resp.StatusCode != 200 || strings.TrimRight(string(got), "!") != string(payload) ||
					!bytes.HasSuffix(got, []byte("!")) {
					t.Fatalf("mutation: status=%d body=%q err=%v", resp.StatusCode, got, readErr)
				}
			default:
				if readErr != nil || resp.StatusCode != 200 || !bytes.Equal(got, payload) {
					t.Fatalf("response: status=%d body=%q err=%v", resp.StatusCode, got, readErr)
				}
				if path == "/response-trailers" && resp.Trailer.Get("X-End") != "yes" {
					t.Fatalf("trailers: %v", resp.Trailer)
				}
			}
			select {
			case <-records:
			case <-time.After(time.Second):
				t.Fatal("missing stream audit")
			}
		})
	}
}
