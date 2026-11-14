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
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"

	"github.com/openkruise/agentio/bench/load"
)

type responseFixture struct {
	extproc.UnimplementedExternalProcessorServer
}

func (responseFixture) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	uid := request.Attributes["envoy.filters.http.ext_proc"].Fields["filter_state['agentio.workload.uid']"].GetStringValue()
	code := typev3.StatusCode(453)
	if strings.HasSuffix(uid, "00001") {
		code = typev3.StatusCode_ServiceUnavailable
	}
	return stream.Send(&extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extproc.ImmediateResponse{Status: &typev3.HttpStatus{Code: code}},
	}})
}

func TestLoadCountsUnexpectedResponses(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(server, responseFixture{})
	go func() {
		if err := server.Serve(listener); err != nil {
			t.Error(err)
		}
	}()
	defer server.Stop()
	output, err := os.CreateTemp(t.TempDir(), "result")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := output.Close(); err != nil {
			t.Error(err)
		}
	}()
	old := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = old }()
	err = run(listener.Addr().String(), "ns", "Kubernetes", "/block", 453, 2, false, load.Config{
		Requests:    8,
		Identities:  2,
		Concurrency: 4,
		Duration:    time.Second,
	})
	if err == nil {
		t.Fatal("unexpected statuses did not fail the run")
	}
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		load.Result
		Connections int            `json:"connections"`
		Responses   map[string]int `json:"responses"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Operations != 8 || result.Errors != 4 || result.Connections != 2 || result.Responses["http_453"] != 4 ||
		result.Responses["http_503"] != 4 {
		t.Fatalf("incorrect error accounting: %+v", result)
	}
}

type sandboxFixture struct {
	extproc.UnimplementedExternalProcessorServer
	received chan *extproc.ProcessingRequest
}

func (s sandboxFixture) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	s.received <- request
	return stream.Send(
		&extproc.ProcessingResponse{
			Response: &extproc.ProcessingResponse_ImmediateResponse{
				ImmediateResponse: &extproc.ImmediateResponse{Status: &typev3.HttpStatus{Code: typev3.StatusCode(451)}},
			},
		},
	)
}
func TestSandboxInventoryCrossesNamespaceBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan *extproc.ProcessingRequest, 2)
	server := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(server, sandboxFixture{received: received})
	go func() {
		if err := server.Serve(listener); err != nil {
			t.Error(err)
		}
	}()
	defer server.Stop()
	if err := run(
		listener.Addr().String(),
		"fixture",
		"Kubernetes",
		"/deny",
		451,
		1,
		true,
		load.Config{Requests: 2, Identities: 2, Offset: 999, Concurrency: 1, Duration: time.Second},
	); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Kubernetes//Pod/fixture-000/sandbox-000999": "kruise:sandbox-000999",
		"Kubernetes//Pod/fixture-001/sandbox-001000": "kruise:sandbox-001000",
	}
	for range 2 {
		request := <-received
		fields := request.Attributes["envoy.filters.http.ext_proc"].Fields
		uid := fields["filter_state['agentio.workload.uid']"].GetStringValue()
		sandbox := fields["filter_state['agentio.sandbox.id']"].GetStringValue()
		if expected, ok := want[uid]; !ok || sandbox != expected {
			t.Fatalf("wrong workload or Sandbox identity: %q %q", uid, sandbox)
		}
		delete(want, uid)
	}
	if len(want) != 0 {
		t.Fatal("missing identities", want)
	}
}
