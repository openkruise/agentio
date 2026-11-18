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
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestFixtureValidatesRealHeaderMutation(t *testing.T) {
	server, err := makeEPE(1)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	extpb.RegisterExternalProcessorServer(grpcServer, server)
	done := make(chan error, 1)
	go func() { done <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	})
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	stream, err := extpb.NewExternalProcessorClient(conn).Process(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	err = stream.Send(
		&extpb.ProcessingRequest{
			Attributes: map[string]*structpb.Struct{
				"envoy.filters.http.ext_proc": {
					Fields: map[string]*structpb.Value{
						"filter_state['agentio.workload.uid']": structpb.NewStringValue("bench-uid"),
					},
				},
			},
			Request: &extpb.ProcessingRequest_RequestHeaders{
				RequestHeaders: &extpb.HttpHeaders{Headers: &corepb.HeaderMap{Headers: []*corepb.HeaderValue{
					{
						Key:      ":method",
						RawValue: []byte("GET"),
					},
					{Key: ":path", RawValue: []byte("/")},
					{Key: ":authority", RawValue: []byte("bench.test")},
					{Key: ":scheme", RawValue: []byte("http")},
				}}},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	mutation := resp.GetRequestHeaders().GetResponse().GetHeaderMutation().GetSetHeaders()
	if len(mutation) != 1 || mutation[0].GetHeader().GetKey() != "x-policy" ||
		string(mutation[0].GetHeader().GetRawValue()) != "applied" {
		t.Fatalf("missing mutation: %v", resp)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadChecksOriginAndPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(origin))
	defer srv.Close()
	if err := runLoad(srv.URL, 8, 2, 0, 1024, false, ""); err != nil {
		t.Fatal(err)
	}
	if err := runLoad(srv.URL, 1, 1, 0, 0, true, ""); err == nil {
		t.Fatal("missing policy was accepted")
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	req.Header.Set("X-Policy", "applied")
	rec := httptest.NewRecorder()
	origin(rec, req)
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil || string(body) != "ok\n" || rec.Header().Get("X-Policy") != "applied" {
		t.Fatalf("invalid origin response: %q %v", body, err)
	}
}

func TestLoadSetsUpstreamAuthority(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.example.test:8443" {
			t.Errorf("Host = %q", r.Host)
			http.Error(w, "wrong Host", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := runLoad(srv.URL, 2, 1, 0, 0, false, "api.example.test:8443"); err != nil {
		t.Fatal(err)
	}
}
