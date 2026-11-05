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

package extensionprovider_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	fixture "github.com/openkruise/agentio/test/fixtures/httpcallout"
)

// This exercises network ext_proc streams, the production engine and a real
// HTTP provider. Kubernetes policy distribution is covered by TestEPEHTTPCallout.
func TestHTTPCalloutTransportE2E(t *testing.T) {
	var refused, calls atomic.Int64
	var mu sync.Mutex
	active := map[string]int{}
	peak := map[string]int{}
	closed := map[string]bool{}
	entered := make(chan string, 128)
	release := make(chan struct{})
	handler := &fixture.Handler{}
	// Immediate replies exercise concurrent HTTP/2 stream completion and reservation.
	endpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		mu.Lock()
		active[r.RemoteAddr]++
		peak[r.RemoteAddr] = max(peak[r.RemoteAddr], active[r.RemoteAddr])
		mu.Unlock()
		defer func() {
			mu.Lock()
			active[r.RemoteAddr]--
			mu.Unlock()
		}()
		if r.URL.Path == "/hold" {
			entered <- r.RemoteAddr
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if r.URL.Path == "/http1" && r.ProtoMajor != 1 {
			t.Errorf("new config used %s", r.Proto)
		}
		if r.URL.Path != "/http1" && r.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2, got %s", r.Proto)
		}
		r.URL.Path = "/continue"
		handler.ServeHTTP(w, r)
	}))
	endpoint.Config.Protocols = new(http.Protocols)
	endpoint.Config.Protocols.SetHTTP1(true)
	endpoint.Config.Protocols.SetUnencryptedHTTP2(true)
	endpoint.Config.HTTP2 = &http.HTTP2Config{
		MaxConcurrentStreams: 4,
		CountError: func(kind string) {
			if kind == "stream_REFUSED_STREAM_over_max_streams_race" {
				refused.Add(1)
			}
		},
	}
	endpoint.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			mu.Lock()
			closed[c.RemoteAddr().String()] = true
			mu.Unlock()
		}
	}
	endpoint.Start()
	defer endpoint.Close()
	registry := &extensionprovider.Registry{}
	defer registry.Close()
	apply := func(protocol, path string, streams int) {
		t.Helper()
		raw := fmt.Sprintf(
			"extensionProviders:\n- name: scanner\n  httpCallout:\n    url: %q\n    timeout: 5s\n    protocol: %s\n    connectionPool: {maxConnections: 4}\n",
			endpoint.URL+path,
			protocol,
		)
		if protocol != "HTTP1" {
			raw += fmt.Sprintf("    http2: {maxConcurrentStreams: %d}\n", streams)
		}
		cfg, err := extensionprovider.ApplyConfig(raw, &configv1.EPEConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if err = registry.Apply(cfg, nil); err != nil {
			t.Fatal(err)
		}
	}
	regs, err := filter.Build(httpcallout.NewDefinition(httpcallout.Deps{Client: httpcallout.NewHTTPClient(registry)}))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(
		map[string]any{
			"provider": "scanner",
			"request":  map[string]any{"headers": map[string]string{"mode": "none"}},
			"failOpen": false,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cfgs, errs := filter.Project(regs, map[string]json.RawMessage{regs[0].Name: raw})
	if errs[0] != nil {
		t.Fatal(errs[0])
	}
	server := extproc.NewServer(
		extproc.ServerDeps{
			Registrations:               regs,
			FailClosedOnMissingIdentity: true,
			Resolve: func(_ context.Context, subj subject.Subject, req *httpreq.HTTPRequest) (engine.Resolution, error) {
				scope := inputs.NewScope(
					inputs.RequestFrom(*req),
					inputs.WorkloadFromSubject(subj),
					inputs.Profile{Name: "transport", Namespace: "default"},
					inputs.Rule{Name: "callout"},
					nil,
				)
				return engine.Resolution{
					Units: []engine.Unit{
						{ID: filter.UnitID{Scope: "default/transport", Name: "callout"}, Scope: scope, Cfgs: cfgs},
					},
				}, nil
			},
		},
	)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	extpb.RegisterExternalProcessorServer(grpcServer, server)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Log(err)
		}
	}()
	defer grpcServer.Stop()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	client := extpb.NewExternalProcessorClient(conn)
	request := func() error {
		ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
		defer cancel()
		stream, err := client.Process(ctx)
		if err != nil {
			return err
		}
		headers := &extpb.HttpHeaders{
			EndOfStream: true,
			Headers: &corepb.HeaderMap{
				Headers: []*corepb.HeaderValue{
					{Key: ":method", RawValue: []byte("GET")},
					{Key: ":scheme", RawValue: []byte("http")},
					{Key: ":authority", RawValue: []byte("origin.test")},
					{Key: ":path", RawValue: []byte("/")},
				},
			},
		}
		attrs, err := structpb.NewStruct(
			map[string]any{
				attributes.FilterStateDownstreamPeerName:      "caller",
				attributes.FilterStateDownstreamPeerNamespace: "default",
			},
		)
		if err != nil {
			return err
		}
		err = stream.Send(
			&extpb.ProcessingRequest{
				Attributes: map[string]*structpb.Struct{attributes.ExtProcAttrsKey: attrs},
				Request:    &extpb.ProcessingRequest_RequestHeaders{RequestHeaders: headers},
			},
		)
		if err != nil {
			return err
		}
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		if resp.GetImmediateResponse() != nil {
			return fmt.Errorf("callout failed closed: %v", resp.GetImmediateResponse())
		}
		if resp.GetRequestHeaders() == nil {
			return fmt.Errorf("unexpected ext_proc response: %v", resp)
		}
		return stream.CloseSend()
	}
	t.Run("cold-start", func(t *testing.T) {
		apply("HTTP2", "/continue", 32)
		var wg sync.WaitGroup
		for range 128 {
			wg.Go(func() {
				if err := request(); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if calls.Load() != 128 || refused.Load() != 0 {
			t.Fatalf("calls=%d refused=%d", calls.Load(), refused.Load())
		}
		mu.Lock()
		defer mu.Unlock()
		for addr, n := range peak {
			if n > 4 {
				t.Errorf("%s peak=%d", addr, n)
			}
		}
	})
	t.Run("update-drains-old-pool", func(t *testing.T) {
		apply("HTTP2", "/hold", 2)
		result := make(chan error, 2)
		for range 2 {
			go func() { result <- request() }()
		}
		var old []string
		for range 2 {
			select {
			case addr := <-entered:
				old = append(old, addr)
			case <-time.After(6 * time.Second):
				t.Fatal("old calls never reached provider")
			}
		}
		apply("HTTP2", "/continue", 1)
		if err := request(); err != nil {
			t.Fatal(err)
		}
		apply("HTTP1", "/http1", 0)
		if err := request(); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		for _, addr := range old {
			if closed[addr] {
				t.Errorf("active old connection %s closed", addr)
			}
		}
		mu.Unlock()
		close(release)
		for range 2 {
			if err := <-result; err != nil {
				t.Error(err)
			}
		}
		deadline := time.Now().Add(time.Second)
		for {
			mu.Lock()
			done := true
			for _, addr := range old {
				done = done && closed[addr]
			}
			mu.Unlock()
			if done {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("old connections were not reclaimed after draining")
			}
			time.Sleep(time.Millisecond)
		}
	})
}
