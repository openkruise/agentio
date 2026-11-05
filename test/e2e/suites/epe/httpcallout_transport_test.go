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

package epe

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	extpb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

type deployedCalloutConnections struct {
	Connections map[string]struct {
		Protocol int
		Active   int
		Peak     int
		Calls    int
		Path     string
		Closed   bool
	}
	Refused int
}

// Exercise the deployed ConfigMap watcher independently of Envoy's message
// timeout. The enclosing test covers the complete Envoy traffic path.
func testDeployedCalloutTransport(
	t *testing.T,
	environment *e2e.Environment,
	scope *kube.ResourceScope,
	name, admin, observer, origin string,
) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	namespace := resolvedAgentioConfig.Namespace
	path := "/origin/transport"
	e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
		"Kind":   "SecurityProfile",
		"Name":   name + "-transport",
		"Client": trafficFixture.Client.Name(),
		"Path":   path,
		"Action": "{provider: {name: transport}, failStrategy: Block, request: {}}",
	}, httpCalloutProfileYAML).ApplyOrFail(t, kube.CreateOnly)
	harness.RetryAssertion(t, time.Minute, 100*time.Millisecond, func() error {
		var listing struct{ Profiles []struct{ Name string } }
		if err := readCalloutJSON(ctx, admin+"/debug/profiles", &listing); err != nil {
			return err
		}
		for _, p := range listing.Profiles {
			if p.Name == name+"-transport" {
				return nil
			}
		}
		return fmt.Errorf("transport profile not compiled")
	})
	conn, err := grpc.NewClient(
		epeForwardPort(t, environment, namespace, name, 9002),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	probe := &egressEPE{
		client:    extpb.NewExternalProcessorClient(conn),
		pod:       trafficFixture.Client.WorkloadsOrFail(t)[0].Name,
		namespace: trafficFixture.Namespace.Name(),
	}
	request := func(timeout time.Duration) error {
		callCtx, stop := context.WithTimeout(ctx, timeout)
		defer stop()
		stream, err := probe.client.Process(callCtx)
		if err != nil {
			return err
		}
		req := probe.request(name+"-http."+namespace+".svc.cluster.local:8080", path, true)
		req.Attributes["envoy.filters.http.ext_proc"].Fields["filter_state['sandbox.labels']"] = structpb.NewStringValue(
			base64.StdEncoding.EncodeToString([]byte("app=" + trafficFixture.Client.Name())),
		)
		if err = stream.Send(req); err != nil {
			return err
		}
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		if resp.GetImmediateResponse() != nil {
			return fmt.Errorf("callout rejected: %v", resp.GetImmediateResponse())
		}
		if resp.GetRequestHeaders() == nil {
			return fmt.Errorf("missing request headers response")
		}
		return stream.CloseSend()
	}
	stats := func() deployedCalloutConnections {
		t.Helper()
		var v deployedCalloutConnections
		if err := readCalloutJSON(ctx, observer+"/transport", &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := stats()
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			if err := request(5 * time.Second); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	after := stats()
	total := 0
	for addr, c := range after.Connections {
		total += c.Calls - before.Connections[addr].Calls
		if _, old := before.Connections[addr]; !old {
			if c.Protocol != 2 || c.Peak > 4 {
				t.Errorf("cold connection %s: %+v", addr, c)
			}
		}
	}
	if total != 64 || after.Refused != before.Refused {
		t.Fatalf("cold calls=%d refused=%d", total, after.Refused-before.Refused)
	}
	apply := func(raw string) {
		t.Helper()
		_, err := scope.ApplyInNamespace(
			ctx,
			namespace,
			&unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "v1",
					"kind":       "ConfigMap",
					"metadata":   map[string]any{"name": name},
					"data":       map[string]any{"config": raw},
				},
			},
			kube.ReconcileOwned,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	update := func(protocol, endpoint string) {
		t.Helper()
		raw := fmt.Sprintf(
			"extensionProviders:\n- name: transport\n  httpCallout:\n    url: %q\n    timeout: 30s\n    protocol: %s\n",
			origin+endpoint,
			protocol,
		)
		if protocol == "HTTP2" {
			raw += "    http2: {maxConcurrentStreams: 2}\n"
		}
		apply(raw)
	}
	// A held request proves the watcher installed the new generation, without
	// sleeps that assume informer propagation has completed.
	update("HTTP2", "/hold")
	var held atomic.Bool
	slowDone := make(chan error, 1)
	go func() {
		for {
			err := request(30 * time.Second)
			if err != nil || held.Load() {
				slowDone <- err
				return
			}
			select {
			case <-ctx.Done():
				slowDone <- ctx.Err()
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	var old string
	harness.RetryAssertion(t, 10*time.Second, 20*time.Millisecond, func() error {
		state := stats()
		for addr, c := range state.Connections {
			if c.Active > 0 && c.Path == "/hold" {
				old = addr
				held.Store(true)
				return nil
			}
		}
		return fmt.Errorf("waiting for held callout")
	})
	update("HTTP1", "/continue")
	harness.RetryAssertion(t, 10*time.Second, 50*time.Millisecond, func() error {
		if err := request(500 * time.Millisecond); err != nil {
			return err
		}
		state := stats()
		for addr, c := range state.Connections {
			if c.Protocol == 1 && c.Calls > after.Connections[addr].Calls {
				return nil
			}
		}
		return fmt.Errorf("new HTTP1 config not observed")
	})
	if stats().Connections[old].Closed {
		t.Fatal("configuration update closed active old connection")
	}
	release := func(addr string) {
		t.Helper()
		releaseReq, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			observer+"/release?connection="+url.QueryEscape(addr),
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(releaseReq)
		if err != nil {
			t.Fatal(err)
		}
		if err = response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 204 {
			t.Fatalf("release: %s", response.Status)
		}
	}
	release("")
	select {
	case err := <-slowDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	harness.RetryAssertion(t, 5*time.Second, 20*time.Millisecond, func() error {
		if !stats().Connections[old].Closed {
			return fmt.Errorf("old connection remains open after response")
		}
		return nil
	})

	testDeployedCalloutLimits(t, origin, apply, request, stats, release)
}
