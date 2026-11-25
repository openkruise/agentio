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
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

const auditExtension = "agentio.body_processing"

// Use the same AgentioConfig compiler as the control plane for every revision.
func auditResources(t *testing.T, yaml, revision string) (*discovery.Resource, *anypb.Any) {
	t.Helper()
	settings, err := config.ApplyAgentioConfig(yaml, &configv1.AgentioConfig{})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := networking.Build(networking.Inputs{
		Gateway:          model.Gateway{Namespace: "test", Name: "egress", Config: &configv1.EgressGateway{}},
		TrustDomain:      "cluster.local",
		DiscoveryAddress: "agentiod:15012",
		BodyProcessing:   settings.BodyProcessing,
	})
	if err != nil {
		t.Fatal(err)
	}
	var extension *discovery.Resource
	var forward *anypb.Any
	for _, r := range resources {
		switch {
		case r.Key.TypeURL == extensionType && r.XDSName == auditExtension:
			extension = &discovery.Resource{Name: r.XDSName, Version: revision, Resource: r.Value}
		case r.Key.TypeURL == model.ListenerType && r.XDSName == networking.MainForward:
			forward = r.Value
		}
	}
	if extension == nil || forward == nil {
		t.Fatal("missing generated audit extension or forwarding listener")
	}
	return extension, forward
}

// Reuse the gateway's ADS validator and the forwarding HCM's ECDS slot and logger.
// The bootstrap's local HTTP listener routes the test requests to the SSE fixture.
func auditBootstrap(t *testing.T, c Config, forward *anypb.Any) []byte {
	t.Helper()
	b, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	b.Admin = nil
	b.DynamicResources.LdsConfig, b.DynamicResources.CdsConfig = nil, nil
	b.StaticResources.Listeners = b.StaticResources.Listeners[:1]
	f := b.StaticResources.Listeners[0].FilterChains[0].Filters[0]
	local := &hcm.HttpConnectionManager{}
	if err := f.GetTypedConfig().UnmarshalTo(local); err != nil {
		t.Fatal(err)
	}
	l := &listener.Listener{}
	if err := forward.UnmarshalTo(l); err != nil {
		t.Fatal(err)
	}
	generated := &hcm.HttpConnectionManager{}
	if err := l.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(generated); err != nil {
		t.Fatal(err)
	}
	for _, filter := range generated.HttpFilters {
		if filter.Name == auditExtension {
			local.HttpFilters = append([]*hcm.HttpFilter{filter}, local.HttpFilters...)
		}
	}
	local.AccessLog = generated.AccessLog
	route := local.GetRouteConfig().VirtualHosts[0].Routes[0].GetMatch()
	route.PathSpecifier = &routev3.RouteMatch_Path{Path: "/v1/chat/completions"}
	if err := f.GetTypedConfig().MarshalFrom(local); err != nil {
		t.Fatal(err)
	}
	data, err := protojson.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCommunityEnvoyBodyProcessingECDS(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY to test the gateway image")
	}
	const rules = `bodyProcessing:
  filterChains:
    - name: llm
      parser: {llm: {}}
      filters:
        - audit:
            format:
              json:
                stream: "%%REQ(X-TEST-STREAM)%%"
                revision: "%s"
                %s: "%%EVENT(llm.answer)%%"
`
	standby, forward := auditResources(t, "bodyProcessing: {}", "standby")
	v1, _ := auditResources(t, fmt.Sprintf(rules, "v1", "oldAnswer"), "v1")
	v2, _ := auditResources(t, fmt.Sprintf(rules, "v2", "newAnswer"), "v2")
	invalid, _ := auditResources(t, "bodyProcessing: {filterChains: null}", "invalid")
	unsupportedFormatter, _ := auditResources(t, fmt.Sprintf(rules, "%CEL('v2')%", "newAnswer"), "unsupported-formatter")

	const first = `data: {"model":"m","choices":[{"index":0,"delta":{"content":"first"}}]}` + "\n\n"
	const last = `data: {"model":"m","choices":[{"index":0,"delta":{"content":"last"},"finish_reason":"stop"}]}` +
		"\n\ndata: [DONE]\n\n"
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := io.WriteString(w, first); err != nil {
			t.Error(err)
			return
		}
		w.(http.Flusher).Flush()
		if r.Header.Get("X-Test-Stream") == "old" {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if _, err := io.WriteString(w, last); err != nil {
			t.Error(err)
		}
	}))
	defer origin.Close()
	c := testConfig(t)
	c.IP = "127.0.0.1"
	ports, releasePorts := reservePorts(t, 1)
	c.EnvoyStatusPort, c.StatusPort = ports[0], origin.Listener.Addr().(*net.TCPAddr).Port
	control := newExtensionDiscovery()
	grpcServer := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, control)
	socket, err := net.Listen("unix", c.XDSSocket)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := grpcServer.Serve(socket); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	}()
	defer grpcServer.Stop()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config-yaml", string(auditBootstrap(t, c, forward)),
		"--concurrency", "1", "--disable-hot-restart", "--file-flush-interval-msec", "10", "-l", "warning")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	releasePorts()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		var exit *exec.ExitError
		if err := cmd.Wait(); err != nil && !errors.As(err, &exit) {
			t.Error(err)
		}
		if t.Failed() {
			t.Log(stderr.String())
		}
	}()
	control.publish(t, standby, "")

	addr := fmt.Sprintf("127.0.0.1:%d", ports[0])
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(conn)
	// RoundTrip on this one client connection cannot silently open a second connection.
	client, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	open := func(id string) io.ReadCloser {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/v1/chat/completions",
			strings.NewReader(`{"model":"m","messages":[],"stream":true}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Stream", id)
		resp, err := client.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			closeResource(resp.Body)
			t.Fatalf("stream %s: %s", id, resp.Status)
		}
		return resp.Body
	}
	logs := json.NewDecoder(stdout)
	finish := func(body io.ReadCloser, id, revision, column string) {
		t.Helper()
		defer closeResource(body)
		if _, err := io.Copy(io.Discard, body); err != nil {
			t.Fatal(err)
		}
		var row map[string]string
		if err := logs.Decode(&row); err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(row, map[string]string{"stream": id, "revision": revision, column: "firstlast"}) {
			t.Fatalf("stream %s: unexpected audit record %v", id, row)
		}
	}

	// Empty rules forward the response and leave stdout empty until the first audited stream finishes.
	idle := open("standby")
	forwarded, err := io.ReadAll(idle)
	closeResource(idle)
	if err != nil || string(forwarded) != first+last {
		t.Fatalf("standby forwarded %q: %v", forwarded, err)
	}
	control.publish(t, v1, "")
	old := open("old")
	prefix := make([]byte, len(first))
	if _, err := io.ReadFull(old, prefix); err != nil || string(prefix) != first {
		t.Fatalf("in-flight stream first frame %q: %v", prefix, err)
	}
	control.publish(t, v2, "")
	finish(open("new"), "new", "v2", "newAnswer")
	close(release)
	finish(old, "old", "v1", "oldAnswer")
	control.publish(t, invalid, auditExtension+": invalid type: null")
	control.publish(t, unsupportedFormatter, `field "revision": CEL: unsupported audit operator`)
	finish(open("after-nack"), "after-nack", "v2", "newAnswer")
}
