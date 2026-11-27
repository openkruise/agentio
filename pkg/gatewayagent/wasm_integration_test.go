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
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	wasmhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"
	wasm "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

//go:embed testdata/header.wasm
var wasmFixture []byte

const extensionType = "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig"

type extensionDiscovery struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	updates chan *discovery.Resource
	acks    chan *discovery.DeltaDiscoveryRequest
}

func newExtensionDiscovery() *extensionDiscovery {
	return &extensionDiscovery{
		updates: make(chan *discovery.Resource, 1),
		acks:    make(chan *discovery.DeltaDiscoveryRequest, 1),
	}
}

func (s *extensionDiscovery) publish(t *testing.T, res *discovery.Resource, wantError string) {
	t.Helper()
	s.updates <- res
	select {
	case ack := <-s.acks:
		if wantError == "" {
			if ack.ErrorDetail != nil {
				t.Fatalf("ECDS %s version %s NACK: %v", res.Name, res.Version, ack.ErrorDetail)
			}
		} else if !strings.Contains(ack.GetErrorDetail().GetMessage(), wantError) {
			t.Fatalf("ECDS %s version %s: expected NACK containing %q, got %v", res.Name, res.Version, wantError, ack)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("no ECDS acknowledgement for %s version %s", res.Name, res.Version)
	}
}

func (s *extensionDiscovery) DeltaAggregatedResources(
	stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	if request.TypeUrl != extensionType {
		return fmt.Errorf("unexpected subscription %s", request.TypeUrl)
	}
	for {
		var resource *discovery.Resource
		select {
		case resource = <-s.updates:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if err := stream.Send(
			&discovery.DeltaDiscoveryResponse{
				TypeUrl:   extensionType,
				Nonce:     resource.Version,
				Resources: []*discovery.Resource{resource},
			},
		); err != nil {
			return err
		}
		for {
			ack, err := stream.Recv()
			if err != nil {
				return err
			}
			if ack.ResponseNonce == resource.Version {
				select {
				case s.acks <- ack:
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
				break
			}
		}
	}
}

// Run with the exact image's Envoy binary. A real Wasm module must mutate a
// response, and an ECDS update must change that behavior without restarting Envoy.
func TestCommunityEnvoyWasmECDS(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY to test the final Envoy image")
	}
	c := testConfig(t)
	fixture := newExtensionDiscovery()
	upstream := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(upstream, fixture)
	server := httptest.NewUnstartedServer(upstream)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer upstream.Stop()
	c.Proxy.DiscoveryAddress = server.Listener.Addr().String()
	c.RootCertFile = filepath.Join(t.TempDir(), "root.pem")
	c.TokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(
		c.RootCertFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.TokenFile, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	stop, _, err := startXDS(c)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ports, releasePorts := reservePorts(t, 2)
	port, admin := ports[0], ports[1]
	bootstrap := fmt.Sprintf(`{
 "node":{"id":"agentio-wasm-test","cluster":"test"},
 "admin":{"address":{"socket_address":{"address":"127.0.0.1","port_value":%d}}},
 "dynamic_resources":{"ads_config":{"api_type":"DELTA_GRPC","transport_api_version":"V3","grpc_services":[{"envoy_grpc":{"cluster_name":"xds"}}]}},
 "static_resources":{
 "clusters":[{"name":"xds","connect_timeout":"1s","type":"STATIC",
 "typed_extension_protocol_options":{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions":{"@type":"type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions","explicit_http_config":{"http2_protocol_options":{}}}},
 "load_assignment":{"cluster_name":"xds","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"pipe":{"path":%q}}}}]}]}}],
 "listeners":[{"name":"test","address":{"socket_address":{"address":"127.0.0.1","port_value":%d}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{
 "@type":"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager","stat_prefix":"test",
 "route_config":{"name":"test","virtual_hosts":[{"name":"test","domains":["*"],"routes":[{"match":{"prefix":"/"},"direct_response":{"status":200,"body":{"inline_string":"ok"}}}]}]},
 "http_filters":[{"name":"agentio.test.wasm","config_discovery":{"config_source":{"ads":{},"resource_api_version":"V3"},"type_urls":["type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm"]}},{"name":"envoy.filters.http.router","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]
 }}]}]}]}}`, admin, c.XDSSocket, port)
	path := filepath.Join(t.TempDir(), "envoy.json")
	if err := os.WriteFile(path, []byte(bootstrap), 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cmd := exec.CommandContext(
		ctx,
		binary,
		"-c",
		path,
		"--concurrency",
		"1",
		"--disable-hot-restart",
		"--log-level",
		"warning",
	)
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	releasePorts()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		var exitError *exec.ExitError
		if err := cmd.Wait(); err != nil && !errors.As(err, &exitError) {
			t.Errorf("wait for Envoy cleanup: %v", err)
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	for i, version := range []string{"wasm-v1", "wasm-v2"} {
		code := bytes.ReplaceAll(wasmFixture, []byte("wasm-v1"), []byte(version))
		filter, err := anypb.New(&wasmhttp.Wasm{Config: &wasm.PluginConfig{
			Name:   "header-test",
			RootId: "header-test",
			Vm: &wasm.PluginConfig_VmConfig{VmConfig: &wasm.VmConfig{
				VmId:    fmt.Sprint(i + 1),
				Runtime: "envoy.wasm.runtime.v8",
				Code:    &core.AsyncDataSource{Specifier: &core.AsyncDataSource_Local{Local: inlineBytes(code)}},
			}}}})
		if err != nil {
			t.Fatal(err)
		}
		resource, err := anypb.New(&core.TypedExtensionConfig{Name: "agentio.test.wasm", TypedConfig: filter})
		if err != nil {
			t.Fatal(err)
		}
		fixture.publish(
			t,
			&discovery.Resource{Name: "agentio.test.wasm", Version: fmt.Sprint(i + 1), Resource: resource},
			"",
		)
		deadline := time.Now().Add(10 * time.Second)
		for {
			client := http.Client{Timeout: time.Second}
			response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
			matched := false
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				closeResource(response.Body)
				matched = err == nil && response.StatusCode == 200 && response.Header.Get("x-agentio-wasm") == version
			}
			if matched {
				t.Logf("Wasm ECDS behavior accepted: %s", version)
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("Wasm response header never became %s; last error %v", version, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// Also verify runtime selection and the final ECDS version in actual Admin output.
	response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/config_dump", admin))
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(response.Body)
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(content) || !strings.Contains(string(content), "envoy.wasm.runtime.v8") {
		t.Fatal("Wasm runtime absent from config dump")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ports, release := reservePorts(t, 1)
	release()
	return ports[0]
}

// Hold ports until process startup so later fixture listeners cannot reuse them.
func reservePorts(t *testing.T, count int) ([]int, func()) {
	t.Helper()
	var listeners []net.Listener
	release := func() {
		for _, listener := range listeners {
			closeResource(listener)
		}
		listeners = nil
	}
	t.Cleanup(release)
	ports := make([]int, count)
	for i := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports[i] = listener.Addr().(*net.TCPAddr).Port
	}
	return ports, release
}

func TestReservedPortsRemainUnavailableUntilRelease(t *testing.T) {
	ports, release := reservePorts(t, 5)
	fixture := httptest.NewServer(http.NotFoundHandler())
	defer fixture.Close()
	for _, port := range ports {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			closeResource(listener)
			t.Fatalf("port %d was not reserved", port)
		}
	}
	release()
	// Keep replacement listeners open to also verify every port is distinct.
	for _, port := range ports {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeResource(listener) })
	}
}
