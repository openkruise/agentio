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
	"path/filepath"
	"strings"
	"testing"
	"time"

	internallistener "github.com/envoyproxy/go-control-plane/envoy/extensions/bootstrap/internal_listener/v3"
	validator "github.com/envoyproxy/go-control-plane/envoy/extensions/config/validators/dynamic_modules/v3"
	httpupstreamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	c := FromEnvironment()
	c.PodName, c.Namespace, c.PodUID, c.ServiceAccount, c.IP = "gateway", "demo", "pod-uid", "egress", "10.0.0.1"
	c.Proxy.ConfigPath = t.TempDir()
	c.XDSSocket = filepath.Join(c.Proxy.ConfigPath, "XDS")
	c.SDSSocket = filepath.Join(c.Proxy.ConfigPath, "SDS")
	c.Proxy.DiscoveryAddress, c.CAAddress = "agentiod.demo.svc:15012", "agentiod.demo.svc:15012"
	return c
}

func TestCommunityBootstrap(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "2001:db8::1"} {
		c := testConfig(t)
		c.IP = ip
		c.LogAsJSON = true
		c.StatsFlushInterval = 500 * time.Millisecond
		b, err := bootstrapConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		internal := &internallistener.InternalListener{}
		if err := b.GetBootstrapExtensions()[0].GetTypedConfig().UnmarshalTo(internal); err != nil {
			t.Fatal(err)
		}
		if internal.GetBufferSizeKb().GetValue() != 64 {
			t.Fatal("internal listener buffer must retain the 64 KiB backpressure threshold")
		}
		validators := b.GetDynamicResources().GetAdsConfig().GetConfigValidators()
		if len(validators) != 1 {
			t.Fatalf("ADS validators = %v", validators)
		}
		body := &validator.DynamicModuleConfigValidator{}
		if err := validators[0].GetTypedConfig().UnmarshalTo(body); err != nil {
			t.Fatal(err)
		}
		if body.GetExtensionName() != "agentio.body_processing" || len(body.GetTypeUrls()) != 1 ||
			body.GetTypeUrls()[0] != extensionType {
			t.Fatalf("unexpected Body Processing validator %v", body)
		}
		if b.GetApplicationLogConfig().GetLogFormat().GetJsonFormat() == nil {
			t.Fatal("missing JSON application logs")
		}
		if !b.GetDeferredStatOptions().GetEnableDeferredCreationStats() {
			t.Fatal("deferred stats creation disabled")
		}
		if b.Node.Id != "agentio-egress~"+ip+"~gateway.demo~demo.svc.cluster.local" {
			t.Fatal(b.Node.Id)
		}
		if b.Node.Metadata.Fields["POD_UID"].GetStringValue() != c.PodUID {
			t.Fatal("missing bound Pod UID")
		}
		for _, cluster := range b.StaticResources.Clusters {
			if cluster.Name != "xds-grpc" && cluster.Name != "sds-grpc" {
				continue
			}
			if cluster.Http2ProtocolOptions != nil {
				t.Fatalf("%s uses deprecated cluster HTTP/2 options", cluster.Name)
			}
			options := &httpupstreamv3.HttpProtocolOptions{}
			if err := cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(
				options,
			); err != nil {
				t.Fatal(err)
			}
			if options.GetExplicitHttpConfig().GetHttp2ProtocolOptions() == nil {
				t.Fatalf("%s must use HTTP/2 for gRPC", cluster.Name)
			}
		}
		content, err := protojson.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, removed := range []string{"istio.", "kruise.networking", "policy_store", "workload_discovery"} {
			if strings.Contains(string(content), removed) {
				t.Fatalf("bootstrap contains %s", removed)
			}
		}
		if len(b.BootstrapExtensions) != 1 || b.BootstrapExtensions[0].Name != "envoy.bootstrap.internal_listener" {
			t.Fatal("unexpected bootstrap extensions")
		}
	}
}

func TestServiceClusterOverride(t *testing.T) {
	for _, value := range []string{"", "custom-gateway"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("AGENTIO_SERVICE_CLUSTER", value)
			c := testConfig(t)
			b, err := bootstrapConfig(c)
			if err != nil {
				t.Fatal(err)
			}
			want := value
			if want == "" {
				want = "agentio-egress"
			}
			if b.Node.Cluster != want || b.Node.Id != c.nodeID() {
				t.Fatalf("unexpected node identity: %v", b.Node)
			}
		})
	}
}
