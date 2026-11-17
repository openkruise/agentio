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

package kubernetes

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/model"
)

// Use textual Any values: importing extension types here would hide missing production registrations.
func TestGatewayPatchFilterTypes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		target   string
		applyTo  string
		typeName string
		config   string
	}{
		{"network-rbac", "networkFilter", "NETWORK_FILTER", "envoy.extensions.filters.network.rbac.v3.RBAC", `{"statPrefix":"test","rules":{}}`},
		{"network-ext-authz", "networkFilter", "NETWORK_FILTER", "envoy.extensions.filters.network.ext_authz.v3.ExtAuthz", `{"statPrefix":"test"}`},
		{"network-connection-limit", "networkFilter", "NETWORK_FILTER", "envoy.extensions.filters.network.connection_limit.v3.ConnectionLimit", `{"statPrefix":"test","maxConnections":"10"}`},
		{"network-local-ratelimit", "networkFilter", "NETWORK_FILTER", "envoy.extensions.filters.network.local_ratelimit.v3.LocalRateLimit", `{"statPrefix":"test","tokenBucket":{"maxTokens":10,"fillInterval":"1s"}}`},
		{"network-ratelimit", "networkFilter", "NETWORK_FILTER", "envoy.extensions.filters.network.ratelimit.v3.RateLimit", `{"statPrefix":"test","domain":"test"}`},
		{"network-dynamic-module", "networkFilter", "NETWORK_FILTER", "envoy.extensions.filters.network.dynamic_modules.v3.DynamicModuleNetworkFilter", `{"filterName":"test"}`},
		{"network-wasm", "networkFilter", "NETWORK_FILTER", "envoy.extensions.filters.network.wasm.v3.Wasm", `{"config":{"name":"test"}}`},
		{"listener-dynamic-module", "listenerFilter", "LISTENER_FILTER", "envoy.extensions.filters.listener.dynamic_modules.v3.DynamicModuleListenerFilter", `{"filterName":"test"}`},
		{"listener-proxy-protocol", "listenerFilter", "LISTENER_FILTER", "envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol", `{"allowRequestsWithoutProxyProtocol":true}`},
		{"listener-local-ratelimit", "listenerFilter", "LISTENER_FILTER", "envoy.extensions.filters.listener.local_ratelimit.v3.LocalRateLimit", `{"statPrefix":"test","tokenBucket":{"maxTokens":10,"fillInterval":"1s"}}`},
		{"listener-original-src", "listenerFilter", "LISTENER_FILTER", "envoy.extensions.filters.listener.original_src.v3.OriginalSrc", `{"mark":1}`},
		{"http-ext-authz", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.ext_authz.v3.ExtAuthz", `{"failureModeAllow":true}`},
		{"http-jwt-authn", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication", `{"bypassCorsPreflight":true}`},
		{"http-lua", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.lua.v3.Lua", `{"defaultSourceCode":{"inlineString":"function envoy_on_request(handle) end"}}`},
		{"http-buffer", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.buffer.v3.Buffer", `{"maxRequestBytes":1024}`},
		{"http-cors", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.cors.v3.Cors", `{}`},
		{"http-fault", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.fault.v3.HTTPFault", `{"abort":{"httpStatus":503,"percentage":{"numerator":1}}}`},
		{"http-header-mutation", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.header_mutation.v3.HeaderMutation", `{"mutations":{"requestMutations":[{"remove":"x-test"}]}}`},
		{"http-header-to-metadata", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.header_to_metadata.v3.Config", `{"requestRules":[{"header":"x-test","onHeaderPresent":{"key":"test","metadataNamespace":"test"}}]}`},
		{"http-ratelimit", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.ratelimit.v3.RateLimit", `{"domain":"test"}`},
		{"http-set-metadata", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.set_metadata.v3.Config", `{"metadataNamespace":"test","value":{"key":"value"}}`},
		{"http-wasm", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.wasm.v3.Wasm", `{"config":{"name":"test"}}`},
		{"http-grpc-web", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.grpc_web.v3.GrpcWeb", `{}`},
		{"http-grpc-json-transcoder", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder", `{"services":["test.Service"]}`},
		{"http-gzip-compressor", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.compressor.v3.Compressor", `{"compressorLibrary":{"name":"gzip","typedConfig":{"@type":"type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"}}}`},
		{"http-gzip-decompressor", "httpFilter", "HTTP_FILTER", "envoy.extensions.filters.http.decompressor.v3.Decompressor", `{"decompressorLibrary":{"name":"gzip","typedConfig":{"@type":"type.googleapis.com/envoy.extensions.compression.gzip.decompressor.v3.Gzip"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want map[string]any
			if err := json.Unmarshal([]byte(tc.config), &want); err != nil {
				t.Fatal(err)
			}
			want["@type"] = "type.googleapis.com/" + tc.typeName
			value, err := json.Marshal(map[string]any{"name": "test.filter", "typed_config": want})
			if err != nil {
				t.Fatal(err)
			}
			for _, format := range []string{"sources", "patches"} {
				t.Run(format, func(t *testing.T) {
					cm := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "filter-types"},
					}
					if format == "sources" {
						cm.Labels = map[string]string{KubeSourceConfigMapLabel: "true"}
						cm.Data = map[string]string{
							KubeSourceDataKey: fmt.Sprintf(`apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  namespace: demo
  name: filter-types
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress
  configPatches:
  - applyTo: %s
    match:
      context: SIDECAR_INBOUND
      listener: {name: main_internal}
    patch:
      operation: INSERT_FIRST
      value: %s
`, tc.applyTo, value),
						}
					} else {
						cm.Labels = map[string]string{ManifestTypeConfigMapLabel: GatewayPatchManifestType}
						cm.Data = map[string]string{KubePatchDataKey: fmt.Sprintf(`targetGateways: [demo/egress]
patches:
- target: %s
  operation: INSERT_FIRST
  match: {name: main_internal}
  value: %s
`, tc.target, value)}
					}
					patches, err := decodeGatewayPatches(cm)
					if err != nil {
						t.Fatal(err)
					}
					if len(patches) != 1 || len(patches[0].Patches) != 1 {
						t.Fatalf("unexpected patches: %+v", patches)
					}
					var typedConfig *anypb.Any
					switch patch := patches[0].Patches[0].Target.(type) {
					case model.NetworkFilterPatch:
						typedConfig = patch.Value.GetTypedConfig()
					case model.HTTPFilterPatch:
						typedConfig = patch.Value.GetTypedConfig()
					case model.ListenerFilterPatch:
						typedConfig = patch.Value.GetTypedConfig()
					default:
						t.Fatalf("unexpected target: %T", patch)
					}
					encoded, err := protojson.Marshal(typedConfig)
					if err != nil {
						t.Fatal(err)
					}
					var got map[string]any
					if err := json.Unmarshal(encoded, &got); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("typed_config = %s, want %v", encoded, want)
					}
				})
			}
		})
	}
}
