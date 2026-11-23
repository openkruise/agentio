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

package networking

import (
	"os"
	"path/filepath"
	"testing"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

// Standalone Envoy fixtures read xDS resources from disk. Give all their HCMs
// the same generated Body Processing extension, including across LDS updates.
func bodyProcessingFile(t *testing.T) *corev3.ConfigSource {
	t.Helper()
	b := &resourceBuilder{}
	extension, err := b.bodyProcessingExtension(nil)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := anypb.New(extension)
	if err != nil {
		t.Fatal(err)
	}
	data, err := protojson.Marshal(&discoveryv3.DiscoveryResponse{
		TypeUrl: model.ExtensionConfigurationType, VersionInfo: "1", Resources: []*anypb.Any{resource},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "body-processing.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return &corev3.ConfigSource{
		ResourceApiVersion: corev3.ApiVersion_V3,
		ConfigSourceSpecifier: &corev3.ConfigSource_PathConfigSource{
			PathConfigSource: &corev3.PathConfigSource{Path: path},
		},
	}
}

func setBodyProcessingSource(manager *hcmv3.HttpConnectionManager, source *corev3.ConfigSource) {
	for _, filter := range manager.HttpFilters {
		if filter.Name == bodyProcessingName {
			filter.GetConfigDiscovery().ConfigSource = source
		}
	}
}

func testGateway(config *configv1.EgressGateway) model.Gateway {
	if config == nil {
		config = &configv1.EgressGateway{}
	}
	return model.Gateway{
		Namespace: "agentio-system",
		Name:      "egress",
		Config:    config,
	}
}

func messagesOf[T proto.Message](
	t *testing.T,
	resources []model.Resource,
	typeURL string,
	newMessage func() T,
) map[string]T {
	t.Helper()
	result := map[string]T{}
	for _, resource := range resources {
		if resource.Key.TypeURL != typeURL {
			continue
		}
		message := newMessage()
		if err := resource.Value.UnmarshalTo(message); err != nil {
			t.Fatalf("unmarshal %s: %v", resource.Key.Name, err)
		}
		result[resource.XDSName] = message
	}
	return result
}

func findHCM(t *testing.T, listener *listenerv3.Listener) *hcmv3.HttpConnectionManager {
	t.Helper()
	for _, chain := range listener.GetFilterChains() {
		for _, filter := range chain.GetFilters() {
			if filter.GetName() != "envoy.filters.network.http_connection_manager" {
				continue
			}
			cfg := &hcmv3.HttpConnectionManager{}
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatalf("unmarshal HCM: %v", err)
			}
			return cfg
		}
	}
	t.Fatal("HCM not found")
	return nil
}

func findFilterChain(t *testing.T, listener *listenerv3.Listener, name string) *listenerv3.FilterChain {
	t.Helper()
	for _, chain := range listener.GetFilterChains() {
		if chain.GetName() == name {
			return chain
		}
	}
	t.Fatalf("filter chain %q not found", name)
	return nil
}

func networkFilterNames(chain *listenerv3.FilterChain) []string {
	result := make([]string, 0, len(chain.GetFilters()))
	for _, filter := range chain.GetFilters() {
		result = append(result, filter.GetName())
	}
	return result
}

func hasHTTPFilter(hcm *hcmv3.HttpConnectionManager, name string) bool {
	for _, filter := range hcm.GetHttpFilters() {
		if filter.GetName() == name {
			return true
		}
	}
	return false
}

func httpFilterNames(hcm *hcmv3.HttpConnectionManager) []string {
	result := make([]string, 0, len(hcm.GetHttpFilters()))
	for _, filter := range hcm.GetHttpFilters() {
		result = append(result, filter.GetName())
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
