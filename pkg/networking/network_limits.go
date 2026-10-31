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
	"fmt"

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

const bandwidthFilterName = "agentio.bandwidth"
const concurrencyFilterName = "agentio.connect_concurrency"

func (b *resourceBuilder) bandwidthFilter(
	gateway string,
	settings *configv1.BandwidthLimitSettings,
) (*hcmv3.HttpFilter, error) {
	return b.connectResourceFilter(gateway, bandwidthFilterName, "bandwidth", "envoy_agentio_bandwidth", settings)
}

func (b *resourceBuilder) concurrencyFilter(
	gateway string,
	settings *configv1.ConnectConcurrencyLimitSettings,
) (*hcmv3.HttpFilter, error) {
	return b.connectResourceFilter(
		gateway,
		concurrencyFilterName,
		"connect_concurrency",
		"envoy_agentio_connect_concurrency",
		settings,
	)
}

func (b *resourceBuilder) connectResourceFilter(
	gateway, name, scope, moduleFilter string,
	settings proto.Message,
) (*hcmv3.HttpFilter, error) {
	data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", name, err)
	}
	config := new(structpb.Struct)
	if err := protojson.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("encode %s: %w", name, err)
	}
	config.Fields["enabled"] = structpb.NewBoolValue(settings.ProtoReflect().IsValid())
	config.Fields["budget_name"] = structpb.NewStringValue("agentio/" + gateway + "/" + scope)
	fields, err := structpb.NewStruct(map[string]any{
		"dynamic_module_config": map[string]any{
			"name":         "envoy_agentio_network_limits",
			"do_not_close": true,
			"module": map[string]any{
				"local": map[string]any{"filename": "/usr/local/lib/libenvoy_agentio_network_limits.so"},
			},
		},
		"filter_name": moduleFilter,
		"filter_config": map[string]any{
			"@type": "type.googleapis.com/google.protobuf.Struct",
			"value": config.AsMap(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode %s module: %w", name, err)
	}
	const moduleType = "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter"
	b.extensions = append(b.extensions, &corev3.TypedExtensionConfig{
		Name: name,
		TypedConfig: b.pack(&udpatypev1.TypedStruct{
			TypeUrl: moduleType,
			Value:   fields,
		})})
	// Keep the ECDS slot stable, but create stream instances only when RDS
	// enables this filter. Unconfigured streams avoid module callbacks entirely.
	return &hcmv3.HttpFilter{
		Name:     name,
		Disabled: true,
		ConfigType: &hcmv3.HttpFilter_ConfigDiscovery{
			ConfigDiscovery: &corev3.ExtensionConfigSource{
				ConfigSource: adsConfigSource(),
				TypeUrls:     []string{moduleType},
			},
		},
	}, nil
}
