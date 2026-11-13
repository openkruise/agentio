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
	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

func sniPolicyListenerFilter() *listenerv3.ListenerFilter {
	fields, err := structpb.NewStruct(map[string]any{
		"dynamic_module_config": map[string]any{
			"name": "envoy_agentio_connection_policy",
			"module": map[string]any{
				"local": map[string]any{"filename": "/usr/local/lib/libenvoy_agentio_connection_policy.so"},
			},
		},
		"filter_name": "envoy_agentio_sni_policy",
	})
	if err != nil {
		panic(err)
	}
	return &listenerv3.ListenerFilter{
		Name: "envoy.filters.listener.dynamic_modules",
		ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: mustPack(&udpatypev1.TypedStruct{
			TypeUrl: "type.googleapis.com/envoy.extensions.filters.listener.dynamic_modules.v3.DynamicModuleListenerFilter",
			Value:   fields,
		})},
	}
}

func buildInspectionDeadlineListenerFilter() *listenerv3.ListenerFilter {
	fields, err := structpb.NewStruct(map[string]any{
		"dynamic_module_config": map[string]any{
			"name":         "envoy_agentio_network_limits",
			"do_not_close": true,
			"module": map[string]any{
				"local": map[string]any{"filename": "/usr/local/lib/libenvoy_agentio_network_limits.so"},
			},
		},
		"filter_name": "envoy_agentio_inspection_deadline",
	})
	if err != nil {
		panic(err)
	}
	return &listenerv3.ListenerFilter{
		Name: "envoy.filters.listener.dynamic_modules",
		ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: mustPack(&udpatypev1.TypedStruct{
			TypeUrl: "type.googleapis.com/envoy.extensions.filters.listener.dynamic_modules.v3.DynamicModuleListenerFilter",
			Value:   fields,
		})},
	}
}
