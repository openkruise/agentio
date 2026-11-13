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
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/openkruise/agentio/pkg/model"
)

// The store owns the snapshot for this CONNECT; only its hash crosses listeners.
func (b *resourceBuilder) connectPolicyFilters() []*hcmv3.HttpFilter {
	store := httpFilter("agentio.connection_policy_store", b.pack(&udpatypev1.TypedStruct{
		TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
		Value: b.structure(map[string]any{
			"dynamic_module_config": map[string]any{
				"name":         "envoy_agentio_connection_policy",
				"do_not_close": true,
				"module": map[string]any{
					"local": map[string]any{"filename": "/usr/local/lib/libenvoy_agentio_connection_policy.so"},
				},
			},
			"filter_name": "envoy_agentio_connection_policy_store",
		}),
	}))
	output := httpFilter("agentio.connect_policy", b.pack(&setstatehttpv3.Config{
		OnRequestHeaders: []*setstatecommonv3.FilterStateValue{
			{
				Key: &setstatecommonv3.FilterStateValue_ObjectKey{
					ObjectKey: model.FilterStateConnectionPolicyHash,
				},
				FactoryKey: "envoy.hashable_string",
				Value: &setstatecommonv3.FilterStateValue_FormatString{
					FormatString: formatString("%DYNAMIC_METADATA(agentio.connection:policy_hash)%"),
				},
				ReadOnly:           true,
				SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
				SkipIfEmpty:        true,
			},
		},
	}))
	return []*hcmv3.HttpFilter{store, output}
}
