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

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

func (b *resourceBuilder) tcpPolicyFilter(resolveSNI, skipMatchedProfile bool) *listenerv3.Filter {
	denied := make([]any, 0)
	if resolveSNI {
		for _, cidr := range configv1.MandatoryEgressDeniedCIDRs() {
			denied = append(denied, cidr)
		}
	}
	return networkFilter("agentio.tcp_policy", b.pack(&udpatypev1.TypedStruct{
		TypeUrl: "type.googleapis.com/envoy.extensions.filters.network.dynamic_modules.v3.DynamicModuleNetworkFilter",
		Value: b.structure(map[string]any{
			"dynamic_module_config": map[string]any{
				"name":         "envoy_agentio_connection_policy",
				"do_not_close": true,
				"module": map[string]any{
					"local": map[string]any{"filename": "/usr/local/lib/libenvoy_agentio_connection_policy.so"},
				},
			},
			"filter_name": "envoy_agentio_tcp_policy",
			"filter_config": map[string]any{
				"@type": "type.googleapis.com/google.protobuf.Struct",
				"value": map[string]any{
					"resolveSni":         resolveSNI,
					"skipMatchedProfile": skipMatchedProfile,
					"deniedCidrs":        denied,
				},
			},
		}),
	}))
}
