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
	"testing"

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tcpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"

	"github.com/openkruise/agentio/pkg/model"
)

func TestTCPPolicyRunsBeforeProxy(t *testing.T) {
	listeners := messagesOf(t, buildCompleteGatewayGraph(t), model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} })
	for _, tc := range []struct {
		listener   string
		chain      string
		cluster    string
		resolveSNI bool
	}{
		{MainInternal, forwardTCPChain, PassthroughCluster, false},
		{MainInternal, forwardTLSChain, TLSPassthrough, true},
		{MainForward, forwardTCPChain, TLSProxyOriginate, true},
	} {
		t.Run(tc.listener+"/"+tc.chain, func(t *testing.T) {
			chain := findFilterChain(t, listeners[tc.listener], tc.chain)
			policyIndex := -1
			for i, filter := range chain.Filters {
				if filter.Name == "agentio.tcp_policy" {
					if policyIndex >= 0 {
						t.Fatal("TCP policy installed more than once")
					}
					policyIndex = i
				}
			}
			if policyIndex < 0 || policyIndex >= len(chain.Filters)-1 {
				t.Fatalf("TCP authorization must precede the proxy: %v", networkFilterNames(chain))
			}
			module := new(udpatypev1.TypedStruct)
			if err := chain.Filters[policyIndex].GetTypedConfig().UnmarshalTo(module); err != nil {
				t.Fatal(err)
			}
			library := module.Value.GetFields()["dynamic_module_config"].GetStructValue().GetFields()["module"].GetStructValue().GetFields()["local"].GetStructValue().GetFields()["filename"].GetStringValue()
			if library != "/usr/local/lib/libenvoy_agentio_connection_policy.so" {
				t.Fatalf("TCP policy module path = %q", library)
			}
			settings := module.Value.GetFields()["filter_config"].GetStructValue().GetFields()["value"].GetStructValue()
			if settings.GetFields()["resolveSni"].GetBoolValue() != tc.resolveSNI {
				t.Fatalf("resolveSni=%v, want %v", settings.GetFields()["resolveSni"], tc.resolveSNI)
			}
			proxy := new(tcpv3.TcpProxy)
			if err := chain.Filters[len(chain.Filters)-1].GetTypedConfig().UnmarshalTo(proxy); err != nil {
				t.Fatal(err)
			}
			if proxy.GetCluster() != tc.cluster {
				t.Fatalf("proxy cluster=%s, want %s", proxy.GetCluster(), tc.cluster)
			}
		})
	}
}
