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
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	setstatenetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pkg/test"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

// Exercise the mutation boundary with shared listener and network filters,
// while other builds marshal the same globals. Run with -race as well.
func TestStaticFiltersConcurrentBuildAndPatch(t *testing.T) {
	test.SetForTest(t, &features.EnableSNITrafficPolicy, true)
	test.SetForTest(t, &features.GatewayRootCAPath, "/etc/ssl/cert.pem")
	inputs := Inputs{
		Gateway:          testGateway(nil),
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	}
	want, err := Build(inputs)
	if err != nil {
		t.Fatal(err)
	}
	inspectorConfig, err := anypb.New(&tlsinspectorv3.TlsInspector{InitialReadBufferSize: wrapperspb.UInt32(32768)})
	if err != nil {
		t.Fatal(err)
	}
	identityConfig, err := anypb.New(&setstatenetworkv3.Config{OnNewConnection: []*setstatecommonv3.FilterStateValue{{
		Key:        &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: "test.patch"},
		FactoryKey: "envoy.string",
		Value:      &setstatecommonv3.FilterStateValue_FormatString{FormatString: formatString("patched")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	patch, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "agentio-system",
		Name:      "static-filter-test",
		Source:    "test",
	}, 0, []string{"agentio-system/egress"}, []model.EnvoyPatch{
		{
			Operation: model.PatchMerge,
			Target: model.ListenerFilterPatch{
				Match: &model.ListenerMatch{Name: MainInternal, ListenerFilter: "envoy.filters.listener.tls_inspector"},
				Value: &listenerv3.ListenerFilter{
					Name:       "envoy.filters.listener.tls_inspector",
					ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: inspectorConfig},
				},
			},
		},
		{
			Operation: model.PatchMerge,
			Target: model.NetworkFilterPatch{
				Match: &model.ListenerMatch{
					Name: MainForward,
					FilterChain: &model.FilterChainMatch{
						Name:   forwardTCPChain,
						Filter: &model.FilterMatch{Name: outerTLSIdentityFilter.GetName()},
					},
				},
				Value: &listenerv3.Filter{
					Name:       outerTLSIdentityFilter.GetName(),
					ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: identityConfig},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			patchedInputs := inputs
			patchedInputs.GatewayPatches = []model.GatewayPatch{patch}
			resources, err := Build(patchedInputs)
			if err != nil {
				t.Fatal(err)
			}
			listeners := messagesOf(
				t,
				resources,
				model.ListenerType,
				func() *listenerv3.Listener { return &listenerv3.Listener{} },
			)
			inspector := &tlsinspectorv3.TlsInspector{}
			if err := listeners[MainInternal].ListenerFilters[3].GetTypedConfig().UnmarshalTo(inspector); err != nil {
				t.Fatal(err)
			}
			if inspector.GetInitialReadBufferSize().GetValue() != 32768 {
				t.Fatal("listener filter patch was not applied")
			}
			var patchedValues int
			for _, chain := range listeners[MainForward].FilterChains {
				if chain.Name == forwardTCPChain {
					identity := &setstatenetworkv3.Config{}
					if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(identity); err != nil {
						t.Fatal(err)
					}
					patchedValues = len(identity.GetOnNewConnection())
				}
			}
			if patchedValues != 3 {
				t.Fatal("network filter patch was not applied")
			}
			got, err := Build(inputs)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatal("patch changed another build's resource count")
			}
			for i := range want {
				if !got[i].Equals(want[i]) {
					t.Errorf("patch contaminated another build's resource %s", want[i].XDSName)
				}
			}
		})
	}
}
