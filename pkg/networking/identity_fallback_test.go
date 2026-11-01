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
	"slices"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	setstatenetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestConnectIdentityFallbackTransfer(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, sni := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%v/sni=%v", legacy, sni), func(t *testing.T) {
				test.SetForTest(t, &features.EnableSNITrafficPolicy, sni)
				resources, err := Build(
					Inputs{
						LegacyGateway: legacy,
						Gateway: testGateway(
							&configv1.EgressGateway{
								ConnectRateLimit: &configv1.LocalRateLimitSettings{
									TokenBucket: &configv1.TokenBucket{
										MaxTokens:     1,
										TokensPerFill: 1,
										FillInterval:  durationpb.New(time.Minute),
									},
								},
							},
						),
						TrustDomain:      "cluster.local",
						DiscoveryAddress: "agentiod.agentio-system.svc:15012",
					},
				)
				if err != nil {
					t.Fatal(err)
				}
				listeners := messagesOf(
					t,
					resources,
					model.ListenerType,
					func() *listenerv3.Listener { return &listenerv3.Listener{} },
				)
				listener := listeners[ConnectTerminate]
				hcm := findHCM(t, listener)
				names := httpFilterNames(hcm)
				index := slices.Index(names, "agentio.connect_workload")
				rateLimitIndex := slices.Index(names, "envoy.filters.http.local_ratelimit")
				if rateLimitIndex < 0 || rateLimitIndex >= slices.Index(names, "envoy.filters.http.router") {
					t.Fatalf("rate limiting must run before routing: %v", names)
				}
				peer := connectAuthorityStates(t, listener)["agentio.downstream.ip"]
				if legacy {
					if index >= 0 || peer != nil {
						t.Fatal("legacy gateway gained Porter identity fallback")
					}
					return
				}
				if peer.GetFormatString().
					GetTextFormatSource().
					GetInlineString() !=
					"%DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT%" ||
					peer.GetFactoryKey() != "envoy.string" ||
					peer.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_NONE {
					t.Fatalf("unexpected source IP capture: %v", peer)
				}
				states := connectAuthorityStates(t, listener)
				cert := states["agentio.peer.certificate"]
				if cert == nil ||
					cert.GetFormatString().GetTextFormatSource().GetInlineString() != "%DOWNSTREAM_PEER_CERT%" ||
					cert.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_NONE {
					t.Fatalf("certificate must come from TLS and stay on CONNECT: %v", cert)
				}
				for _, key := range []string{"sandbox.labels", "agentio.workload.name", "agentio.workload.namespace"} {
					if states[key] != nil {
						t.Fatalf("native gateway still reads workload header for %s", key)
					}
				}
				if index < 1 || names[index-1] != "envoy.filters.http.ext_proc" ||
					index >= rateLimitIndex {
					t.Fatalf("identity must be restored after Porter and before rate limiting: %v", names)
				}
				processor := &extprocv3.ExternalProcessor{}
				if err := hcm.HttpFilters[index-1].GetTypedConfig().UnmarshalTo(processor); err != nil {
					t.Fatal(err)
				}
				for _, attr := range []string{"filter_state['agentio.downstream.ip']", "filter_state['agentio.peer.principal']", "filter_state['agentio.peer.certificate']"} {
					if !slices.Contains(processor.RequestAttributes, attr) {
						t.Fatalf("Porter missing %s", attr)
					}
				}
				for _, attr := range []string{model.AttributeWorkloadName, model.AttributeWorkloadNamespace} {
					if slices.Contains(processor.RequestAttributes, attr) {
						t.Fatalf("Porter still requests header identity: %s", attr)
					}
				}
				restored := &setstatehttpv3.Config{}
				if err := hcm.HttpFilters[index].GetTypedConfig().UnmarshalTo(restored); err != nil {
					t.Fatal(err)
				}
				if len(restored.OnRequestHeaders) != 4 {
					t.Fatalf("identity state=%v", restored)
				}
				for i, key := range []string{model.FilterStateWorkloadLabels, "sandbox.labels"} {
					state := restored.OnRequestHeaders[2+i]
					factory := "envoy.hashable_string"
					if key == "sandbox.labels" {
						factory = "envoy.string"
					}
					if state.GetObjectKey() != key ||
						state.GetFactoryKey() != factory ||
						state.GetFormatString().
							GetTextFormatSource().
							GetInlineString() !=
							"%DYNAMIC_METADATA(agentio:workload_labels)%" ||
						state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_ONCE {
						t.Fatalf("new and legacy labels must share the same WDS value: %v", state)
					}
				}
				for i, field := range []string{"name", "namespace"} {
					state := restored.OnRequestHeaders[i]
					if state.GetObjectKey() != "agentio.workload."+field ||
						state.GetFactoryKey() != "envoy.hashable_string" ||
						state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_ONCE ||
						state.GetFormatString().
							GetTextFormatSource().
							GetInlineString() !=
							"%DYNAMIC_METADATA(agentio:workload:"+field+")%" {
						t.Fatalf("identity must survive internal hops and isolate connection pools: %v", state)
					}
				}
			})
		}
	}
}

func TestWorkloadStateTLSRelay(t *testing.T) {
	config := &setstatenetworkv3.Config{}
	if err := relayDownstreamFilter.GetTypedConfig().UnmarshalTo(config); err != nil {
		t.Fatal(err)
	}
	states := map[string]*setstatecommonv3.FilterStateValue{}
	for _, state := range config.OnNewConnection {
		states[state.GetObjectKey()] = state
	}
	if states["agentio.workload.instance"] != nil {
		t.Fatal("unused workload instance must not be relayed")
	}
	for _, key := range []string{
		model.FilterStateSandboxID, "sandbox.token", "agentio.sandbox.metadata",
		model.FilterStateWorkloadName, model.FilterStateWorkloadNamespace,
		model.FilterStateWorkloadLabels, "sandbox.labels",
	} {
		state := states[key]
		factory := "envoy.hashable_string"
		if key == "sandbox.labels" {
			factory = "envoy.string"
		}
		if state.GetFactoryKey() != factory ||
			state.GetFormatString().GetTextFormatSource().GetInlineString() != "%FILTER_STATE("+key+":PLAIN)%" ||
			state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_ONCE {
			t.Errorf("%s must survive TLS termination but stop sharing at main_forward: %v", key, state)
		}
		if wantSkip := key != model.FilterStateSandboxID && key != "sandbox.token"; state.GetSkipIfEmpty() != wantSkip {
			t.Errorf("%s skip_if_empty = %v, want %v", key, state.GetSkipIfEmpty(), wantSkip)
		}
	}
}
