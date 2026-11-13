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
	"strings"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayFilterStateNamesStayIsolated(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		var graph strings.Builder
		for _, resource := range buildGatewayGraph(t, legacy) {
			data, err := protojson.Marshal(resource.Value)
			if err != nil {
				t.Fatal(err)
			}
			graph.Write(data)
		}
		for _, pair := range [][2]string{
			{outerSNIKey, legacyOuterSNIKey},
			{model.FilterStateConnectAuthority, connectAuthorityKey},
		} {
			want, absent := pair[0], pair[1]
			if legacy {
				want, absent = absent, want
			}
			text := graph.String()
			if !strings.Contains(text, `"`+want+`"`) || strings.Contains(text, `"`+absent+`"`) ||
				strings.Contains(
					text,
					"filter_state['"+absent+"']",
				) || strings.Contains(text, "%FILTER_STATE("+absent+":") {
				t.Fatalf("legacy=%t: expected consistent %s references without %s", legacy, want, absent)
			}
		}
	}
}

func TestAgentioEgressPolicyTransfer(t *testing.T) {
	resources := buildCompleteGatewayGraph(t)
	for _, r := range resources {
		data, err := protojson.Marshal(r.Value)
		if err != nil {
			t.Fatal(err)
		}
		for _, unsupported := range []string{"istio.hashable_string", "io.istio.peer_principal", "io.istio.local_principal", "io.istio.http.peer_metadata.Config", "kruise.networking.policy_runtime.", "istio.stats", "x-agentio-tls"} {
			if strings.Contains(string(data), unsupported) {
				t.Fatalf("%s contains legacy extension %s", r.XDSName, unsupported)
			}
		}
	}
	listeners := messagesOf(
		t,
		resources,
		model.ListenerType,
		func() *listenerv3.Listener { return &listenerv3.Listener{} },
	)
	if _, found := connectAuthorityStates(t, listeners[ConnectTerminate])[tlsActionKey]; found {
		t.Fatal("agentio-egress captures a caller TLS action")
	}
	hcm := findHCM(t, listeners[ConnectTerminate])
	found := false
	for _, f := range hcm.GetHttpFilters() {
		switch f.GetName() {
		case "envoy.filters.http.ext_proc":
			cfg := &extprocv3.ExternalProcessor{}
			if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.FailureModeAllow || cfg.GetGrpcService().GetEnvoyGrpc().GetClusterName() != PorterCluster ||
				cfg.GetMessageTimeout().AsDuration() != 5*time.Second {
				t.Fatalf("CONNECT processor=%v", cfg)
			}
			if cfg.GetProcessingMode().GetRequestBodyMode() != extprocv3.ProcessingMode_NONE {
				t.Fatal("CONNECT processor must not consume tunnel data")
			}
		case "agentio.connect_workload":
			cfg := &setstatehttpv3.Config{}
			if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			states := cfg.GetOnRequestHeaders()
			state := states[len(states)-1]
			if state.GetObjectKey() != "agentio.connection.policy_json" || state.GetReadOnly() ||
				state.GetFactoryKey() != "envoy.string" || state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_NONE {
				t.Fatalf("JSON input must be mutable and local to CONNECT: %v", state)
			}
		case "agentio.connect_policy":
			cfg := &setstatehttpv3.Config{}
			if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			states := cfg.GetOnRequestHeaders()
			if len(states) != 1 {
				t.Fatalf("policy states=%v", states)
			}
			state := states[0]
			if state.GetObjectKey() != model.FilterStateConnectionPolicyHash ||
				state.GetFactoryKey() != "envoy.hashable_string" ||
				!state.GetSkipIfEmpty() ||
				!state.GetReadOnly() ||
				state.GetSharedWithUpstream() != setstatecommonv3.FilterStateValue_ONCE ||
				state.GetFormatString().
					GetTextFormatSource().
					GetInlineString() !=
					"%DYNAMIC_METADATA(agentio.connection:policy_hash)%" {
				t.Fatalf("policy transfer=%v", state)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing Porter policy transfer")
	}
}
