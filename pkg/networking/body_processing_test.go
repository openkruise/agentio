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
	"encoding/json"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cel "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	stream "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	dynamicfilter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_modules/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/model"
)

const bodyProcessingYAML = `
bodyProcessing:
  filterChains:
    - name: custom
      matcher:
        hosts: ["*.llm.test"]
        filterState: [{key: agentio.sandbox.id, values: [box-1, box-2]}]
      parser: {llm: {protocol: openai-responses}}
      filters:
        - audit:
            format:
              json:
                agentio.workload.namespace: "%DYNAMIC_METADATA(workload:namespace)%"
                messages: "%EVENT(llm.request.messages):8192%"
                answer: "%EVENT(llm.answer)%"
                tenant: "%REQ(X-TENANT-ID):128%"
                sandbox: "%FILTER_STATE(agentio.sandbox.id:PLAIN)%"
    - name: catch-all
      parser: {llm: {}}
      filters:
        - audit:
            format:
              json:
                agentio.workload.namespace: "%DYNAMIC_METADATA(alternate:ns)%"

`

func unpackBodyRules(t *testing.T, value *anypb.Any) *structpb.Struct {
	t.Helper()
	wire := &dynamicfilter.DynamicModuleFilter{}
	if err := value.UnmarshalTo(wire); err != nil {
		t.Fatal(err)
	}
	config := &wrapperspb.StringValue{}
	if err := wire.FilterConfig.UnmarshalTo(config); err != nil {
		t.Fatal(err)
	}
	var rules structpb.Struct
	raw := config.Value
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		t.Fatal(err)
	}
	return &rules
}

func TestBodyProcessingGatewayConfig(t *testing.T) {
	settings, err := config.ApplyAgentioConfig(bodyProcessingYAML, &configv1.AgentioConfig{})
	if err != nil {
		t.Fatal(err)
	}
	resources, err := Build(Inputs{
		DiscoveryAddress: "agentiod:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(nil),
		BodyProcessing:   settings.BodyProcessing,
	})
	if err != nil {
		t.Fatal(err)
	}
	extensions := messagesOf(t, resources, model.ExtensionConfigurationType, func() *core.TypedExtensionConfig {
		return &core.TypedExtensionConfig{}
	})
	ext := extensions[bodyProcessingName]
	if ext.GetName() != bodyProcessingName || !proto.Equal(unpackBodyRules(t, ext.TypedConfig), settings.BodyProcessing) {
		t.Fatalf("unexpected body processing ECDS resource: %v", ext)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listener.Listener { return &listener.Listener{} })
	for _, name := range []string{MainInternal, MainForward} {
		manager := findHCM(t, listeners[name])
		module := manager.HttpFilters[len(manager.HttpFilters)-2]
		source := module.GetConfigDiscovery()
		if module.Name != bodyProcessingName || module.Disabled || source.GetConfigSource().GetAds() == nil ||
			!source.GetApplyDefaultConfigWithoutWarming() || len(source.TypeUrls) != 1 || source.TypeUrls[0] != bodyProcessingType {
			t.Fatal(module)
		}
		rules := unpackBodyRules(t, source.DefaultConfig)
		if chains := rules.Fields["filterChains"].GetListValue(); chains == nil || len(chains.Values) != 0 {
			t.Fatal(rules)
		}
		if len(manager.AccessLog) != 1 {
			t.Fatal(manager.AccessLog)
		}
		logger := manager.AccessLog[0]
		f := &cel.ExpressionFilter{}
		if err := logger.Filter.GetExtensionFilter().GetTypedConfig().UnmarshalTo(f); err != nil {
			t.Fatal(err)
		}
		if f.Expression != "'agentio.body_processing.audit' in filter_state" {
			t.Fatal(f.Expression)
		}
		out := &stream.StdoutAccessLog{}
		if err := logger.GetTypedConfig().UnmarshalTo(out); err != nil {
			t.Fatal(err)
		}
		text := out.GetLogFormat().GetTextFormatSource().GetInlineString()
		if text != "%FILTER_STATE(agentio.body_processing.audit:PLAIN)%" {
			t.Fatal(out)
		}
	}
}

func TestBodyProcessingDiscoveryUpdates(t *testing.T) {
	const standby = "bodyProcessing: {filterChains: []}"
	in := Inputs{
		DiscoveryAddress: "agentiod:15012",
		TrustDomain:      "cluster.local",
		Gateway:          testGateway(&configv1.EgressGateway{}),
	}
	var previous map[model.ResourceKey]*anypb.Any
	for _, step := range []struct {
		name, config string
		lds, ecds    bool
	}{
		{name: "omitted", config: "{}"},
		{name: "first rules", config: bodyProcessingYAML, lds: true, ecds: true},
		{name: "clear rules", config: standby, ecds: true},
		{name: "restore rules", config: bodyProcessingYAML, ecds: true},
		{name: "remove field", config: "{}", lds: true, ecds: true},
		{name: "install empty", config: standby, lds: true},
		{name: "remove empty", config: "{}", lds: true},
	} {
		settings, err := config.ApplyAgentioConfig(step.config, &configv1.AgentioConfig{})
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		in.BodyProcessing = settings.BodyProcessing
		resources, err := Build(in)
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		current := make(map[model.ResourceKey]*anypb.Any, len(resources))
		for _, res := range resources {
			current[res.Key] = res.Value
			if previous == nil {
				continue
			}
			wantChange := false
			switch res.Key.TypeURL {
			case model.ListenerType:
				wantChange = step.lds && (res.XDSName == MainForward || res.XDSName == MainInternal)
			case model.ExtensionConfigurationType:
				wantChange = step.ecds && res.XDSName == bodyProcessingName
			}
			old, ok := previous[res.Key]
			if !ok {
				t.Fatalf("%s: unexpected new resource %v", step.name, res.Key)
			}
			if changed := !proto.Equal(old, res.Value); changed != wantChange {
				t.Fatalf("%s: %s %s changed=%t, want %t", step.name, res.Key.TypeURL, res.XDSName, changed, wantChange)
			}
		}
		if previous != nil && len(current) != len(previous) {
			t.Fatalf("%s: resource count changed from %d to %d", step.name, len(previous), len(current))
		}
		previous = current
	}
}
