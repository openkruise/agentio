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

	"google.golang.org/protobuf/proto"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	cel "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	stream "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	dynamicfilter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_modules/v3"
	"github.com/openkruise/agentio/pkg/model"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
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
            maxSize: 8KiB
            format:
              attributes:
                agentio.workload.namespace: "%DYNAMIC_METADATA(workload:namespace)%"
                tenant: "%REQ(X-TENANT-ID)%"
                sandbox: "%FILTER_STATE(agentio.sandbox.id:PLAIN)%"
            request: {}
            response: {include: [llm.messages]}
    - name: catch-all
      parser: {llm: {}}
      filters:
        - audit:
            format:
              attributes:
                agentio.workload.namespace: "%DYNAMIC_METADATA(alternate:ns)%"
            response: {}

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
	cfg := effectiveConfig{gateway: &configv1.EgressGateway{}}
	for _, tls := range []bool{false, true} {
		b := resourceBuilder{}
		manager, err := b.buildForwardHCM(HTTPForwardProxy, cfg, tls)
		if err != nil {
			t.Fatal(err)
		}
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
		if out.GetLogFormat().GetTextFormatSource().GetInlineString() != "%FILTER_STATE(agentio.body_processing.audit:PLAIN)%" {
			t.Fatal(out)
		}
	}
}

func TestBodyProcessingRulesOnlyChangeECDS(t *testing.T) {
	in := Inputs{DiscoveryAddress: "agentiod:15012", TrustDomain: "cluster.local", Gateway: testGateway(&configv1.EgressGateway{})}
	before, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := config.ApplyAgentioConfig(bodyProcessingYAML, &configv1.AgentioConfig{})
	if err != nil {
		t.Fatal(err)
	}
	in.BodyProcessing = settings.BodyProcessing
	after, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("resource count changed")
	}
	originals := make(map[model.ResourceKey]model.Resource)
	for _, res := range before {
		originals[res.Key] = res
	}
	changed := 0
	for _, res := range after {
		old, ok := originals[res.Key]
		if !ok {
			t.Fatal(res.Key)
		}
		if res.Key.TypeURL == model.ExtensionConfigurationType && res.XDSName == bodyProcessingName {
			changed++
			ext := &core.TypedExtensionConfig{}
			if err := res.Value.UnmarshalTo(ext); err != nil {
				t.Fatal(err)
			}
			if ext.Name != bodyProcessingName || !proto.Equal(unpackBodyRules(t, ext.TypedConfig), settings.BodyProcessing) {
				t.Fatal(ext)
			}
			if proto.Equal(old.Value, res.Value) {
				t.Fatal("rules did not update")
			}
		} else if old.Hash != res.Hash || !proto.Equal(old.Value, res.Value) {
			t.Fatalf("unexpected change to %v", res.Key)
		}
	}
	if changed != 1 {
		t.Fatalf("got %d body processing resources", changed)
	}
}
