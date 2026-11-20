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

	udpa "github.com/cncf/xds/go/udpa/type/v1"
	cel "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
)

const contentGuardYAML = `
contentGuard:
  defaults: {schema: genai, maxLogBytes: 4096}
  attributes:
    tenant.id: {requestHeader: x-tenant}
    agentio.sandbox.id: {filterState: agentio.sandbox.id}
    agentio.workload.namespace: {dynamicMetadata: {namespace: agentio, path: [workload, namespace]}}
  rules:
    - match: {hosts: [skip.llm.test]}
      skip: true
    - match:
        hosts: ["*.llm.test"]
        filterState:
          - {key: agentio.sandbox.id, values: [box-1, box-2]}
          - {key: agentio.sandbox.id, present: true}
      audit:
        schema: agentio
        parsers:
          llm: {protocol: openai-responses, response: {include: [messages]}}
          generic: {request: {}}
`

func TestContentGuardGatewayConfig(t *testing.T) {
	settings, err := config.ApplyAgentioConfig(contentGuardYAML, &configv1.AgentioConfig{})
	if err != nil {
		t.Fatal(err)
	}
	original := proto.CloneOf(settings.ContentGuard)
	b := resourceBuilder{contentGuard: settings.ContentGuard}
	for _, tls := range []bool{false, true} {
		manager, err := b.buildForwardHCM(HTTPForwardProxy, effectiveConfig{gateway: &configv1.EgressGateway{}}, tls)
		if err != nil {
			t.Fatal(err)
		}
		filters := manager.HttpFilters
		projector, module := filters[len(filters)-3], filters[len(filters)-2]
		p := &state.Config{}
		if err := projector.GetTypedConfig().UnmarshalTo(p); err != nil {
			t.Fatal(err)
		}
		if len(p.OnRequestHeaders) != 1 ||
			p.OnRequestHeaders[0].GetFormatString().
				GetTextFormatSource().
				GetInlineString() !=
				"%DYNAMIC_METADATA(agentio:workload:namespace)%" {
			t.Fatal(p)
		}
		wire := &udpa.TypedStruct{}
		if err := module.GetTypedConfig().UnmarshalTo(wire); err != nil {
			t.Fatal(err)
		}
		var moduleSettings struct {
			Rules      []map[string]any
			Attributes map[string]map[string]string
		}
		raw := wire.Value.Fields["filter_config"].GetStructValue().Fields["value"].GetStringValue()
		if err := json.Unmarshal([]byte(raw), &moduleSettings); err != nil {
			t.Fatal(err)
		}
		if len(moduleSettings.Rules) != 2 ||
			moduleSettings.Attributes["agentio.workload.namespace"]["filterState"] != p.OnRequestHeaders[0].GetObjectKey() {
			t.Fatal(raw)
		}
		if len(manager.AccessLog) != 2 {
			t.Fatal(manager.AccessLog)
		}
		for i, direction := range []string{"request", "response"} {
			f := &cel.ExpressionFilter{}
			if err := manager.AccessLog[i].Filter.GetExtensionFilter().GetTypedConfig().UnmarshalTo(f); err != nil {
				t.Fatal(err)
			}
			if f.Expression != "'agentio.contentguard."+direction+"' in filter_state" {
				t.Fatal(f)
			}
		}
	}
	// Building both chains must leave the immutable configuration usable on the next update.
	if !proto.Equal(settings.ContentGuard, original) {
		t.Fatal("builder mutated shared config")
	}
}

func TestContentGuardLogDirections(t *testing.T) {
	for _, tc := range []struct {
		rule string
		logs int
	}{
		{"skip: true", 0},
		{"audit: {parsers: {generic: {response: {}}}}", 1},
	} {
		settings, err := config.ApplyAgentioConfig(
			"contentGuard:\n  rules:\n    - match: {}\n      "+tc.rule,
			&configv1.AgentioConfig{},
		)
		if err != nil {
			t.Fatal(err)
		}
		b := resourceBuilder{contentGuard: settings.ContentGuard}
		_, logs, err := b.contentGuardConfig()
		if err != nil || len(logs) != tc.logs {
			t.Fatalf("%s: logs=%v err=%v", tc.rule, logs, err)
		}
		if len(logs) == 1 {
			f := &cel.ExpressionFilter{}
			if err := logs[0].Filter.GetExtensionFilter().GetTypedConfig().UnmarshalTo(f); err != nil ||
				f.Expression != "'agentio.contentguard.response' in filter_state" {
				t.Fatal(f, err)
			}
		}
	}
}
