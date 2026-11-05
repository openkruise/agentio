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

package gatewaydeployer

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAgentgatewayGeneratedUsesOfficialInterfaces(t *testing.T) {
	gateway, _ := agentgatewayFixture()
	content, err := agentgatewayEgressConfig(agentgatewaySettings(t, `
serviceEntries:
- hosts: [api.example]
  endpoints: [{address: 192.0.2.1}, {address: 192.0.2.2}]
extProc: {serviceRef: {name: epe, namespace: system}}
`), extractServicePorts(*gateway), agentgatewayConfigInputs{MITM: true})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		t.Fatal(err)
	}
	for _, custom := range []string{"hboneExtProc", "source.connectMetadata", "agentio.route.candidates"} {
		if strings.Contains(content, custom) {
			t.Fatalf("generated configuration requires an agentgateway patch: %s", custom)
		}
	}
	listeners := config["binds"].([]any)[1].(map[string]any)["listeners"].([]any)
	route := listeners[0].(map[string]any)["routes"].([]any)[0].(map[string]any)
	processor := route["policies"].(map[string]any)["extProc"].(map[string]any)
	if processor["name"] != "system/epe-0.agentio-extproc" || processor["port"] != float64(9002) {
		t.Fatalf("ServiceRef must use native name/port fields: %v", processor)
	}
	attributes := processor["requestAttributes"].(map[string]any)
	if attributes["source.address"] != agentgatewaySourceAddress {
		t.Fatal("native processor did not receive its source address")
	}
	for _, value := range listeners {
		listener := value.(map[string]any)
		if listener["protocol"] == "HTTPS" {
			t.Fatal("mounting a CA must not enable unsupported Porter-driven termination")
		}
	}
}

func TestGatewayStatusAddressesAreAnArrayBeforeAssignment(t *testing.T) {
	gateway, _ := agentgatewayFixture()
	rig := newControllerTestRig(t, gateway)
	defer rig.close()
	controller := rig.newController()
	for _, write := range []func() error{
		func() error { return controller.setGatewayControllerVersion(*gateway) },
		func() error {
			return controller.setGatewayStatus(*gateway, TemplateInput{}, builtinClasses["agentio-agentgateway"])
		},
		func() error { return controller.setGatewayConfigError(*gateway, fmt.Errorf("invalid parameters")) },
	} {
		if err := write(); err != nil {
			t.Fatal(err)
		}
		patch := rig.patcher.find("gateways")
		var output map[string]any
		if err := json.Unmarshal(patch.data, &output); err != nil {
			t.Fatal(err)
		}
		if _, valid := output["status"].(map[string]any)["addresses"].([]any); !valid {
			t.Fatal("Gateway API rejects null status.addresses")
		}
	}
}
