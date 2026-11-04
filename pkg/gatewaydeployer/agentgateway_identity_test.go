// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package gatewaydeployer

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestAgentgatewayPorterIdentityConfiguration(t *testing.T) {
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
	porter := config["frontendPolicies"].(map[string]any)["hboneExtProc"].(map[string]any)
	if porter["host"] != "127.0.0.1:9002" || porter["timeout"] != "5s" ||
		porter["requestAttributes"].(map[string]any)[model.AttributePeerCertificate] != `has(source.certificate) ? source.certificate : ""` {
		t.Fatalf("Porter must receive the authenticated outer TLS context: %v", porter)
	}
	listeners := config["binds"].([]any)[1].(map[string]any)["listeners"].([]any)
	route := listeners[0].(map[string]any)["routes"].([]any)[0].(map[string]any)
	processor := route["policies"].(map[string]any)["extProc"].(map[string]any)
	if processor["name"] != "system/epe-0.agentio-extproc" || processor["port"] != float64(9002) {
		t.Fatalf("ServiceRef must use native name/port fields: %v", processor)
	}
	attributes := processor["requestAttributes"].(map[string]any)
	if attributes[model.AttributeWorkloadUID] != "source.connectMetadata.agentio.workload.uid" ||
		attributes["source.address"] != agentgatewaySourceAddress {
		t.Fatalf("identity did not come from immutable CONNECT metadata: %v", attributes)
	}
	candidates := attributes["agentio.route.candidates"].(string)
	if !strings.Contains(candidates, "192.0.2.1") || !strings.Contains(candidates, "192.0.2.2") {
		t.Fatal("EPE did not receive the static endpoint candidates")
	}
	if !strings.Contains(candidates, `destination.hostname == "api.example"`) {
		t.Fatal("static candidates must match the normalized hostname, including case and port handling")
	}
	for _, value := range listeners {
		listener := value.(map[string]any)
		if listener["protocol"] == "HTTPS" && listener["hostname"] == "*" {
			return
		}
	}
	t.Fatal("Porter cannot select TLS termination without a wildcard HTTPS listener")
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
