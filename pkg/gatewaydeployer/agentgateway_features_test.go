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
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestAgentgatewayGeneratedMITM(t *testing.T) {
	settings := agentgatewaySettings(t, `
tlsTermination:
  includeHosts: ['*.example', api.example]
  excludeHosts: [API.EXAMPLE, private.example]
serviceEntries:
- hosts: [static.example]
  endpoints: [{address: 192.0.2.10}]
http: {acceptHttp10: false}
`)
	gw, _ := agentgatewayFixture()
	content, err := agentgatewayEgressConfig(settings, extractServicePorts(*gw), agentgatewayConfigInputs{
		MITM:        true,
		TrustBundle: "public and private CAs",
	})
	if err != nil {
		t.Fatal(err)
	}
	if schema := os.Getenv("AGENTIO_AGENTGATEWAY_SCHEMA"); schema != "" {
		validateAgentgatewaySchema(t, t.Context(), schema, content)
	}
	var output map[string]any
	if err := json.Unmarshal([]byte(content), &output); err != nil {
		t.Fatal(err)
	}
	if output["frontendPolicies"].(map[string]any)["connect"].(map[string]any)["mode"] != "deny" {
		t.Fatal("native CONNECT termination must not replace forwarding to the original HTTP proxy")
	}
	listeners := output["binds"].([]any)[1].(map[string]any)["listeners"].([]any)
	found := false
	for _, value := range listeners {
		listener := value.(map[string]any)
		host := listener["hostname"]
		if host == "api.example" || host == "private.example" {
			if listener["protocol"] != "TLS" || listener["tls"] != nil {
				t.Fatalf("excluded host %v was terminated", host)
			}
		}
		if host != "*.example" {
			continue
		}
		found = true
		if listener["tls"].(map[string]any)["mode"] != "dynamicCa" {
			t.Fatal("TLS listener does not issue SNI certificates")
		}
		for _, value := range listener["routes"].([]any) {
			route := value.(map[string]any)
			backend := route["backends"].([]any)[0].(map[string]any)
			tls := backend["policies"].(map[string]any)["backendTLS"].(map[string]any)
			if tls["root"] != "/etc/agentgateway/upstream-root.pem" {
				t.Fatal("TLS origination lost the public/private trust union")
			}
			if hosts, ok := route["hostnames"]; ok && hosts.([]any)[0] == "static.example" {
				if tls["hostname"] != "static.example" {
					t.Fatal("static IP backend must verify the service hostname")
				}
			}
		}
	}
	if !found {
		t.Fatal("missing HTTPS listener")
	}
	if _, err := agentgatewayEgressConfig(settings, extractServicePorts(*gw), agentgatewayConfigInputs{}); err == nil {
		t.Fatal("MITM silently accepted a missing signing Secret")
	}
}

func TestAgentgatewayV170RetryCount(t *testing.T) {
	settings := agentgatewaySettings(t, "http: {routing: {fallback: {retries: {attempts: 2, retryOn: '503'}}}}")
	policies, err := agentgatewayRoutePolicies(settings.GetHttp().GetRouting().GetFallback())
	if err != nil {
		t.Fatal(err)
	}
	if got := policies["retry"].(map[string]any)["attempts"]; got != int32(2) {
		t.Fatalf("v1.7.0 attempts counts retries, so two retries must remain two, got %v", got)
	}
}

func TestAgentgatewayGeneratedProcessorChain(t *testing.T) {
	global := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{Service: "primary.example"},
		AdditionalExtProcs: []*configv1.ExtProcProvider{{
			Service: "secondary.example",
			Response: &configv1.ProcessingModeOptions{
				HeaderMode: configv1.HeaderSendMode_SEND,
				Attributes: []string{"response.code", "response.headers"},
			},
		}},
	}
	gw, _ := agentgatewayFixture()
	inputs := agentgatewayConfigInputs{Global: global}
	content, err := agentgatewayEgressConfig(&configv1.EgressGateway{}, extractServicePorts(*gw), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if schema := os.Getenv("AGENTIO_AGENTGATEWAY_SCHEMA"); schema != "" {
		validateAgentgatewaySchema(t, t.Context(), schema, content)
	}
	var output map[string]any
	if err := json.Unmarshal([]byte(content), &output); err != nil {
		t.Fatal(err)
	}
	listener := output["binds"].([]any)[1].(map[string]any)["listeners"].([]any)[0].(map[string]any)
	primary := listener["policies"].(map[string]any)["extProc"].(map[string]any)
	if primary["host"] != "primary.example:9002" {
		t.Fatalf("global primary must run before route processing: %v", primary)
	}
	routes := listener["routes"].([]any)
	secondary := routes[0].(map[string]any)["policies"].(map[string]any)["extProc"].(map[string]any)
	if secondary["host"] != "secondary.example:9002" ||
		secondary["responseAttributes"].(map[string]any)["response.code"] != "response.code" {
		t.Fatalf("additional processor or response attributes missing: %v", secondary)
	}
	content, err = agentgatewayEgressConfig(&configv1.EgressGateway{
		ExtProc: &configv1.ExtProcProvider{Service: "override.example"},
	}, extractServicePorts(*gw), inputs)
	if err != nil || !strings.Contains(content, "override.example") ||
		!strings.Contains(content, "secondary.example") || strings.Contains(content, "primary.example") {
		t.Fatalf("gateway override must replace only the primary processor: %s %v", content, err)
	}
	content, err = agentgatewayEgressConfig(
		&configv1.EgressGateway{ExtProc: &configv1.ExtProcProvider{}},
		extractServicePorts(*gw),
		inputs,
	)
	if err != nil || strings.Contains(content, "extProc") {
		t.Fatalf("explicit disable must disable the entire processor chain: %s %v", content, err)
	}
	global.AdditionalExtProcs = append(global.AdditionalExtProcs, &configv1.ExtProcProvider{Service: "third.example"})
	if _, err := agentgatewayEgressConfig(&configv1.EgressGateway{}, extractServicePorts(*gw), inputs); err == nil {
		t.Fatal("native two-phase processor limit was silently exceeded")
	}
}

func TestAgentgatewaySourceChangesRegenerateConfig(t *testing.T) {
	gw, cm := agentgatewayFixture()
	cm.Data = map[string]string{"config": "{}"}
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	global := krt.NewMutableCollection(nil, []model.AgentioConfiguration{{Value: &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{Service: "first.example"},
	}}})
	endpoints := krt.NewMutableCollection[model.Endpoint](nil, nil)
	d := rig.newController()
	d.renderer = generatedAgentgatewayRenderer(t)
	d.agentgatewaySources = AgentgatewaySources{
		Config:    global.AsCollection(),
		Endpoints: endpoints.AsCollection(),
		Services: krt.NewStaticCollection(nil, []model.Service{{
			Namespace: "system",
			Name:      "processor",
			Hostname:  "processor.system.svc.cluster.local",
			Ports:     []model.ServicePort{{Name: "grpc", Port: 9002}},
		}}),
	}
	unregister := d.watchAgentgatewaySources()
	defer unregister()
	go d.Run(rig.stop)
	global.UpdateObject(
		model.AgentioConfiguration{Value: &configv1.AgentioConfig{SandboxExtProc: &configv1.ExtProcProvider{
			ServiceRef: &configv1.ServiceReference{Name: "processor", Namespace: "system"},
		}}},
	)
	endpoints.UpdateObject(model.Endpoint{
		ServiceKey: "system/processor.system.svc.cluster.local",
		Address:    "10.0.0.9",
		PortName:   "grpc",
		Port:       12345,
		Ready:      true,
		Serving:    true,
	})
	waitCondition(t, 3*time.Second, func() bool {
		for _, patch := range rig.patcher.all() {
			if patch.gvr.Resource == "configmaps" && strings.Contains(string(patch.data), "10.0.0.9") &&
				strings.Contains(string(patch.data), "12345") {
				return true
			}
		}
		return false
	}, "global provider and EndpointSlice changes to regenerate native configuration")
}

func TestAgentgatewayProcessorEndpointDiscovery(t *testing.T) {
	provider := &configv1.ExtProcProvider{
		ServiceRef: &configv1.ServiceReference{Name: "processor", Namespace: "system"},
		Port:       9002,
	}
	service := model.Service{
		Namespace: "system",
		Name:      "processor",
		Hostname:  "processor.system.svc.custom",
		Ports:     []model.ServicePort{{Name: "grpc", Port: 9002, TargetPort: 10000}}}
	endpoint := model.Endpoint{
		ServiceKey: service.ResourceName(),
		Address:    "10.0.0.2",
		PortName:   "grpc",
		Port:       12345,
		Ready:      true,
		Serving:    true,
	}
	inputs := agentgatewayConfigInputs{
		Services:  []model.Service{service},
		Endpoints: []model.Endpoint{endpoint},
	}
	services, workloads := agentgatewayProcessorServices([]*configv1.ExtProcProvider{provider, provider}, inputs)
	if len(services) != 1 || len(workloads) != 1 {
		t.Fatalf("discovery did not deduplicate the referenced Service: %v %v", services, workloads)
	}
	key := "system/" + agentgatewayProcessorHostname(provider)
	ports := workloads[0].(map[string]any)["services"].(map[string]any)[key].(map[uint32]uint32)
	if ports[9002] != 12345 {
		t.Fatal("EndpointSlice port must override Service targetPort")
	}
	for _, state := range []model.Endpoint{
		{Ready: false, Serving: true}, {Ready: true, Serving: false}, {Ready: true, Serving: true, Terminating: true},
	} {
		ep := endpoint
		ep.Ready, ep.Serving, ep.Terminating = state.Ready, state.Serving, state.Terminating
		inputs.Endpoints = []model.Endpoint{ep}
		services, workloads = agentgatewayProcessorServices([]*configv1.ExtProcProvider{provider}, inputs)
		if len(services) != 1 || len(workloads) != 0 {
			t.Fatal("unavailable endpoints must leave an empty native Service, without DNS fallback")
		}
	}
}

func TestAgentgatewayGeneratedTrustAndHotUpdates(t *testing.T) {
	ca, err := pki.NewSelfSignedCA("test upstream", 365*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	gw, cm := agentgatewayFixture()
	cm.Data = map[string]string{
		"config": `upstreamTrustBundle: {additionalSources: [{configMapRef: {name: private-ca, key: ca.pem}}, {secretRef: {name: secret-ca, key: ca.pem}}]}`,
	}
	root := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "private-ca", Namespace: "agentio-system"},
		Data: map[string]string{"ca.pem": string(ca.CertificatePEM())}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-ca", Namespace: "agentio-system"},
		Data: map[string][]byte{"ca.pem": ca.CertificatePEM()}}
	rig := newControllerTestRig(t, gw, cm, root)
	defer rig.close()
	d := rig.newController()
	d.renderer = generatedAgentgatewayRenderer(t)
	d.agentgatewaySources = AgentgatewaySources{
		TrustBundle: string(ca.CertificatePEM()),
		Secrets:     krt.NewStaticCollection(nil, []*corev1.Secret{secret}),
	}
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	var first, next appsv1.Deployment
	if err := json.Unmarshal(rig.patcher.find("deployments").data, &first); err != nil {
		t.Fatal(err)
	}
	var generated corev1.ConfigMap
	if err := json.Unmarshal(rig.patcher.find("configmaps").data, &generated); err != nil {
		t.Fatal(err)
	}
	if strings.Count(generated.Data["upstream-root.pem"], "BEGIN CERTIFICATE") != 1 {
		t.Fatal("trust sources did not retain and deduplicate the baseline CA")
	}
	root.Data["ca.pem"] = "invalid certificate"
	if _, err := rig.kubeClient.CoreV1().
		ConfigMaps(root.Namespace).
		Update(t.Context(), root, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, time.Second, func() bool {
		return rig.configMaps.Get(root.Name, root.Namespace).Data["ca.pem"] == root.Data["ca.pem"]
	}, "invalid CA source update")
	rig.patcher.mu.Lock()
	rig.patcher.patches = nil
	rig.patcher.mu.Unlock()
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	if rig.patcher.find("configmaps") != nil || rig.patcher.find("deployments") != nil {
		t.Fatal("invalid CA source replaced the last valid gateway configuration")
	}
	if status := rig.patcher.find(
		"gateways",
	); status == nil ||
		!strings.Contains(string(status.data), `"status":"False"`) {
		t.Fatal("invalid CA source did not report a Gateway configuration error")
	}
	cm.Data["config"] = "http: {routing: {fallback: {timeout: 9s}}}"
	if _, err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(
		t,
		time.Second,
		func() bool { return rig.configMaps.Get(cm.Name, cm.Namespace).Data["config"] == cm.Data["config"] },
		"updated input",
	)
	rig.patcher.mu.Lock()
	rig.patcher.patches = nil
	rig.patcher.mu.Unlock()
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rig.patcher.find("deployments").data, &next); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Spec.Template, next.Spec.Template) ||
		!strings.Contains(string(rig.patcher.find("configmaps").data), "9s") {
		t.Fatal("route-only updates must change native configuration without restarting the Pod")
	}
}
