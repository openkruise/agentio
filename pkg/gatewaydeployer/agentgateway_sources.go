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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func (d *DeploymentController) requeueAgentgateways() {
	for _, gw := range d.clients.Gateways.List(metav1.NamespaceAll, labels.Everything()) {
		if string(gw.Spec.GatewayClassName) == "agentio-agentgateway" {
			d.queue.AddObject(gw)
		}
	}
}

func (d *DeploymentController) watchAgentgatewaySources() func() {
	var registrations []krt.HandlerRegistration
	sources := d.agentgatewaySources
	if sources.Config != nil {
		registrations = append(registrations, sources.Config.Register(func(krt.Event[model.AgentioConfiguration]) {
			d.requeueAgentgateways()
		}))
	}
	if sources.Services != nil {
		registrations = append(registrations, sources.Services.Register(func(krt.Event[model.Service]) {
			d.requeueAgentgateways()
		}))
	}
	if sources.Endpoints != nil {
		registrations = append(registrations, sources.Endpoints.Register(func(krt.Event[model.Endpoint]) {
			d.requeueAgentgateways()
		}))
	}
	if sources.Secrets != nil {
		registrations = append(registrations, sources.Secrets.Register(func(krt.Event[*corev1.Secret]) {
			d.requeueAgentgateways()
		}))
	}
	return func() {
		for _, registration := range registrations {
			registration.UnregisterHandler()
		}
	}
}

func (d *DeploymentController) agentgatewayTrustBundle(settings *configv1.EgressGateway) (string, error) {
	sources := settings.GetUpstreamTrustBundle().GetAdditionalSources()
	baseline := d.agentgatewaySources.TrustBundle
	if len(sources) == 0 {
		return baseline, nil
	}
	if baseline == "" {
		return "", fmt.Errorf("upstreamTrustBundle requires the built-in public CA package")
	}
	bundles := [][]byte{[]byte(baseline)}
	for _, source := range sources {
		ref := source.GetConfigMapRef()
		var data []byte
		if ref != nil {
			cm := d.clients.ConfigMaps.Get(ref.GetName(), d.systemNamespace)
			if cm == nil {
				return "", fmt.Errorf("upstreamTrustBundle ConfigMap %s/%s not found", d.systemNamespace, ref.GetName())
			}
			data = []byte(cm.Data[ref.GetKey()])
		} else {
			ref = source.GetSecretRef()
			if d.agentgatewaySources.Secrets == nil {
				return "", fmt.Errorf("upstreamTrustBundle Secret discovery is unavailable")
			}
			secret := d.agentgatewaySources.Secrets.GetKey(d.systemNamespace + "/" + ref.GetName())
			if secret == nil {
				return "", fmt.Errorf("upstreamTrustBundle Secret %s/%s not found", d.systemNamespace, ref.GetName())
			}
			data = (*secret).Data[ref.GetKey()]
		}
		if _, _, err := clienttrust.Merge([][]byte{data}, time.Now()); err != nil {
			return "", fmt.Errorf("upstreamTrustBundle source %s key %q: %w", ref.GetName(), ref.GetKey(), err)
		}
		bundles = append(bundles, data)
	}
	merged, _, err := clienttrust.Merge(bundles, time.Now())
	return string(merged), err
}

// Each native Service has explicit endpoints; an empty set never falls back to DNS.
func agentgatewayProcessorServices(
	providers []*configv1.ExtProcProvider,
	inputs agentgatewayConfigInputs,
) ([]any, []any) {
	var services []any
	workloads := []any{}
	seen := map[string]bool{}
	for _, provider := range providers {
		ref := provider.GetServiceRef()
		if ref == nil {
			continue
		}
		port := provider.GetPort()
		if port == 0 {
			port = 9002
		}
		// A separate Service per processor port keeps endpoint port mappings independent.
		hostname := agentgatewayProcessorHostname(provider)
		key := ref.GetNamespace() + "/" + hostname
		if seen[key] {
			continue
		}
		seen[key] = true
		ports := map[uint32]uint32{port: port}
		services = append(services, map[string]any{
			"name":      ref.GetName(),
			"namespace": ref.GetNamespace(),
			"hostname":  hostname,
			"vips":      []any{},
			"ports":     ports,
		})
		selected := networking.SelectServiceEndpoints(networking.ServiceTarget{
			Namespace: ref.GetNamespace(),
			Name:      ref.GetName(),
			Port:      port,
		}, inputs.Services, inputs.Endpoints)
		for _, endpoint := range selected {
			workloads = append(workloads, map[string]any{
				"uid":         key + "/" + endpoint.ResourceName(),
				"name":        ref.GetName(),
				"namespace":   ref.GetNamespace(),
				"workloadIps": []string{endpoint.Address},
				"services":    map[string]any{key: map[uint32]uint32{port: endpoint.Port}},
			})
		}
	}
	return services, workloads
}

func agentgatewayProcessorHostname(provider *configv1.ExtProcProvider) string {
	ref := provider.GetServiceRef()
	// This is an internal discovery name, not a DNS lookup.
	return fmt.Sprintf("%s-%d.agentio-extproc", ref.GetName(), provider.GetPort())
}
