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
	"bytes"
	"os/exec"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestChartValuesReachGatewayPods(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	output, err := exec.Command(
		"helm",
		"template",
		"test",
		"../../manifests/charts/agentio",
		"--namespace",
		"agentio-system",
		"--set",
		"agentiod.gatewayDeployer.enabled=true",
		"--set",
		"global.imagePullSecrets[0].name=registry-creds",
		"--set",
		"egressGateway.enabled=true,egressGateway.resources.requests.cpu=250m,egressGateway.nodeSelector.pool=gateways",
		"--set",
		"egressGateway.image.repository=registry.example/shared-envoy,egressGateway.image.tag=tested",
		"--set",
		"egressGateway.porter.image.repository=registry.example/shared-porter,egressGateway.porter.image.tag=tested",
		"--set", "egressGateway.terminationGracePeriodSeconds=45",
		"--set", "egressGateway.tolerations[0].key=gateway,egressGateway.tolerations[0].operator=Exists",
		"--set", "egressGateway.agentConfig.logAsJSON=true",
		"--set", "egressGateway.agentgateway.ca.enabled=true",
		"--set", "egressGateway.porter.cache.maxEntries=123",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, output)
	}
	var injector corev1.ConfigMap
	for doc := range bytes.SplitSeq(output, []byte("\n---")) {
		var cm corev1.ConfigMap
		if err := yaml.Unmarshal(doc, &cm); err != nil {
			t.Fatal(err)
		}
		if cm.Kind == "ConfigMap" && cm.Name == "agentio-sidecar-injector" {
			injector = cm
		}
		if cm.Kind == "Deployment" && cm.Name == "agentio-egress" {
			var deployment appsv1.Deployment
			if err := yaml.Unmarshal(doc, &deployment); err != nil {
				t.Fatal(err)
			}
			pod := deployment.Spec.Template.Spec
			if pod.Containers[0].Image != "registry.example/shared-envoy:tested" ||
				pod.InitContainers[0].Image != "registry.example/shared-porter:tested" ||
				pod.Containers[0].Resources.Requests.Cpu().MilliValue() != 250 ||
				pod.NodeSelector["pool"] != "gateways" ||
				*pod.TerminationGracePeriodSeconds != 45 || len(pod.Tolerations) != 1 ||
				!slices.Contains(pod.InitContainers[0].Args, "--xds-cache-max-entries=123") {
				t.Fatalf("shared gateway defaults did not reach the Helm-managed Pod: %+v", pod)
			}
		}
	}
	provider, err := newTemplateProvider(testOptions(), defaultProxyConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.updateFromInjectorConfig(injector.Data["config"], injector.Data["values"]); err != nil {
		t.Fatal(err)
	}
	for _, template := range []string{egressGatewayTemplateName, agentgatewayTemplateName} {
		t.Run(template, func(t *testing.T) {
			gw := egressGatewayFixture("gateway", "demo")
			input := templateInputForTest(gw, parityKubeVersion)
			input.AgentgatewayIdentity = template == agentgatewayTemplateName
			docs, err := provider.Renderer().Render(template, input)
			if err != nil {
				t.Fatal(err)
			}
			for _, doc := range docs {
				var deployment appsv1.Deployment
				if err := yaml.Unmarshal([]byte(doc), &deployment); err != nil {
					t.Fatal(err)
				}
				if deployment.Kind != "Deployment" {
					continue
				}
				pod := deployment.Spec.Template.Spec
				if len(pod.ImagePullSecrets) != 1 || pod.ImagePullSecrets[0].Name != "registry-creds" {
					t.Fatalf("imagePullSecrets = %+v", pod.ImagePullSecrets)
				}
				if pod.InitContainers[0].Image != "registry.example/shared-porter:tested" ||
					!slices.Contains(pod.InitContainers[0].Args, "--xds-cache-max-entries=123") {
					t.Fatalf("shared Porter image did not reach %s: %+v", template, pod.InitContainers)
				}
				if template == egressGatewayTemplateName {
					if !slices.Contains(pod.Containers[0].Env, corev1.EnvVar{
						Name:  "AGENTIO_GATEWAY_CONFIG",
						Value: `{"logAsJSON":true}`,
					}) {
						t.Fatalf("shared agent settings did not reach the Gateway API Pod: %+v", pod.Containers[0].Env)
					}
					if pod.Containers[0].Resources.Requests.Cpu().MilliValue() != 250 ||
						pod.Containers[0].Image != "registry.example/shared-envoy:tested" ||
						pod.NodeSelector["pool"] != "gateways" || len(pod.Tolerations) != 1 || *pod.TerminationGracePeriodSeconds != 45 {
						t.Fatalf("gateway resource/scheduling values did not reach Pod: %+v", pod)
					}
				} else if pod.Containers[0].Resources.Requests.Cpu().MilliValue() != 100 ||
					len(pod.NodeSelector) != 0 {
					t.Fatalf("native defaults must be independent of Envoy defaults: %+v", pod)
				}
				return
			}
			t.Fatal("missing gateway Deployment")
		})
	}
}
