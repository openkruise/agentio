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

package charts_test

import (
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/yaml"
)

func TestPolicyControlPlane(t *testing.T) {
	for _, profile := range []string{"sidecar", "ambient"} {
		t.Run(profile, func(t *testing.T) {
			manifest := renderAgentio(t, "--set", "profile="+profile,
				"--set", "agentiod.policyPool.enabled=true,agentiod.policyPool.replicaCount=3",
				"--set", "agentiod.policyPool.resources.requests.cpu=2,agentiod.resources.limits.cpu=4",
				"--set", "agentiod.networkPolicy.enabled=true,agentiod.autoscaling.enabled=true",
				"--set", "egressGateway.mode=static,epe.mode=managed,epe.tls.enabled=true")
			deployments := map[string]appsv1.Deployment{}
			services := map[string]corev1.Service{}
			for document := range strings.SplitSeq(manifest, "\n---") {
				var object renderedObject
				if err := yaml.Unmarshal([]byte(document), &object); err != nil {
					t.Fatal(err)
				}
				switch object.Kind {
				case "Deployment":
					var deployment appsv1.Deployment
					if err := yaml.Unmarshal([]byte(document), &deployment); err != nil {
						t.Fatal(err)
					}
					deployments[deployment.Name] = deployment
				case "Service":
					var service corev1.Service
					if err := yaml.Unmarshal([]byte(document), &service); err != nil {
						t.Fatal(err)
					}
					services[service.Name] = service
				}
			}
			proxy, policy := deployments["agentiod"], deployments["agentiod-policy"]
			if policy.Spec.Replicas == nil || *policy.Spec.Replicas != 3 {
				t.Fatal("policy replica count was not rendered")
			}
			if proxy.Spec.Replicas != nil {
				t.Fatal("proxy HPA was disabled")
			}
			wantSelector := map[string]string{
				"app.kubernetes.io/name":     "agentiod",
				"app.kubernetes.io/instance": "test",
			}
			if !reflect.DeepEqual(proxy.Spec.Selector.MatchLabels, wantSelector) {
				t.Fatalf("legacy Deployment selector changed: %v", proxy.Spec.Selector)
			}
			for _, name := range []string{"agentiod", "agentiod-policy"} {
				service, ok := services[name]
				if !ok {
					t.Fatalf("Service %s is missing", name)
				}
				for _, backend := range []appsv1.Deployment{proxy, policy} {
					matches := labels.SelectorFromSet(service.Spec.Selector).
						Matches(labels.Set(backend.Spec.Template.Labels))
					if matches != (backend.Name == name) {
						t.Fatalf("Service %s selects backend %s = %v", name, backend.Name, matches)
					}
				}
			}
			if policy.Spec.Template.Labels["agentio.kruise.io/control-plane-pool"] != "policy" {
				t.Fatal("policy pool label missing")
			}
			if policy.Spec.Template.Spec.ServiceAccountName != proxy.Spec.Template.Spec.ServiceAccountName {
				t.Fatal("pools must share the existing ServiceAccount")
			}
			env := map[string]string{}
			for _, variable := range policy.Spec.Template.Spec.Containers[0].Env {
				env[variable.Name] = variable.Value
			}
			for name, want := range map[string]string{
				"AGENTIO_SERVICE_NAME":                    "agentiod-policy",
				"AGENTIO_CA_SECRET_NAME":                  "agentio-ca-secret",
				"AGENTIO_ENABLE_SIDECAR_INJECTOR":         "false",
				"AGENTIO_ENABLE_GATEWAY_DEPLOYER":         "false",
				"AGENTIO_ENABLE_CLIENT_TRUST_DISTRIBUTOR": "false",
				"AGENTIO_XDS_CPU_BUDGET":                  "2",
			} {
				if env[name] != want {
					t.Fatalf("policy %s = %q, want %q", name, env[name], want)
				}
			}
			if got := policy.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu().String(); got != "2" {
				t.Fatalf("policy CPU request = %s", got)
			}
			if !policy.Spec.Template.Spec.Containers[0].Resources.Limits.Cpu().IsZero() {
				t.Fatal("policy inherited the proxy CPU limit")
			}
			policyAddress := "agentiod-policy.agentio-system.svc.cluster.local:15012"
			epe := deployments["agentio-epe"].Spec.Template.Spec.Containers[0]
			if !strings.Contains(strings.Join(epe.Args, "\n"), "--xds-address="+policyAddress) {
				t.Fatal("EPE ADS endpoint did not switch")
			}
			if !strings.Contains(strings.Join(epe.Args, "\n"), "-ca-address="+policyAddress) {
				t.Fatal("EPE CA endpoint did not switch")
			}
			gateway := deployments["agentio-egress"]
			for _, container := range gateway.Spec.Template.Spec.Containers {
				for _, variable := range container.Env {
					if variable.Name == "CA_ADDR" || variable.Name == "AGENTIO_XDS_ADDRESS" {
						if variable.Value != policyAddress {
							t.Fatalf("gateway %s = %q", variable.Name, variable.Value)
						}
					}
				}
				for _, arg := range container.Args {
					if strings.HasPrefix(arg, "--xds-address=") && arg != "--xds-address="+policyAddress {
						t.Fatalf("Porter address = %s", arg)
					}
				}
			}
			if profile == "sidecar" {
				requireContains(t, manifest, `xdsAddress: "agentiod.agentio-system.svc.cluster.local:15012"`,
					`gatewayXdsAddress: "`+policyAddress+`"`)
			} else {
				requireContains(t, manifest, `value: "agentiod.agentio-system.svc.cluster.local:15012"`)
			}
			var baseline appsv1.Deployment
			baselineYAML := renderAgentio(
				t,
				"--show-only",
				"templates/agentiod/deployment.yaml",
				"--set",
				"profile="+profile,
				"--set",
				"agentiod.resources.limits.cpu=4,agentiod.autoscaling.enabled=true",
			)
			if err := yaml.Unmarshal([]byte(baselineYAML), &baseline); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(proxy.Spec, baseline.Spec) {
				t.Fatal("enabling policy changed the existing agentiod Deployment spec")
			}
		})
	}
}

func TestPolicyControlPlaneNamesAndValidation(t *testing.T) {
	manifest := renderAgentio(
		t,
		"--set",
		"agentiod.policyPool.enabled=true,agentiod.fullnameOverride=custom-control,agentiod.serviceAccount.name=shared-control",
	)
	requireContains(
		t,
		manifest,
		"name: custom-control-policy",
		`value: "custom-control-policy"`,
		"serviceAccountName: shared-control",
	)
	requireRenderError(t, "/agentiod/policyPool/replicaCount", "--set", "agentiod.policyPool.replicaCount=0")
}
