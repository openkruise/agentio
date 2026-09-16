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

package gateway

import (
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/util/file"
	"istio.io/istio/pkg/test/util/tmpl"
	"istio.io/istio/pkg/test/util/yml"
)

const agentioSandboxEgressLabel = "networking.agents.kruise.io/sandbox-egress"

func renderAgentioWaypointDeployment(t *testing.T, sandboxEgress, sniTrafficPolicyEnabled bool) *appsv1.Deployment {
	t.Helper()

	template, err := inject.ParseTemplates(map[string]string{
		"waypoint": file.AsStringOrFail(t, filepath.Join(
			env.IstioSrc, "manifests/charts/agentio/files/waypoint-injection-template.yaml")),
	})
	if err != nil {
		t.Fatal(err)
	}

	policyEnv := ""
	if sniTrafficPolicyEnabled {
		policyEnv = "\n    ENABLE_SNI_TRAFFIC_POLICY: true"
	}
	values, err := inject.NewValuesConfig(`
global:
  hub: test
  tag: test
  pilotCertProvider: istiod
  proxy:
    image: proxyv2
    clusterDomain: cluster.local
    readinessFailureThreshold: 4
    readinessInitialDelaySeconds: 0
    readinessPeriodSeconds: 15
  waypoint: {}
pilot:
  env:
    PILOT_ENABLE_AMBIENT: "true"` + policyEnv)
	if err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{}
	if sandboxEgress {
		labels[agentioSandboxEgressLabel] = "true"
	}
	gw := &gatewayapi.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress",
			Namespace: "agentio-system",
		},
		Spec: gatewayapi.GatewaySpec{
			GatewayClassName: "istio-waypoint",
		},
	}
	proxyConfig := mesh.DefaultProxyConfig()
	input := derivedInput{
		TemplateInput: TemplateInput{
			Gateway:              gw,
			GatewayClass:         "istio-waypoint",
			DeploymentName:       "egress",
			ServiceAccount:       "egress",
			KubeVersion:          30,
			ProxyUID:             1337,
			ProxyGID:             1337,
			InfrastructureLabels: labels,
			GatewayNameLabel:     "gateway.networking.k8s.io/gateway-name",
			ControllerLabel:      "istio.io-mesh-controller",
		},
		ProxyImage:  "example.com/proxyv2:test",
		ProxyConfig: proxyConfig,
		MeshConfig:  mesh.DefaultMeshConfig(),
		Values:      values.Map(),
	}

	rendered, err := tmpl.Execute(template["waypoint"], input)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range yml.SplitString(rendered) {
		var typeMeta metav1.TypeMeta
		if err := yaml.Unmarshal([]byte(document), &typeMeta); err != nil {
			t.Fatal(err)
		}
		if typeMeta.Kind != "Deployment" {
			continue
		}
		deployment := &appsv1.Deployment{}
		if err := yaml.Unmarshal([]byte(document), deployment); err != nil {
			t.Fatal(err)
		}
		return deployment
	}
	t.Fatal("waypoint template did not render a Deployment")
	return nil
}

func TestAgentioWaypointPolicyStore(t *testing.T) {
	const enabled = "true"
	tests := []struct {
		name                    string
		sandboxEgress           bool
		sniTrafficPolicyEnabled bool
		want                    bool
	}{
		{
			name:                    "enabled sandbox egress gateway",
			sandboxEgress:           true,
			sniTrafficPolicyEnabled: true,
			want:                    true,
		},
		{
			name:                    "ordinary waypoint",
			sniTrafficPolicyEnabled: true,
		},
		{
			name:          "feature disabled",
			sandboxEgress: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deployment := renderAgentioWaypointDeployment(t, tt.sandboxEgress, tt.sniTrafficPolicyEnabled)
			settings := map[string]*corev1.EnvVar{}
			for i := range deployment.Spec.Template.Spec.Containers[0].Env {
				envVar := &deployment.Spec.Template.Spec.Containers[0].Env[i]
				if envVar.Name == "PEER_METADATA_DISCOVERY" || envVar.Name == "ENABLE_POLICY_STORE" {
					settings[envVar.Name] = envVar
				}
			}
			if tt.want {
				if capability := settings["PEER_METADATA_DISCOVERY"]; capability == nil || capability.Value != "true" {
					t.Fatalf("PEER_METADATA_DISCOVERY = %#v, want true", capability)
				}
				if capability := settings["ENABLE_POLICY_STORE"]; capability == nil || capability.Value != enabled {
					t.Fatalf("ENABLE_POLICY_STORE = %#v, want %q", capability, enabled)
				}
			} else if len(settings) != 0 {
				t.Fatalf("policy store settings = %#v, want absent", settings)
			}
		})
	}
}

func TestAgentioWaypointCredentialMounts(t *testing.T) {
	deployment := renderAgentioWaypointDeployment(t, true, false)
	spec := deployment.Spec.Template.Spec
	proxy := spec.Containers[0]
	envs := map[string]string{}
	for _, env := range proxy.Env {
		envs[env.Name] = env.Value
	}
	if envs["JWT_PATH"] != "/var/run/secrets/tokens/agentio-token" || envs["CA_ROOT_CA"] != "/var/run/secrets/agentio/root-cert.pem" || envs["XDS_ROOT_CA"] != envs["CA_ROOT_CA"] {
		t.Fatalf("credential env = %v", envs)
	}
	volumes := map[string]corev1.Volume{}
	for _, volume := range spec.Volumes {
		volumes[volume.Name] = volume
	}
	mounts := map[string]string{}
	for _, mount := range proxy.VolumeMounts {
		if _, ok := volumes[mount.Name]; !ok {
			t.Fatalf("missing volume %q", mount.Name)
		}
		mounts[mount.Name] = mount.MountPath
	}
	token := volumes["agentio-token"].Projected
	if token == nil || len(token.Sources) != 1 || token.Sources[0].ServiceAccountToken == nil {
		t.Fatal("missing projected token")
	}
	if mounts["agentio-token"]+"/"+token.Sources[0].ServiceAccountToken.Path != envs["JWT_PATH"] {
		t.Fatal("JWT path does not match projected token")
	}
	if volumes["agentio-ca-certs"].ConfigMap == nil || mounts["agentio-ca-certs"]+"/root-cert.pem" != envs["CA_ROOT_CA"] {
		t.Fatal("CA path does not match ConfigMap mount")
	}
}
