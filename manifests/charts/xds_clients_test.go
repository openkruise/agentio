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
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/model"
)

func TestEPEXDSEgressAuthorization(t *testing.T) {
	for _, tls := range []bool{false, true} {
		t.Run(map[bool]string{false: "plaintext extproc", true: "mtls extproc"}[tls], func(t *testing.T) {
			args := []string{
				"--namespace",
				"custom-system",
				"--set",
				"epe.mode=managed,epe.enableXDSEgressAuthz=true,epe.serviceAccount.name=custom-epe,global.trustDomain=example.com,global.clusterId=custom-cluster,agentiod.fullnameOverride=custom-control",
			}
			if tls {
				args = append(args, "--set", "epe.tls.enabled=true")
			}
			manifest := renderAgentio(t, args...)
			foundConfig, foundDeployment := false, false
			for doc := range strings.SplitSeq(manifest, "\n---") {
				var obj renderedObject
				if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
					t.Fatal(err)
				}
				switch {
				case obj.Kind == "ConfigMap" && obj.Metadata.Name == "agentio-config":
					var cm corev1.ConfigMap
					if err := yaml.Unmarshal([]byte(doc), &cm); err != nil {
						t.Fatal(err)
					}
					cfg, err := config.Apply(cm.Data["config"], &configv1.AgentioConfig{})
					if err != nil {
						t.Fatal(err)
					}
					if err := model.ValidateXDSClients(cfg.GetXdsClients()); err != nil {
						t.Fatal(err)
					}
					grants := cfg.GetXdsClients()
					if len(grants) != 1 ||
						grants[0].GetPrincipal() != "spiffe://example.com/ns/custom-system/sa/custom-epe" ||
						!slices.Equal(grants[0].GetResources(), []string{"Workload", "TrafficPolicy"}) {
						t.Fatalf("grants = %v", grants)
					}
					foundConfig = true
				case obj.Kind == "Deployment" && obj.Metadata.Name == "agentio-epe":
					var dep appsv1.Deployment
					if err := yaml.Unmarshal([]byte(doc), &dep); err != nil {
						t.Fatal(err)
					}
					pod := dep.Spec.Template.Spec
					if pod.ServiceAccountName != "custom-epe" {
						t.Fatalf("SA = %s", pod.ServiceAccountName)
					}
					container := pod.Containers[0]
					for _, arg := range []string{"--enable-xds-egressauthz", "--xds-address=custom-control.custom-system.svc.cluster.local:15012", "--xds-root-path=/var/run/secrets/agentio/root-cert.pem", "--xds-token-path=/var/run/secrets/tokens/agentio-token", "--xds-cluster-id=custom-cluster"} {
						if !slices.Contains(container.Args, arg) {
							t.Fatalf("missing argument %s", arg)
						}
					}
					for _, name := range []string{"POD_NAME", "POD_NAMESPACE", "POD_UID", "POD_IP"} {
						if !slices.ContainsFunc(
							container.Env,
							func(env corev1.EnvVar) bool { return env.Name == name && env.ValueFrom.FieldRef.FieldPath != "" },
						) {
							t.Fatalf("missing identity %s", name)
						}
					}
					if len(pod.Volumes) != 2 || len(container.VolumeMounts) != 2 {
						t.Fatalf("TLS/xDS mounts not shared: %+v", pod.Volumes)
					}
					for _, vol := range pod.Volumes {
						if vol.Name == "workload-token" &&
							vol.Projected.Sources[0].ServiceAccountToken.Audience != "agentio-ca" {
							t.Fatal("wrong token audience")
						}
					}
					foundDeployment = true
				}
			}
			if !foundConfig || !foundDeployment {
				t.Fatal("missing EPE deployment or control-plane grant")
			}
		})
	}
	disabled := renderAgentio(t, "--set", "epe.mode=managed")
	if strings.Contains(disabled, "xdsClients:") || strings.Contains(disabled, "--enable-xds-egressauthz") {
		t.Fatal("xDS authorization must remain opt-in")
	}
}
