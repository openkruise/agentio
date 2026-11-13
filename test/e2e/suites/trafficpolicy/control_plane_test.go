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

package trafficpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/kube"
)

// TestControlPlaneConfigDebug validates that remote callers authenticate as a
// Kubernetes service account in the control-plane namespace and receive the
// effective, synced configuration rather than an internal mutable object.
func TestControlPlaneConfigDebug(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)

	rig.RunScenario(
		t,
		"authenticated snapshot and unauthenticated rejection",
		func(t *testing.T, _ *kube.ResourceScope) {
			environment := suite.Environment(t)
			endpoint := fmt.Sprintf(
				"http://agentiod.%s.svc.cluster.local:15014/debug/configz?kind=AgentioConfig&name=effective",
				resolvedAgentioConfig.Namespace,
			)
			ctx, cancel := e2e.Context(t, 2*time.Minute)
			defer cancel()

			stdout, stderr, err := trafficFixture.Client.Exec(ctx, []string{
				"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", endpoint,
			})
			if err != nil {
				t.Fatalf("request config debug endpoint without credentials: %v; stderr: %s", err, stderr)
			}
			if got := strings.TrimSpace(stdout); got != "401" {
				t.Fatalf("unauthenticated config debug status = %q, want 401", got)
			}

			reader := echo.Deploy(t, environment, echo.Config{
				Name:      "config-debug-reader",
				Namespace: resolvedAgentioConfig.Namespace,
				Image:     echo.DefaultImage,
				Ports:     echo.DefaultPorts(),
			})
			pod, err := environment.Cluster.Kube.CoreV1().
				Pods(reader.Namespace()).
				Get(ctx, reader.WorkloadsOrFail(t)[0].Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			token, err := environment.Cluster.Kube.CoreV1().
				ServiceAccounts(resolvedAgentioConfig.Namespace).
				CreateToken(
					ctx,
					pod.Spec.ServiceAccountName,
					&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
						Audiences: []string{"agentio-ca"},
						BoundObjectRef: &authenticationv1.BoundObjectReference{
							APIVersion: "v1",
							Kind:       "Pod",
							Name:       pod.Name,
							UID:        pod.UID,
						},
					}},
					metav1.CreateOptions{},
				)
			if err != nil {
				t.Fatalf("create config debug service account token: %v", err)
			}
			stdout, stderr, err = reader.Exec(ctx, []string{
				"curl", "-sS", "--fail-with-body", "-H", "Authorization: Bearer " + token.Status.Token, endpoint,
			})
			if err != nil {
				t.Fatalf("request config debug endpoint as root-namespace service account: %v; stderr: %s", err, stderr)
			}

			var response struct {
				Synced       bool           `json:"synced"`
				CountsByKind map[string]int `json:"countsByKind"`
				Items        []struct {
					Kind     string `json:"kind"`
					Metadata struct {
						Name string `json:"name"`
					} `json:"metadata"`
					Spec json.RawMessage `json:"spec"`
				} `json:"items"`
				Failures []struct {
					Key     string
					Message string
				} `json:"failures"`
			}
			if err := json.Unmarshal([]byte(stdout), &response); err != nil {
				t.Fatalf("decode config debug response: %v; body: %s", err, stdout)
			}
			if !response.Synced {
				t.Fatal("config debug endpoint reports synced=false")
			}
			if got := response.CountsByKind["AgentioConfig"]; got != 1 || len(response.Items) != 1 {
				t.Fatalf("config debug AgentioConfig count/items = %d/%d, want 1/1", got, len(response.Items))
			}
			item := response.Items[0]
			if item.Kind != "AgentioConfig" || item.Metadata.Name != "effective" {
				t.Fatalf("config debug item = %s/%s, want AgentioConfig/effective", item.Kind, item.Metadata.Name)
			}
			if len(response.Failures) != 0 {
				t.Fatalf("config debug failures = %+v, want none", response.Failures)
			}

			var effective struct {
				EgressGateways []struct {
					Name      string
					Namespace string
				} `json:"egressGateways"`
			}
			if err := json.Unmarshal(item.Spec, &effective); err != nil {
				t.Fatalf("decode effective AgentioConfig: %v; spec: %s", err, item.Spec)
			}
			if len(effective.EgressGateways) != 1 ||
				effective.EgressGateways[0].Name != "egress-gateway" ||
				effective.EgressGateways[0].Namespace != resolvedAgentioConfig.Namespace {
				t.Fatalf("effective egress gateways = %+v, want registered shared gateway", effective.EgressGateways)
			}
		},
	)
}
