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

package agentgateway

import (
	"fmt"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openkruise/agentio/test/e2e"
	native "github.com/openkruise/agentio/test/e2e/components/agentgateway"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestAgentgatewayPorterEPEIdentity(t *testing.T) {
	env, scope := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 5*time.Minute)
	defer cancel()
	const name = "identity-egress"
	host := fmt.Sprintf("server.%s.svc.cluster.local", traffic.Namespace.Name())
	settings := native.Configuration(config.Namespace, name, "")
	settings.Object["data"] = map[string]any{"config": fmt.Sprintf(`
serviceEntries:
- hosts: [%s]
  endpoints: [{address: %s}]
extProc:
  serviceRef: {name: agentio-epe, namespace: %s}
  request: {attributes: ["filter_state['agentio.workload.uid']"]}
`, host, traffic.Server.ServiceIPOrFail(t), config.Namespace)}
	for _, object := range []*unstructured.Unstructured{settings, native.Gateway(config.Namespace, name)} {
		if _, err := scope.Apply(ctx, object, kube.CreateOnly); err != nil {
			t.Fatal(err)
		}
	}
	e2econfig.New(scope).Eval(traffic.Namespace.Name(), nil, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: native-workload-identity
spec:
  selector:
    matchLabels: {app: client}
  rules:
  - name: identity-path
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: /native-identity}]
    actions:
      block: {statusCode: 452, body: native-identity-block}
`).ApplyOrFail(t, kube.CreateOnly)
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": config.Namespace}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressGateways:
    - {name: identity-egress, namespace: {{ .Namespace }}}
    egressPolicies:
    - policy: GATEWAY
      gateway: {service: identity-egress.{{ .Namespace }}.svc.cluster.local}
`)
	if err := native.WaitReadyHash(ctx, env, config.Namespace, name, "generated-v1.7.0-identity"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/native-identity", "/native-allowed"} {
		want := 200
		if path == "/native-identity" {
			want = 452
		}
		traffic.Client.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  "192.0.2.1",
			Port:     80,
			Path:     path,
			Count:    1,
			Headers: map[string]string{
				"Host":                         host,
				"X-Agentio-Workload-Name":      "forged-workload",
				"X-Agentio-Workload-Namespace": "forged-namespace",
				"X-Agentio-Sandbox-Uid":        "forged-sandbox",
			},
			Check: check.NoErrorAndStatus(want),
			Retry: harness.FixedRetry(2*time.Minute, time.Second),
		})
	}
}
