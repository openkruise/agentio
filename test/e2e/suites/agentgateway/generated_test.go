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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openkruise/agentio/test/e2e"
	native "github.com/openkruise/agentio/test/e2e/components/agentgateway"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestAgentgatewayGeneratedEgress(t *testing.T) {
	env, scope := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 3*time.Minute)
	defer cancel()
	const name = "generated-egress"
	settings := native.Configuration(config.Namespace, name, "")
	settings.Object["data"] = map[string]any{"config": fmt.Sprintf(`
serviceEntries:
- hosts: [static-only.invalid]
  endpoints: [{address: %s}]
extProc:
  serviceRef: {name: ext-proc, namespace: %s}
  response: {headerMode: SEND}
`, traffic.Server.ServiceIPOrFail(t), config.Namespace)}
	for _, object := range []*unstructured.Unstructured{settings, native.Gateway(config.Namespace, name)} {
		if _, err := scope.Apply(ctx, object, kube.CreateOnly); err != nil {
			t.Fatal(err)
		}
	}
	var content string
	if err := retry.UntilSuccess(
		ctx,
		retry.Policy{Timeout: 2 * time.Minute, Delay: time.Second, Converge: 1},
		func() error {
			generated, err := env.Cluster.Kube.CoreV1().
				ConfigMaps(config.Namespace).
				Get(ctx, name+"-native", metav1.GetOptions{})
			if err != nil {
				return err
			}
			content = generated.Data["config.yaml"]
			if content == "" {
				return fmt.Errorf("generated native configuration is empty")
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": config.Namespace}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressGateways:
    - {name: generated-egress, namespace: {{ .Namespace }}}
    egressPolicies:
    - policy: GATEWAY
      gateway: {service: generated-egress.{{ .Namespace }}.svc.cluster.local}
`)
	if err := native.WaitReadyHash(ctx, env, config.Namespace, name, "generated-v1.7.0"); err != nil {
		t.Fatal(err)
	}
	traffic.Client.CallOrFail(t, echo.CallOptions{
		Protocol: echo.HTTP,
		Address:  "192.0.2.1",
		Port:     80,
		Count:    1,
		Headers:  map[string]string{"Host": "static-only.invalid"},
		Check: check.And(
			check.OK(),
			check.RequestHeader("X-Hello-To-Ext-Proc", "true"),
			check.ResponseHeader("X-Hello-From-Ext-Proc", "true"),
		),
		Retry: harness.FixedRetry(2*time.Minute, time.Second),
	})
}
