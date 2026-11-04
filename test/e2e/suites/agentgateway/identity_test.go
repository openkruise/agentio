// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

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
	settings := native.Configuration(config.Namespace, name, "")
	settings.Object["data"] = map[string]any{"config": fmt.Sprintf(`
serviceEntries:
- hosts: [identity-static.invalid]
  endpoints: [{address: %s}]
extProc:
  serviceRef: {name: agentio-epe, namespace: %s}
`, traffic.Server.ServiceIPOrFail(t), config.Namespace)}
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
      schemes: [http]
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
	if err := native.WaitReadyHash(ctx, env, config.Namespace, name, "generated-v1.7.0-agentio"); err != nil {
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
				"Host":                         "identity-static.invalid",
				"X-Agentio-Workload-Name":      "forged-workload",
				"X-Agentio-Workload-Namespace": "forged-namespace",
				"X-Agentio-Sandbox-Uid":        "forged-sandbox",
			},
			Check: check.NoErrorAndStatus(want),
			Retry: harness.FixedRetry(2*time.Minute, time.Second),
		})
	}
}
