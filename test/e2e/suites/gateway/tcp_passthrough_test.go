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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/network"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func applyTCPPassthrough(t *testing.T, environment *e2e.Environment, scope *kube.ResourceScope, rules string) {
	t.Helper()
	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
		"Rules":     rules,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
`+gatewayTraversalConfig+`    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tcpPassthrough: {{ .Rules }}
`)
	waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
		// Removed listeners may still drain after the active route has changed.
		if strings.Contains(dump, `"tcp-passthrough-0"`) != (rules != "[]") {
			return fmt.Errorf("gateway has not applied TCP passthrough configuration")
		}
		return nil
	})
}

func TestSandboxTCPPassthroughServerFirst(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	server := echo.Deploy(t, environment, echo.Config{
		Name:      "tcp-server-first",
		Namespace: trafficFixture.Namespace.Name(),
		Ports: []echo.Port{{
			Name:         "tcp",
			Protocol:     echo.TCP,
			ServicePort:  9092,
			WorkloadPort: 19092,
			ServerFirst:  true,
		}},
	})
	address := server.WorkloadsOrFail(t)[0].Address
	cidr, err := network.HostCIDR(address)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		rules   string
		allowed bool
	}{
		{name: "inspection cannot forward server-first", rules: "[]"},
		{name: "CIDR and port", rules: fmt.Sprintf(`[{"cidrs":[%q],"ports":[19092]}]`, cidr), allowed: true},
		{name: "CIDR miss", rules: `[{"cidrs":["192.0.2.0/24"],"ports":[19092]}]`},
		{name: "CIDR only", rules: fmt.Sprintf(`[{"cidrs":[%q]}]`, cidr), allowed: true},
		{name: "port miss", rules: fmt.Sprintf(`[{"cidrs":[%q],"ports":[19093]}]`, cidr)},
		{name: "port only", rules: `[{"ports":[19092]}]`, allowed: true},
		{name: "removal restores inspection", rules: "[]"},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			applyTCPPassthrough(t, environment, scope, tc.rules)
			checker := check.Error()
			if tc.allowed {
				checker = check.OK()
			}
			trafficFixture.Client.CallOrFail(t, echo.CallOptions{
				Protocol:    echo.TCP,
				Address:     address,
				Port:        19092,
				ServerFirst: true,
				Count:       1,
				Timeout:     5 * time.Second,
				Check:       checker,
				Retry:       harness.FixedRetry(45*time.Second, time.Second),
			})
		}) {
			return
		}
	}
}

func TestSandboxTCPPassthroughHTTP(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	original := trafficFixture.Server.WorkloadsOrFail(t)[0]
	other := trafficFixture.AnotherServer.WorkloadsOrFail(t)[0]
	cidr, err := network.HostCIDR(original.Address)
	if err != nil {
		t.Fatal(err)
	}
	request := echo.CallOptions{
		Protocol: echo.HTTP,
		Address:  original.Address,
		Port:     18080,
		Count:    1,
		Headers: map[string]string{
			"Host": net.JoinHostPort(trafficFixture.AnotherServer.Address(), "80"),
		},
		Retry: harness.FixedRetry(45*time.Second, time.Second),
	}
	matched := fmt.Sprintf(`[{"cidrs":[%q],"ports":[18080]}]`, cidr)
	for _, tc := range []struct {
		name      string
		rules     string
		inspected bool
	}{
		{name: "matched HTTP preserves original destination and skips ext-proc", rules: matched},
		{name: "CIDR miss uses Host and ext-proc", rules: `[{"cidrs":["192.0.2.0/24"],"ports":[18080]}]`, inspected: true},
		{name: "port miss uses Host and ext-proc", rules: fmt.Sprintf(`[{"cidrs":[%q],"ports":[18081]}]`, cidr), inspected: true},
		{name: "port only skips HTTP processing", rules: `[{"ports":[18080]}]`},
		{name: "removal restores Host routing and ext-proc", rules: "[]", inspected: true},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			applyTCPPassthrough(t, environment, scope, tc.rules)
			hostname := original.Name
			if tc.inspected {
				hostname = other.Name
			}
			src.CallOrFail(
				t,
				request.WithCheck(check.And(check.OK(), hostnameIs(hostname), gatewayTraversal(tc.inspected))),
			)
		}) {
			return
		}
	}
	t.Run("passthrough does not bypass TrafficPolicy", func(t *testing.T) {
		applyTCPPassthrough(t, environment, scope, matched)
		src.CallOrFail(t, request.WithCheck(check.And(check.OK(), hostnameIs(original.Name), gatewayTraversal(false))))
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App":  src.Name(),
			"CIDR": cidr,
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: deny-tcp-passthrough
spec:
  priority: 100
  selector:
    matchLabels:
      app: {{ .App }}
  egress:
    rules:
    - action: reject
      to:
      - cidr: {{ .CIDR }}
      ports:
      - protocol: TCP
        port: 18080
    - action: allow
      to:
      - cidr: 0.0.0.0/0
      - cidr: "::/0"
`).ApplyOrFail(t, kube.CreateOnly)
		src.CallOrFail(t, request.WithCheck(check.Error()))
		control := request
		control.Address = other.Address
		src.CallOrFail(t, control.WithCheck(check.And(check.OK(), hostnameIs(other.Name), gatewayTraversal(true))))
	})
}
