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

package epe

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/network"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestEPETCPPriorityAndResolvedDestination(t *testing.T) {
	environment, scope := beginEPEDataPathScenario(t, "TCP priority EPE logs")
	target := echo.Deploy(t, environment, echo.Config{
		Name:      "tcp-policy-target",
		Namespace: trafficFixture.Namespace.Name(),
		Ports:     echo.DefaultPorts(),
	})
	targetCIDR, err := network.HostCIDR(target.ServiceIPOrFail(t))
	if err != nil {
		t.Fatal(err)
	}
	originalCIDR, err := network.HostCIDR(trafficFixture.Server.ServiceIPOrFail(t))
	if err != nil {
		t.Fatal(err)
	}
	request := trafficFixture.Server.CallOptionsOrFail(t, "http")
	request.Address = trafficFixture.Server.ServiceIPOrFail(t)
	request.Headers = map[string]string{"Host": net.JoinHostPort(target.Address(), "80")}
	request.Count = 1
	request.Retry = harness.FixedRetry(2*time.Minute, time.Second)
	targetName := target.WorkloadsOrFail(t)[0].Name
	reachedTarget := check.Each(func(response echo.Response) error {
		if response.Hostname != targetName {
			return fmt.Errorf("reached %q, want Host-selected backend %q", response.Hostname, targetName)
		}
		return nil
	})
	trafficFixture.Client.CallOrFail(t, request.WithCheck(check.And(check.OK(), reachedTarget)))
	const bypass = `[{name: bypass, match: [{domains: ["*"]}], actions: {bypass: true}}]`
	const block = `[{name: block, match: [{domains: ["*"]}], actions: {block: {statusCode: 451, body: lower-http-block}}}]`
	const mutate = `[{name: mutate, match: [{domains: ["*"]}], actions: {headerManipulation: {set: [{name: x-tcp-priority, value: applied}]}}}]`
	// Keep the lower profile fixed so its propagation cannot mask a priority regression.
	e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
		"App": trafficFixture.Client.Name(),
	}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: tcp-priority-second
spec:
  priority: 20
  selector:
    matchLabels: {app: "{{ .App }}"}
  rules:
  - name: bypass
    match: [{domains: ["*"], paths: [{type: Exact, value: /bypass}]}]
    actions: {bypass: true}
  - name: block
    match: [{domains: ["*"]}]
    actions: {block: {statusCode: 451, body: lower-http-block}}
`).ApplyOrFail(t, kube.CreateOnly)
	request.Path = "/block"
	trafficFixture.Client.CallOrFail(
		t,
		request.WithCheck(check.And(check.NoError(), check.Status(451), strictEPEBodyContains("lower-http-block"))),
	)
	request.Path = "/bypass"
	trafficFixture.Client.CallOrFail(t, request.WithCheck(check.And(check.OK(), reachedTarget)))
	var active *e2econfig.Plan
	for index, tc := range []struct {
		name     string
		rules    string
		action   string
		cidr     string
		path     string
		priority int
		status   int
		mutated  bool
	}{
		{name: "higher TCP deny beats lower HTTP bypass at resolved IP", rules: "[]", action: "Deny", cidr: targetCIDR, path: "/bypass", priority: 10, status: 403},
		{name: "higher TCP allow beats lower HTTP block", rules: "[]", action: "Allow", cidr: targetCIDR, path: "/block", priority: 10, status: 200},
		{name: "same profile HTTP block beats TCP allow", rules: block, action: "Allow", cidr: targetCIDR, path: "/bypass", priority: 10, status: 451},
		{name: "same profile HTTP bypass skips TCP deny", rules: bypass, action: "Deny", cidr: targetCIDR, path: "/block", priority: 10, status: 200},
		{name: "header mutation still requires TCP authorization", rules: mutate, action: "Deny", cidr: targetCIDR, path: "/bypass", priority: 10, status: 403},
		{name: "header mutation survives TCP allow", rules: mutate, action: "Allow", cidr: targetCIDR, path: "/block", priority: 10, status: 200, mutated: true},
		{name: "original IP allow cannot authorize Host target", rules: "[]", action: "Allow", cidr: originalCIDR, path: "/block", priority: 10, status: 451},
		{name: "priority update moves HTTP bypass before TCP deny", rules: "[]", action: "Deny", cidr: targetCIDR, path: "/bypass", priority: 30, status: 200},
		{name: "restore deny before deletion", rules: "[]", action: "Deny", cidr: targetCIDR, path: "/bypass", priority: 10, status: 403},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			active = e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
				"App":      trafficFixture.Client.Name(),
				"Priority": tc.priority,
				"Rules":    tc.rules,
				"Action":   tc.action,
				"CIDR":     tc.cidr,
			}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: tcp-priority-first
spec:
  priority: {{ .Priority }}
  selector:
    matchLabels: {app: "{{ .App }}"}
  rules: {{ .Rules }}
  tcpRules:
  - name: selected-address
    match: [{cidrs: ["{{ .CIDR }}"], ports: [80]}]
    action: {{ .Action }}
`)
			mode := kube.ReconcileOwned
			if index == 0 {
				mode = kube.CreateOnly
			}
			active.ApplyOrFail(t, mode)
			checker := check.And(check.NoError(), check.Status(tc.status))
			if tc.status == 200 {
				checker = check.And(checker, reachedTarget)
			}
			if tc.status == 451 {
				checker = check.And(checker, strictEPEBodyContains("lower-http-block"))
			}
			if tc.mutated {
				checker = check.And(checker, check.Each(func(response echo.Response) error {
					if got := response.RequestHeaders.Get("X-TCP-Priority"); got != "applied" {
						return fmt.Errorf("mutation = %q, want applied", got)
					}
					return nil
				}))
			}
			current := request
			current.Path = tc.path
			trafficFixture.Client.CallOrFail(t, current.WithCheck(checker))
		}) {
			return
		}
	}
	active.DeleteOrFail(t)
	trafficFixture.Client.CallOrFail(t, request.WithCheck(check.And(check.OK(), reachedTarget)))
}
