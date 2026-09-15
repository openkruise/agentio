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
	"testing"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/network"
)

// TestTrafficPolicyLowerPriorityWins pins numeric priority across policy scopes
// and proves that changing only priority changes the observed traffic decision.
func TestTrafficPolicyLowerPriorityWins(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src, dst := trafficFixture.Client, trafficFixture.Server
	target := dst.ServiceIPOrFail(t)
	cidr, err := network.HostCIDR(target)
	if err != nil {
		t.Fatal(err)
	}
	// Use a literal address so a denied DNS lookup cannot masquerade as policy enforcement.
	call := echo.CallOptionsForAddress(echo.HTTP, target, 80)

	for _, tc := range []struct{ name, allowKind, denyKind string }{
		{"namespaced allow versus global deny", "TrafficPolicy", "GlobalTrafficPolicy"},
		{"global allow versus namespaced deny", "GlobalTrafficPolicy", "TrafficPolicy"},
	} {
		rig.RunScenario(t, tc.name, func(t *testing.T, scope *kube.ResourceScope) {
			apply := func(kind, name, action string, priority int, mode kube.Mode) *e2econfig.Plan {
				t.Helper()
				namespace := src.Namespace()
				if kind == "GlobalTrafficPolicy" {
					namespace = ""
				}
				plan := e2econfig.New(scope).Eval(namespace, map[string]any{
					"Kind":     kind,
					"Name":     name,
					"App":      src.Name(),
					"Action":   action,
					"Priority": priority,
					"CIDR":     cidr,
				}, `
apiVersion: agents.kruise.io/v1alpha1
kind: {{ .Kind }}
metadata:
  name: {{ .Name }}
spec:
  priority: {{ .Priority }}
  selector:
    matchLabels:
      app: {{ .App }}
  egress:
    rules:
      - action: {{ .Action }}
        to:
          - cidr: {{ .CIDR }}
`)
				plan.ApplyOrFail(t, mode)
				return plan
			}
			const allowName, denyName = "tp-priority-z-allow", "tp-priority-a-deny"
			src.CallOrFail(t, call.WithCheck(check.OK()))
			apply(tc.allowKind, allowName, "allow", 100, kube.CreateOnly)
			waitForPolicyPresent(t, src, allowName)
			src.CallOrFail(t, call.WithCheck(check.OK()))

			deny := apply(tc.denyKind, denyName, "reject", 10, kube.CreateOnly)
			waitForPolicyPresent(t, src, denyName)
			src.CallOrFail(t, call.WithCheck(check.Error()))

			// Neither DENY action nor global scope may override a smaller numeric priority.
			apply(tc.allowKind, allowName, "allow", 0, kube.ReconcileOwned)
			src.CallOrFail(t, call.WithCheck(check.OK()))
			apply(tc.allowKind, allowName, "allow", 100, kube.ReconcileOwned)
			src.CallOrFail(t, call.WithCheck(check.Error()))

			deny.DeleteOrFail(t)
			waitForPolicyGone(t, src, denyName)
			src.CallOrFail(t, call.WithCheck(check.OK()))
		})
	}
}
