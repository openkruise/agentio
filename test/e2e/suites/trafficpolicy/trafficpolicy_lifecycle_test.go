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
	"fmt"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/network"
	"github.com/openkruise/agentio/test/e2e/retry"
)

// TestSandboxTrafficPolicyLifecycle covers policy lifecycle scenarios that go
// beyond basic allow/deny enforcement: update propagation, deletion cleanup,
// invalid CIDR admission, empty selector, wildcard service, label-change
// reconciliation, and fail-closed handling of unresolvable FQDNs.
func TestSandboxTrafficPolicyLifecycle(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer
	serviceIPBlock, err := network.PrefixCIDR(src.ServiceIPOrFail(t), 16)
	if err != nil {
		t.Fatal(err)
	}

	rig.RunScenario(t, "policy update propagation", func(t *testing.T, scope *kube.ResourceScope) {
		// Phase 1: apply deny policy — dst should be unreachable.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
			"Dst": dst.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-update
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-lifecycle-update")

		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))

		// Phase 2: update policy to allow — dst should become reachable.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
			"Dst": serviceIPBlock,
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-update
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(t, kube.ReconcileOwned)

		waitForPolicyPresent(t, src, "tp-lifecycle-update")

		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))

		// Phase 3: update again to deny — dst should be blocked.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
			"Dst": dst.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-update
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
`).ApplyOrFail(t, kube.ReconcileOwned)

		waitForPolicyPresent(t, src, "tp-lifecycle-update")

		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
	})

	rig.RunScenario(t, "policy deletion cleanup", func(t *testing.T, scope *kube.ResourceScope) {
		policy := e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
			"Dst": dst.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-lifecycle-delete
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
`)
		policy.ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-lifecycle-delete")

		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))

		// Delete the policy explicitly.
		policy.DeleteOrFail(t)

		// Wait until the AuthorizationPolicy referencing this TP is gone.
		waitForPolicyGone(t, src, "tp-lifecycle-delete")

		// Traffic should be allowed after policy deletion.
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "invalid CIDR resilience", func(t *testing.T, scope *kube.ResourceScope) {
		ctx, cancel := e2e.Context(t, 2*time.Minute)
		defer cancel()
		invalid := e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-invalid-cidr
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "not-a-valid-cidr"
`)
		if _, err := invalid.Apply(ctx, kube.CreateOnly); !apierrors.IsForbidden(err) ||
			!strings.Contains(err.Error(), "invalid CIDR") {
			t.Fatalf("create invalid CIDR policy: got %v, want admission rejection", err)
		}

		// A rejected policy must not prevent subsequent valid policy propagation.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
			"Dst": serviceIPBlock,
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-after-invalid
spec:
  priority: 50
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-after-invalid")

		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "empty selector matches all pods", func(t *testing.T, scope *kube.ResourceScope) {
		// An empty selector ({}) should match ALL pods in the namespace.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"Dst": dst.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-empty-selector
spec:
  priority: 100
  selector: {}
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)

		// Both src and anotherDst should match the empty selector. The ambient
		// ztunnel admin dump does not expose namespace-scoped Authorizations, so
		// its retrying traffic checks below are the propagation barrier there.
		if resolvedAgentioConfig.Profile == agentiocomponent.ProfileSidecar {
			waitForPolicyPresent(t, src, "tp-empty-selector")
			waitForPolicyPresent(t, anotherDst, "tp-empty-selector")
		}

		// src -> dst should be denied (matched by empty selector).
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))

		// anotherDst -> dst should also be denied.
		anotherDst.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))

		// But src -> anotherDst should still work (different CIDR).
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "wildcard service name", func(t *testing.T, scope *kube.ResourceScope) {
		// Service name "*" should match all services in the namespace.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App":          src.Name(),
			"DstNamespace": dst.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wildcard-svc
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - service:
              namespace: "{{ .DstNamespace }}"
              name: "*"
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-wildcard-svc")

		// src should be able to reach dst via service (wildcard matches all services).
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))

		// src should also reach another-server via service.
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))

		// External traffic should be denied (not covered by service wildcard).
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "label change reconciliation", func(t *testing.T, scope *kube.ResourceScope) {
		// Apply a policy targeting "server" pods.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"Dst": dst.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-label-reconcile
spec:
  priority: 100
  selector:
    matchLabels:
      app: "server"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, dst, "tp-label-reconcile")

		// "server" (dst) matches the selector, so its egress to itself is denied.
		// "client" (src) does NOT match, so src -> dst is unaffected.
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))

		// Verify that the AuthorizationPolicy is present on dst (server).
		waitForPolicyPresent(t, dst, "tp-label-reconcile")

		// Verify that client (src) does NOT have this policy.
		waitForPolicyGone(t, src, "tp-label-reconcile")
	})

	rig.RunScenario(t, "unresolvable FQDN fails closed", func(t *testing.T, scope *kube.ResourceScope) {
		// Apply a policy with an unresolvable FQDN.
		// The controller should retain the policy with a never-match
		// clause rather than broadening the allow rule to a wildcard.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-bad-fqdn
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - fqdn: "this-fqdn-does-not-exist.invalid"
`).ApplyOrFail(t, kube.CreateOnly)

		// Wait for the policy to be processed.
		waitForPolicyPresent(t, src, "tp-bad-fqdn")

		// The unresolvable FQDN must fail closed. The kube-dns rule does
		// not match dst, and the empty Match sentinel prevents the FQDN
		// rule from becoming a wildcard allow.
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))

		// The controller should not crash — verify by applying another policy.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
			"Dst": serviceIPBlock,
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-after-bad-fqdn
spec:
  priority: 50
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-after-bad-fqdn")

		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "missing service fails closed and recovers", func(t *testing.T, scope *kube.ResourceScope) {
		const lateService = "late-service"
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-missing-service
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - service:
              name: `+lateService+`
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-missing-service")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))

		e2econfig.New(scope).YAML(trafficFixture.Namespace.Name(), `
apiVersion: v1
kind: Service
metadata:
  name: `+lateService+`
spec:
  selector:
    app: server
  ports:
    - name: http
      port: 80
      targetPort: 18080
`).ApplyOrFail(t, kube.CreateOnly)

		lateAddress := lateService + "." + trafficFixture.Namespace.Name() + ".svc.cluster.local"
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, lateAddress, 80).WithCheck(check.OK()))
	})

	rig.RunScenario(t, "unmatched workload peer fails closed", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App":       src.Name(),
			"Namespace": trafficFixture.Namespace.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-missing-workload
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - workload:
              namespace: "{{ .Namespace }}"
              selector:
                app: missing-workload
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-missing-workload")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
	})

	rig.RunScenario(t, "invalid CIDR update preserves existing policy", func(t *testing.T, scope *kube.ResourceScope) {
		ctx, cancel := e2e.Context(t, 2*time.Minute)
		defer cancel()
		const name = "tp-invalid-cidr-update"
		namespace := trafficFixture.Namespace.Name()
		selector := map[string]string{"app": src.Name()}
		valid := trafficPolicy(name, namespace, selector, "reject", dst.ServiceIPOrFail(t))
		if _, err := scope.Apply(ctx, valid, kube.CreateOnly); err != nil {
			t.Fatalf("create valid deny policy: %v", err)
		}
		waitForPolicyPresent(t, src, name)
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))

		invalid := trafficPolicy(name, namespace, selector, "allow", "not-a-valid-cidr")
		if _, err := scope.Apply(ctx, invalid, kube.ReconcileOwned); !apierrors.IsForbidden(err) ||
			!strings.Contains(err.Error(), "invalid CIDR") {
			t.Fatalf("update invalid CIDR policy: got %v, want admission rejection", err)
		}
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
	})
}

// TestSandboxWorkloadPeerAdvanced covers advanced workload peer scenarios:
// multi-replica workload resolution, dynamic pod lifecycle (IPSet updates),
// and mixed workload+service / workload+CIDR peer combinations.
func TestSandboxWorkloadPeerAdvanced(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	environment := suite.Environment(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer
	workloadTarget := trafficFixture.WorkloadTarget

	rig.RunScenario(t, "workload selector resolves multiple replicas", func(t *testing.T, scope *kube.ResourceScope) {
		workloads := workloadTarget.WorkloadsOrFail(t)
		if len(workloads) < 2 {
			t.Fatalf("workload-target ready workloads = %d, want at least 2", len(workloads))
		}

		// Apply egress allow policy with workload peer targeting
		// the "workload-target" service pods.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App":         src.Name(),
			"WlNamespace": workloadTarget.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wl-multi-replica
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - workload:
              namespace: "{{ .WlNamespace }}"
              selector:
                app: "workload-target"
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-wl-multi-replica")

		// src should be able to reach ALL replicas of workload-target.
		for _, workload := range workloads {
			src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, workload.Address, 18080).WithCheck(check.OK()))
		}

		// src should NOT reach anotherDst (not in workload selector).
		src.CallOrFail(
			t,
			echo.CallOptionsForAddress(echo.HTTP, anotherDst.WorkloadsOrFail(t)[0].Address, 18080).
				WithCheck(check.Error()),
		)
	})

	rig.RunScenario(
		t,
		"dynamic pod lifecycle updates workload peer IPs",
		func(t *testing.T, scope *kube.ResourceScope) {
			workloads := workloadTarget.WorkloadsOrFail(t)
			initialCount := len(workloads)
			if initialCount < 2 {
				t.Fatalf("workload-target ready workloads = %d, want at least 2", initialCount)
			}

			// Apply egress allow with workload peer.
			e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
				"App":         src.Name(),
				"WlNamespace": workloadTarget.Namespace(),
			}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wl-dynamic
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - workload:
              namespace: "{{ .WlNamespace }}"
              selector:
                app: "workload-target"
`).ApplyOrFail(t, kube.CreateOnly)

			waitForPolicyPresent(t, src, "tp-wl-dynamic")

			// Verify connectivity to all initial replicas.
			for _, workload := range workloads {
				src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, workload.Address, 18080).WithCheck(check.OK()))
			}

			// Verify the applicable policy bodies contain entries for all replicas.
			ctx, cancel := e2e.Context(t, 2*time.Minute)
			defer cancel()
			if err := retry.UntilSuccess(ctx, retry.Policy{
				Timeout:  2 * time.Minute,
				Delay:    5 * time.Second,
				Backoff:  1,
				MaxDelay: 5 * time.Second,
				Converge: 1,
			}, func() error {
				dump, err := rig.ConfigDump(ctx, environment, src)
				if err != nil {
					return err
				}
				view, err := inspectPolicyDump(dump, "tp-wl-dynamic")
				if err != nil {
					return err
				}
				if !view.found {
					return fmt.Errorf("policy tp-wl-dynamic is absent from config dump")
				}
				for _, workload := range workloads {
					cidr, err := network.HostCIDR(workload.Address)
					if err != nil {
						return err
					}
					if !strings.Contains(view.body, `"`+cidr+`"`) {
						return fmt.Errorf("workload IP %s is absent from tp-wl-dynamic config dump", workload.Address)
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("wait for all workload-target replica IPs in config dump: %v", err)
			}
		},
	)

	rig.RunScenario(t, "mixed workload and service peers", func(t *testing.T, scope *kube.ResourceScope) {
		// Allow egress to server via workload peer AND to another-server
		// via service peer. Other traffic should be denied.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App":            src.Name(),
			"DstApp":         dst.Name(),
			"DstNamespace":   dst.Namespace(),
			"AnotherSvcNs":   anotherDst.Namespace(),
			"AnotherSvcName": anotherDst.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wl-svc-mixed
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
          - service:
              namespace: "{{ .AnotherSvcNs }}"
              name: "{{ .AnotherSvcName }}"
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-wl-svc-mixed")

		// src -> dst (workload peer) should be reachable.
		src.CallOrFail(
			t,
			echo.CallOptionsForAddress(echo.HTTP, dst.WorkloadsOrFail(t)[0].Address, 18080).WithCheck(check.OK()),
		)

		// src -> another-server (service peer) should be reachable.
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))

		// External FQDN should be denied (not in workload or service peers).
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "mixed workload and CIDR peers", func(t *testing.T, scope *kube.ResourceScope) {
		anotherWorkload := anotherDst.WorkloadsOrFail(t)[0]
		anotherIPBlock, err := network.PrefixCIDR(anotherWorkload.Address, 24)
		if err != nil {
			t.Fatal(err)
		}

		// Allow egress to server via workload peer AND to another-server's
		// IP block via CIDR. Other traffic should be denied.
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App":          src.Name(),
			"DstApp":       dst.Name(),
			"DstNamespace": dst.Namespace(),
			"CidrBlock":    anotherIPBlock,
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-wl-cidr-mixed
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
          - cidr: "{{ .CidrBlock }}"
`).ApplyOrFail(t, kube.CreateOnly)

		waitForPolicyPresent(t, src, "tp-wl-cidr-mixed")

		// src -> dst (workload peer) should be reachable.
		src.CallOrFail(
			t,
			echo.CallOptionsForAddress(echo.HTTP, dst.WorkloadsOrFail(t)[0].Address, 18080).WithCheck(check.OK()),
		)

		// src -> another-server (covered by CIDR) should be reachable.
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, anotherWorkload.Address, 18080).WithCheck(check.OK()))

		// External traffic should be denied.
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
	})
}
