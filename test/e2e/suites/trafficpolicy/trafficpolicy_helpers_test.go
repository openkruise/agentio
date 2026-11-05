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
//
// This file contains policy-propagation and firewall assertions; generic
// manifest and echo-call helpers live in reusable E2E packages.

package trafficpolicy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/retry"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type configDumpFunc func(context.Context) (string, error)

func waitForPolicyState(ctx context.Context, policy string, present bool, dump configDumpFunc) error {
	if dump == nil {
		return fmt.Errorf("config dump callback is required")
	}
	return retry.UntilSuccess(ctx, retry.Policy{
		Timeout:  2 * time.Minute,
		Delay:    200 * time.Millisecond,
		Backoff:  1,
		MaxDelay: 200 * time.Millisecond,
		Converge: 1,
	}, func() error {
		content, err := dump(ctx)
		if err != nil {
			return err
		}
		view, err := inspectPolicyDump(content, policy)
		if err != nil {
			return err
		}
		if view.found == present {
			return nil
		}
		if present {
			return fmt.Errorf("policy %q is absent from config dump", policy)
		}
		return fmt.Errorf("policy %q remains in config dump", policy)
	})
}

func waitForPolicyPresent(t *testing.T, instance echo.Instance, policy string) {
	t.Helper()
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	environment := suite.Environment(t)
	if err := waitForPolicyState(ctx, policy, true, func(ctx context.Context) (string, error) {
		return rig.ConfigDump(ctx, environment, instance)
	}); err != nil {
		t.Fatalf("wait for policy %q in %s config dump: %v", policy, instance.Name(), err)
	}
}

func waitForPolicyGone(t *testing.T, instance echo.Instance, policy string) {
	t.Helper()
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	environment := suite.Environment(t)
	if err := waitForPolicyState(ctx, policy, false, func(ctx context.Context) (string, error) {
		return rig.ConfigDump(ctx, environment, instance)
	}); err != nil {
		t.Fatalf("wait for policy %q to leave %s config dump: %v", policy, instance.Name(), err)
	}
}

func requirePingState(t *testing.T, source echo.Instance, address string, allowed bool) {
	t.Helper()
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	var stdout, stderr string
	var execErr error
	err := retry.UntilSuccess(ctx, retry.Policy{
		Timeout:  90 * time.Second,
		Delay:    300 * time.Millisecond,
		Backoff:  1.5,
		MaxDelay: 2 * time.Second,
		Converge: 3,
	}, func() error {
		stdout, stderr, execErr = source.Exec(ctx, []string{"ping", "-c", "1", "-W", "3", address})
		if allowed && execErr == nil || !allowed && execErr != nil {
			return nil
		}
		if allowed {
			return fmt.Errorf("ping failed: %w", execErr)
		}
		return fmt.Errorf("ping is still allowed")
	})
	if err != nil {
		state := "denied"
		if allowed {
			state = "allowed"
		}
		t.Fatalf(
			"expected ping from %s to %s to be %s: %v; last error=%v stdout=%q stderr=%q",
			source.Name(),
			address,
			state,
			err,
			execErr,
			stdout,
			stderr,
		)
	}
}

func requireFirewallRules(t *testing.T) {
	t.Helper()
	if !resolvedAgentioConfig.EnableFirewallRules {
		t.Skip("UDP and ICMP traffic policy tests require Agentio firewall rules")
	}
}

func trafficPolicy(name, namespace string, selector map[string]string, action, cidr string) *unstructured.Unstructured {
	matchLabels := make(map[string]any, len(selector))
	for key, value := range selector {
		matchLabels[key] = value
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1",
		"kind":       "TrafficPolicy",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]any{
			"priority": int64(100),
			"selector": map[string]any{
				"matchLabels": matchLabels,
			},
			"egress": map[string]any{
				"rules": []any{
					map[string]any{
						"action": action,
						"to": []any{
							map[string]any{"cidr": cidr},
						},
					},
					map[string]any{
						"action": "allow",
						"to": []any{
							map[string]any{"cidr": "0.0.0.0/0"},
						},
					},
				},
			},
		},
	}}
}
