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
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestSandboxConnectionPool(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	environment := suite.Environment(t)

	rig.RunScenario(t, "stream idle timeout", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      http:
        streamIdleTimeout: 600s
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			if !containsStreamIdleTimeout(dump, 600) {
				return fmt.Errorf("config_dump does not have stream_idle_timeout=600s")
			}
			return nil
		})
	})

	rig.RunScenario(t, "tcp idle timeout and max connection duration", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts:
        - "*.example.com"
      tcp:
        idleTimeout: 1800s
        maxConnectionDuration: 7200s
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			if !containsTCPIdleTimeout(dump, 1800) {
				return fmt.Errorf("config_dump does not have tcp idle_timeout=1800s")
			}
			if !containsMaxConnectionDuration(dump, 7200) {
				return fmt.Errorf("config_dump does not have max_downstream_connection_duration=7200s")
			}
			return nil
		})
	})

	rig.RunScenario(t, "default route timeout", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      http:
        streamIdleTimeout: 600s
        routing:
          fallback:
            timeout: 30s
            retries:
              attempts: 3
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			if !containsRouteTimeout(dump, "sandbox|default|", 30) {
				return fmt.Errorf("config_dump does not have default route timeout=30s")
			}
			if !containsRetryPolicy(dump, "sandbox|default|", 3) {
				return fmt.Errorf("config_dump does not have default route num_retries=3")
			}
			return nil
		})
	})

	rig.RunScenario(t, "per-host route overrides", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      http:
        streamIdleTimeout: 600s
        routing:
          fallback:
            timeout: 30s
          hostOverrides:
          - hosts:
            - "api.example.com"
            - "*.api.example.com"
            settings:
              timeout: 120s
              retries:
                attempts: 5
                perTryTimeout: 10s
                retryOn: "connect-failure,refused-stream"
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			if !strings.Contains(dump, "sandbox|override|0") {
				return fmt.Errorf("config_dump does not contain sandbox|override|0 virtual host")
			}
			if !strings.Contains(dump, "api.example.com") {
				return fmt.Errorf("config_dump does not contain api.example.com domain")
			}
			if !containsRouteTimeout(dump, "sandbox|override|0", 120) {
				return fmt.Errorf("config_dump does not have override route timeout=120s")
			}
			if !containsRetryPolicy(dump, "sandbox|override|0", 5) {
				return fmt.Errorf("config_dump does not have override route num_retries=5")
			}
			return nil
		})
	})

	rig.RunScenario(t, "full connection pool settings", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts:
        - "*.example.com"
      tcp:
        idleTimeout: 3600s
        maxConnectionDuration: 14400s
      http:
        streamIdleTimeout: 900s
        routing:
          fallback:
            timeout: 60s
            retries:
              attempts: 2
          hostOverrides:
          - hosts:
            - "slow.example.com"
            settings:
              timeout: 300s
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			if !containsStreamIdleTimeout(dump, 900) {
				return fmt.Errorf("config_dump does not have stream_idle_timeout=900s")
			}
			if !containsTCPIdleTimeout(dump, 3600) {
				return fmt.Errorf("config_dump does not have tcp idle_timeout=3600s")
			}
			if !containsMaxConnectionDuration(dump, 14400) {
				return fmt.Errorf("config_dump does not have max_downstream_connection_duration=14400s")
			}
			if !containsRouteTimeout(dump, "sandbox|default|", 60) {
				return fmt.Errorf("config_dump does not have default route timeout=60s")
			}
			if !strings.Contains(dump, "slow.example.com") {
				return fmt.Errorf("config_dump does not contain slow.example.com domain")
			}
			if !containsRouteTimeout(dump, "sandbox|override|0", 300) {
				return fmt.Errorf("config_dump does not have override route timeout=300s")
			}
			return nil
		})
	})

	rig.RunScenario(t, "defaults when no connection pool configured", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			// Default stream_idle_timeout is 30min = 1800s
			if !containsStreamIdleTimeout(dump, 1800) {
				return fmt.Errorf("config_dump does not have default stream_idle_timeout=1800s (30min)")
			}
			return nil
		})
	})
}

func TestSandboxConnectionPoolTimeout(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	targetHost := dst.Address()

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace":  resolvedAgentioConfig.Namespace,
		"TargetHost": targetHost,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      http:
        streamIdleTimeout: 600s
        routing:
          hostOverrides:
          - hosts:
            - "{{ .TargetHost }}"
            settings:
              timeout: 1s
`)

	waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
		if !strings.Contains(dump, "sandbox|override|0") {
			return fmt.Errorf("sandbox route config not yet propagated")
		}
		if !strings.Contains(dump, targetHost) {
			return fmt.Errorf("sandbox route config for %q not yet propagated", targetHost)
		}
		return nil
	})

	t.Run("route timeout triggers 504 on slow upstream", func(t *testing.T) {
		options := echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  targetHost,
			Port:     80,
			Path:     "/?delay=5s",
			Count:    1,
			Timeout:  10 * time.Second,
			Check:    check.Status(504),
			Retry:    harness.FixedRetry(30*time.Second, 200*time.Millisecond),
		}
		src.CallOrFail(t, options)
	})

	t.Run("requests within timeout succeed", func(t *testing.T) {
		options := echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  targetHost,
			Port:     80,
			Path:     "/",
			Count:    1,
			Timeout:  10 * time.Second,
			Check:    check.OK(),
			Retry:    harness.FixedRetry(30*time.Second, 200*time.Millisecond),
		}
		src.CallOrFail(t, options)
	})
}

func TestSandboxRateLimit(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	environment := suite.Environment(t)

	rig.RunScenario(t, "global token bucket", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      connectRateLimit:
        tokenBucket:
          maxTokens: 100
          tokensPerFill: 100
          fillInterval: 1s
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			if !strings.Contains(dump, "connect_rate_limit") {
				return fmt.Errorf("config_dump does not contain rate limit stat_prefix")
			}
			if !strings.Contains(dump, "envoy.filters.http.local_ratelimit") {
				return fmt.Errorf("config_dump does not contain local_ratelimit filter")
			}
			return nil
		})
	})

	rig.RunScenario(t, "per-client filter-state descriptor bucketing", func(t *testing.T, scope *kube.ResourceScope) {
		dst := trafficFixture.AnotherServer
		targetHost := dst.Address()

		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      connectRateLimit:
        rateLimits:
        - actions:
          - filterState: {key: agentio.workload.name, descriptorKey: peer_name}
        descriptors:
        - entries:
          - key: peer_name
          tokenBucket:
            maxTokens: 1
            tokensPerFill: 1
            fillInterval: 30s
`)

		waitForGatewayConfig(t, environment, time.Second, func(dump string) error {
			if !strings.Contains(dump, "envoy.rate_limit_descriptors.expr") || !strings.Contains(dump, "peer_name") {
				return fmt.Errorf("per-client rate limit descriptor not yet in config_dump")
			}
			return nil
		})

		curlFromPod := func(podLabel string) (int, error) {
			return curlHTTPCodeFromPod(
				t,
				environment,
				trafficFixture.Namespace.Name(),
				podLabel,
				"app",
				fmt.Sprintf("http://%s:80/", targetHost),
			)
		}

		// Client A (app=client): retry until first request succeeds
		harness.RetryAssertion(t, 2*time.Minute, 2*time.Second, func() error {
			code, err := curlFromPod("app=client")
			if err != nil {
				return err
			}
			if code != 200 {
				return fmt.Errorf("client A got %d, want 200", code)
			}
			return nil
		})

		// Client A: 2nd request -> bucket empty (30s refill) -> expect failure
		harness.RetryAssertion(t, 30*time.Second, 2*time.Second, func() error {
			code, err := curlFromPod("app=client")
			if err != nil {
				return nil
			}
			return fmt.Errorf("client A 2nd request should be rate limited, got %d", code)
		})

		// Client B (app=server): first request should succeed (separate bucket)
		harness.RetryAssertion(t, 30*time.Second, 2*time.Second, func() error {
			code, err := curlFromPod("app=server")
			if err != nil {
				return err
			}
			if code != 200 {
				return fmt.Errorf("client B got %d, want 200", code)
			}
			return nil
		})
	})

	rig.RunScenario(t, "rate limit enforced", func(t *testing.T, scope *kube.ResourceScope) {
		src := trafficFixture.AnotherServer
		dst := trafficFixture.Server
		targetHost := dst.Address()

		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      connectRateLimit:
        tokenBucket:
          maxTokens: 1
          tokensPerFill: 1
          fillInterval: 60s
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			if !strings.Contains(dump, "connect_rate_limit") {
				return fmt.Errorf("rate limit config not yet propagated")
			}
			return nil
		})

		curlFromPod := func(podLabel string) (int, error) {
			return curlHTTPCodeFromPod(
				t,
				environment,
				trafficFixture.Namespace.Name(),
				podLabel,
				"app",
				fmt.Sprintf("http://%s:80/", targetHost),
			)
		}

		// First request should succeed (consumes the single token)
		harness.RetryAssertion(t, 30*time.Second, 200*time.Millisecond, func() error {
			code, err := curlFromPod(fmt.Sprintf("app=%s", src.Name()))
			if err != nil {
				return err
			}
			if code != 200 {
				return fmt.Errorf("first request got %d, want 200", code)
			}
			return nil
		})

		// Subsequent request should be rate limited (429)
		harness.RetryAssertion(t, 30*time.Second, 200*time.Millisecond, func() error {
			code, err := curlFromPod(fmt.Sprintf("app=%s", src.Name()))
			if err != nil {
				return nil
			}
			return fmt.Errorf("second request should be rate limited, got %d", code)
		})
	})

	rig.RunScenario(t, "no rate limit when not configured", func(t *testing.T, scope *kube.ResourceScope) {
		rig.ApplyConfig(t, scope, map[string]any{
			"Namespace": resolvedAgentioConfig.Namespace,
		}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
`)

		waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
			if strings.Contains(dump, "connect_rate_limit") {
				return fmt.Errorf("config_dump should NOT contain rate limit when not configured")
			}
			return nil
		})
	})
}

func waitForGatewayConfig(
	t *testing.T,
	environment *e2e.Environment,
	delay time.Duration,
	assert func(string) error,
) {
	t.Helper()
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	err := retry.UntilSuccess(ctx, harness.FixedRetry(2*time.Minute, delay), func() error {
		dump, err := getEgressGatewayConfigDump(ctx, environment)
		if err != nil {
			return err
		}
		return assert(dump)
	})
	if err != nil {
		t.Fatalf("wait for egress gateway config: %v", err)
	}
}

func curlHTTPCodeFromPod(
	t *testing.T,
	environment *e2e.Environment,
	namespaceName, podLabel, container, url string,
) (int, error) {
	t.Helper()
	ctx, cancel := e2e.Context(t, 15*time.Second)
	defer cancel()
	stdout, stderr, err := execFirstReadyPod(
		ctx,
		environment,
		namespaceName,
		podLabel,
		container,
		[]string{
			"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
			"--connect-timeout", "3", "--max-time", "10", url,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("curl failed: %w; stderr: %s", err, stderr)
	}
	code := 0
	if _, err := fmt.Sscanf(stdout, "%d", &code); err != nil {
		return 0, fmt.Errorf("failed to parse curl http_code %q: %w", stdout, err)
	}
	return code, nil
}

// --- config_dump JSON parsing helpers ---

func containsJSONField(dump, field string, seconds int) bool {
	value := fmt.Sprintf("%ds", seconds)
	compact := fmt.Sprintf(`"%s":"%s"`, field, value)
	pretty := fmt.Sprintf(`"%s": "%s"`, field, value)
	return strings.Contains(dump, compact) || strings.Contains(dump, pretty)
}

func containsStreamIdleTimeout(dump string, seconds int) bool {
	return containsJSONField(dump, "stream_idle_timeout", seconds)
}

func containsTCPIdleTimeout(dump string, seconds int) bool {
	return containsJSONField(dump, "idle_timeout", seconds)
}

func containsMaxConnectionDuration(dump string, seconds int) bool {
	return containsJSONField(dump, "max_downstream_connection_duration", seconds)
}

func containsRouteTimeout(dump, vhostPrefix string, seconds int) bool {
	index := strings.Index(dump, vhostPrefix)
	if index < 0 {
		return false
	}
	section := dump[index:]
	return containsJSONField(section, "timeout", seconds)
}

func containsRetryPolicy(dump, vhostPrefix string, numRetries int) bool {
	index := strings.Index(dump, vhostPrefix)
	if index < 0 {
		return false
	}
	section := dump[index:]
	target := fmt.Sprintf(`"num_retries": %d`, numRetries)
	return strings.Contains(section, target)
}
