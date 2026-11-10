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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestSandboxHTTPDFPAuthorityRouting verifies that the sandbox catch-all HTTP
// path selects its upstream from :authority instead of the intercepted original
// destination. TEST-NET-1 is intentionally unreachable; both requests can
// succeed only when DFP uses the supplied hostname or IP literal.
func TestSandboxHTTPDFPAuthorityRouting(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	dstPod := dst.WorkloadsOrFail(t)[0].Name
	dstIP := dst.ServiceIPOrFail(t)

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      failureModeAllow: true
      request:
        headerMode: SEND
      response:
        headerMode: SEND
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)

	callAuthority := func(t *testing.T, authority string) {
		t.Helper()
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  "192.0.2.1",
			Port:     80,
			Count:    1,
			Headers:  map[string]string{"Host": authority},
			Check: check.And(
				check.OK(),
				hostnameIs(dstPod),
				check.RequestHeader("X-Hello-To-Ext-Proc", "true"),
			),
			Retry: harness.FixedRetry(2*time.Minute, 5*time.Second),
		})
	}

	t.Run("hostname authority selects upstream", func(t *testing.T) {
		callAuthority(t, dst.Address())
	})

	t.Run("IP literal authority selects upstream", func(t *testing.T) {
		callAuthority(t, net.JoinHostPort(dstIP, "80"))
	})
}

// TestEgressStaticServiceEntries verifies that the original endpoint is retained
// for an allowed Host and that another Host cannot use the same endpoint.
func TestEgressStaticServiceEntries(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	dstPod := dst.WorkloadsOrFail(t)[0].Name
	dstIP := dst.ServiceIPOrFail(t)
	const host = "static-entry.example"

	rig.ApplyConfig(t, scope, map[string]any{
		"Endpoint":  dstIP,
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
      serviceEntries:
      - hosts:
        - `+host+`
        endpoints:
        - address: {{ .Endpoint }}
`)

	waitForGatewayConfig(t, environment, 200*time.Millisecond, func(dump string) error {
		for _, want := range []string{"service-entry|" + dstIP + "|http", host, "agentio.route.upstream"} {
			if !strings.Contains(dump, want) {
				return fmt.Errorf("gateway config_dump does not contain %q", want)
			}
		}
		return nil
	})

	t.Run("allowed Host retains endpoint", func(t *testing.T) {
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  dstIP,
			Port:     80,
			Count:    1,
			Headers:  map[string]string{"Host": net.JoinHostPort(host, "80")},
			Check:    check.And(check.OK(), hostnameIs(dstPod), noEnvoyResponseHeader()),
			Retry:    harness.FixedRetry(2*time.Minute, 5*time.Second),
		})
	})

	t.Run("unlisted Host is denied", func(t *testing.T) {
		src.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  dstIP,
			Port:     80,
			Count:    1,
			Headers:  map[string]string{"Host": "unlisted.example"},
			Check:    check.NoErrorAndStatus(http.StatusForbidden),
			Retry:    harness.FixedRetry(2*time.Minute, 5*time.Second),
		})
	})
}

func TestSandboxExtProc(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      failureModeAllow: true
      request:
        headerMode: SEND
      response:
        headerMode: SEND
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)

	harness.RunGatewayExtProc(t, src, dst)
}

func TestSandboxTraffic(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server

	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
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
`)

	harness.RunGatewayTraffic(
		t,
		src,
		dst,
		gatewayTraversal(true),
		check.NoError(),
		func(t *testing.T, id, authority string) { waitForGatewayAccessLog(t, environment, id, authority) },
	)
}

// TestSandboxMatchPorts verifies that only matched destination ports traverse
// the gateway and carry the request marker added by the ext_proc fixture.
func TestSandboxMatchPorts(t *testing.T) {
	_, scope := rig.BeginScenario(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server

	// Echo's "http" port -> ServicePort 80 (matched).
	// Echo's "http2" port -> ServicePort 85 (not matched, must bypass).
	rig.ApplyConfig(t, scope, map[string]any{
		"Namespace": resolvedAgentioConfig.Namespace,
	}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
`+gatewayTraversalConfig+`    egressPolicies:
    - matchPorts:
      - "80"
      gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)

	harness.RunGatewayMatchPorts(t, src, dst, gatewayTraversal(true), gatewayTraversal(false))
}

func hostnameIs(want string) echo.Checker {
	return check.Each(func(response echo.Response) error {
		if response.Hostname != want {
			return fmt.Errorf("hostname = %q, want %q", response.Hostname, want)
		}
		return nil
	})
}

// noEnvoyResponseHeader checks the gateway does not expose its generated headers.
func noEnvoyResponseHeader() echo.Checker {
	return check.Each(func(response echo.Response) error {
		if response.ResponseHeaders.Get("Server") == "agentio-envoy" {
			return fmt.Errorf("gateway server header must not be exposed")
		}
		for key := range response.ResponseHeaders {
			if strings.HasPrefix(strings.ToLower(key), "x-envoy-") {
				return fmt.Errorf(
					"did not expect x-envoy-* response header, got %s=%v",
					key,
					response.ResponseHeaders.Values(key),
				)
			}
		}
		return nil
	})
}

// The existing ext_proc fixture marks requests only when they traverse the gateway.
const gatewayTraversalConfig = `    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      request:
        headerMode: SEND
      response:
        headerMode: SKIP
`

func gatewayTraversal(want bool) echo.Checker {
	return check.And(noEnvoyResponseHeader(), check.Each(func(response echo.Response) error {
		got := response.RequestHeaders.Get("X-Hello-To-Ext-Proc")
		if (got == "true") != want {
			return fmt.Errorf("gateway traversal marker = %q, want gateway traversal %t", got, want)
		}
		return nil
	}))
}
