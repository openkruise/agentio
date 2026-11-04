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
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestSandboxUpstreamTLS uses isolated server listeners so successful HTTP
// responses prove a compatible upstream handshake, not merely accepted xDS.
// Every curl call starts a fresh downstream connection. TEST-NET resolution forces the
// gateway to resolve the actual upstream rather than letting curl bypass it.
func TestSandboxUpstreamTLS(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	namespace := resolvedAgentioConfig.Namespace
	host := fmt.Sprintf("upstream-tls.%s.svc.cluster.local", namespace)
	badHost := fmt.Sprintf("upstream-tls-wrong-san.%s.svc.cluster.local", namespace)
	key, chain, ca := generateConnectProxyCertificate(t, host)
	applyGatewayTLSTerminationProfile(t, scope, host, badHost, "example.com")
	e2econfig.New(scope).EvalFile(namespace, map[string]any{
		"Namespace": namespace, "ServerKey": key, "ServerCertChain": chain, "ServerCA": ca,
		"ForwardProxyImage": resolvedAgentioConfig.ForwardProxyImage,
	}, "testdata/upstream-tls.yaml").ApplyOrFail(t, kube.CreateOnly)
	readyCtx, readyCancel := e2e.Context(t, 2*time.Minute)
	defer readyCancel()
	if _, err := environment.Kube.WaitReadyPods(readyCtx, namespace, "app=upstream-tls", 1); err != nil {
		t.Fatalf("TLS upstream not ready: %v", err)
	}
	applySettings := func(t *testing.T, settings string, trustCA bool) {
		rig.ApplyConfig(
			t,
			scope,
			map[string]any{
				"Namespace": namespace,
				"Host":      host,
				"BadHost":   badHost,
				"Settings":  settings,
				"TrustCA":   trustCA,
			},
			`
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
      {{ if .TrustCA }}
      upstreamTrustBundle:
        additionalSources:
        - configMapRef: {name: upstream-tls-ca, key: ca.crt}
      {{ end }}
      tlsTermination:
        includeHosts:
        - "{{ .Host }}"
        - "{{ .BadHost }}"
        - example.com
      {{ .Settings }}
`,
		)
	}
	call := func(host string, port int, want string) error {
		// -k trusts only the gateway's on-demand downstream certificate. The
		// gateway still validates the upstream against the fixture CA and SAN.
		ctx, cancel := e2e.Context(t, 20*time.Second)
		defer cancel()
		stdout, stderr, err := externalCurl(ctx,
			"-k", "--http1.1", "--noproxy", "*", "--connect-timeout", "5", "--max-time", "15",
			"--resolve", fmt.Sprintf("%s:%d:192.0.2.1", host, port),
			"-H", "Connection: close", "-w", "\n%{http_code}", fmt.Sprintf("https://%s:%d/", host, port),
		)
		if err != nil {
			return fmt.Errorf("TLS request to %s:%d: %w; stdout=%q stderr=%q", host, port, err, stdout, stderr)
		}
		if want == "503" {
			if !strings.HasSuffix(strings.TrimSpace(stdout), "\n503") ||
				!strings.Contains(stdout, "upstream connect error") {
				return fmt.Errorf("response = %q, want gateway upstream-connect 503", stdout)
			}
		} else if want == "200" {
			if !strings.HasSuffix(strings.TrimSpace(stdout), "\n200") {
				return fmt.Errorf("response = %q, want HTTP 200", stdout)
			}
		} else if strings.TrimSpace(stdout) != want+"\n200" {
			return fmt.Errorf("response = %q, want %q and HTTP 200", stdout, want)
		}
		return nil
	}
	for _, tt := range []struct {
		name, settings               string
		tls13, ecdhe, rsa128, rsa256 string
	}{
		{"compatible defaults", "", "tls13", "ecdhe", "rsa128", "rsa256"},
		{"maximum TLS 1.2", "tls: {origination: {maxProtocolVersion: TLSV1_2}}", "503", "ecdhe", "rsa128", "rsa256"},
		{"ECDHE list replaces defaults", "tls: {origination: {cipherSuites: [ECDHE-RSA-AES128-GCM-SHA256]}}", "tls13", "ecdhe", "503", "503"},
		{"minimum TLS 1.3", "tls: {origination: {minProtocolVersion: TLSV1_3}}", "tls13", "503", "503", "503"},
		{"empty list restores defaults", "tls: {origination: {cipherSuites: []}}", "tls13", "ecdhe", "rsa128", "rsa256"},
		{"omitted settings restore defaults", "", "tls13", "ecdhe", "rsa128", "rsa256"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			applySettings(t, tt.settings, true)
			// Check the complete matrix together on each retry so propagation errors
			// cannot satisfy a negative assertion while all destinations are broken.
			harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
				for _, endpoint := range []struct {
					port int
					want string
				}{
					{18443, tt.tls13}, {18444, tt.ecdhe}, {18445, tt.rsa128}, {18446, tt.rsa256},
				} {
					if err := call(host, endpoint.port, endpoint.want); err != nil {
						return err
					}
				}
				return call(badHost, 18443, "503")
			})
		})
	}

	t.Run("trust bundle updates", func(t *testing.T) {
		ctx, cancel := e2e.Context(t, 10*time.Minute)
		defer cancel()
		token, err := environment.Cluster.Kube.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, "default",
			&authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{Audiences: []string{"agentio-ca"}},
			}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("create config debug token: %v", err)
		}
		assertTraffic := func(want string) {
			t.Helper()
			harness.RetryAssertion(t, 2*time.Minute, 5*time.Second, func() error {
				if err := call(host, 18443, want); err != nil {
					return err
				}
				if err := call(badHost, 18443, "503"); err != nil {
					return err
				}
				return call("example.com", 443, "200")
			})
		}
		updateCA := func(value string) {
			t.Helper()
			cm, err := environment.Cluster.Kube.CoreV1().
				ConfigMaps(namespace).
				Get(ctx, "upstream-tls-ca", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			cm.Data["ca.crt"] = value
			if _, err := environment.Cluster.Kube.CoreV1().
				ConfigMaps(namespace).
				Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		waitRejected := func(reason string) {
			t.Helper()
			// Wait for this update's rejection before asserting last-known-good traffic.
			harness.RetryAssertion(t, time.Minute, time.Second, func() error {
				probeCtx, probeCancel := e2e.Context(t, 15*time.Second)
				defer probeCancel()
				stdout, stderr, err := externalCurl(probeCtx, "--fail-with-body", "--max-time", "10",
					"-H", "Authorization: Bearer "+token.Status.Token,
					fmt.Sprintf("http://agentiod.%s.svc.cluster.local:15014/debug/configz", namespace))
				if err != nil {
					return fmt.Errorf("read compiler failures: %w; stderr=%s", err, stderr)
				}
				var snapshot struct {
					Failures []struct {
						Key     string
						Message string
					} `json:"failures"`
				}
				if err := json.Unmarshal([]byte(stdout), &snapshot); err != nil {
					return err
				}
				for _, failure := range snapshot.Failures {
					if failure.Key == "Gateway/"+namespace+"/egress-gateway" &&
						strings.Contains(
							failure.Message,
							"upstream-tls-ca",
						) && strings.Contains(failure.Message, reason) {
						return nil
					}
				}
				return fmt.Errorf(
					"compiler failures = %+v, want CA source rejection containing %q",
					snapshot.Failures,
					reason,
				)
			})
		}

		applySettings(t, "", false)
		assertTraffic("503")
		applySettings(t, "", true)
		assertTraffic("tls13")

		_, _, unrelatedCA := generateConnectProxyCertificate(t, host)
		updateCA(unrelatedCA)
		assertTraffic("503")
		updateCA(ca)
		assertTraffic("tls13")

		updateCA("invalid PEM")
		waitRejected("non-certificate data")
		assertTraffic("tls13")
		if err := environment.Cluster.Kube.CoreV1().
			ConfigMaps(namespace).
			Delete(ctx, "upstream-tls-ca", metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		waitRejected("not found")
		assertTraffic("tls13")

		applySettings(t, "", false)
		assertTraffic("503")
	})
}
