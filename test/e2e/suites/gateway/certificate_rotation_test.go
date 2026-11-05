//go:build certrotation

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
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// Explicitly opt in: this test waits for real certificate clocks and interrupts
// the suite-owned control plane. It must not run in parallel with other tests.
func TestSandboxOnDemandCertificateRotation(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	namespace := resolvedAgentioConfig.Namespace
	restoreReplicas := configureCertificateIssuer(t, environment, map[string]string{
		"AGENTIO_MITM_LEAF_LIFETIME": "75s",
		"AGENTIO_MITM_RENEW_BEFORE":  "45s",
		"AGENTIO_MITM_CACHE_MAX_AGE": "1h",
	})
	const serviceName = "upstream-tls-expiry"
	host := fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, namespace)
	key, chain, ca := generateConnectProxyCertificate(t, host)
	applyGatewayTLSTerminationProfile(t, scope, host)
	e2econfig.New(scope).EvalFile(namespace, map[string]any{
		"Namespace":         namespace,
		"ServiceName":       serviceName,
		"ServerKey":         key,
		"ServerCertChain":   chain,
		"ServerCA":          ca,
		"ForwardProxyImage": resolvedAgentioConfig.ForwardProxyImage,
	}, "testdata/upstream-tls.yaml").ApplyOrFail(t, kube.CreateOnly)
	ctx, cancel := e2e.Context(t, 8*time.Minute)
	defer cancel()
	if _, err := environment.Kube.WaitReadyPods(ctx, namespace, "app=upstream-tls", 1); err != nil {
		t.Fatal(err)
	}
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": namespace, "Host": host}, `
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
      upstreamTrustBundle:
        additionalSources:
        - configMapRef: {name: upstream-tls-ca, key: ca.crt}
      tlsTermination:
        includeHosts: ["{{ .Host }}"]
`)
	secret, err := environment.Cluster.Kube.CoreV1().Secrets(namespace).Get(ctx, "agentio-mitm-ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	roots := string(secret.Data["root-cert.pem"])
	if roots == "" {
		t.Fatal("MITM root bundle is empty")
	}
	gateway, err := firstReadyPod(ctx, environment, namespace, harness.GatewayPodSelector)
	if err != nil {
		t.Fatal(err)
	}
	probe := func() (*x509.Certificate, error) {
		return rotationCertificate(ctx, environment, host, roots)
	}
	var initial *x509.Certificate
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		initial, err = probe()
		return err
	})
	if remaining := time.Until(initial.NotAfter); remaining > 75*time.Second || remaining < 45*time.Second {
		t.Fatalf("unexpected remaining leaf lifetime %s; short-lived issuer is not active", remaining)
	}
	t.Logf("initial serial=%s expires=%s", initial.SerialNumber, initial.NotAfter.Format(time.RFC3339Nano))

	// Once configuration has converged, do not retry away failed handshakes.
	// Two successive serial changes prove repeated real leaf rotation.
	current := initial
	for round := 1; round <= 2; round++ {
		deadline := current.NotAfter.Add(10 * time.Second)
		attempts := 0
		var slowest time.Duration
		for {
			started := time.Now()
			fresh, err := probe()
			slowest = max(slowest, time.Since(started))
			attempts++
			if err != nil {
				t.Fatalf("rotation %d handshake %d: %v", round, attempts, err)
			}
			if fresh.SerialNumber.Cmp(current.SerialNumber) != 0 {
				if !fresh.NotAfter.After(current.NotAfter) {
					t.Fatal("replacement certificate did not extend validity")
				}
				t.Logf(
					"rotation=%d handshakes=%d max_latency=%s serial=%s expires=%s",
					round,
					attempts,
					slowest,
					fresh.SerialNumber,
					fresh.NotAfter.Format(time.RFC3339Nano),
				)
				current = fresh
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("certificate did not rotate")
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	// Scaling every issuer to zero severs existing SDS streams as well as
	// reconnects. The business path, Envoy and upstream remain alive.
	if err := restoreReplicas(ctx, 0); err != nil {
		t.Fatal(err)
	}
	harness.RetryAssertion(t, 45*time.Second, time.Second, func() error {
		pods, err := environment.Cluster.Kube.CoreV1().
			Pods(namespace).
			List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=agentiod"})
		if err != nil {
			return err
		}
		if len(pods.Items) != 0 {
			return fmt.Errorf("%d issuer pods still exist", len(pods.Items))
		}
		return nil
	})
	// Porter fails closed on new CONNECTs while ADS is offline. Inspect the
	// exact SDS resource to distinguish retention/expiry from that rejection.
	before, err := activeCertificateCopies(ctx, environment, gateway.Name, host)
	if err != nil || before < 1 {
		t.Fatalf("no active on-demand certificate before TTL: active=%d error=%v", before, err)
	}
	// TTL is relative to receipt; allow a small transport/scheduling tolerance.
	wait := time.Until(current.NotAfter.Add(3 * time.Second))
	if wait > 0 {
		time.Sleep(wait)
	}
	harness.RetryAssertion(t, 10*time.Second, time.Second, func() error {
		active, err := activeCertificateCopies(ctx, environment, gateway.Name, host)
		if err != nil {
			return err
		}
		if active != 0 {
			return fmt.Errorf("Envoy retained %d certificates after TTL with issuer offline", active)
		}
		return nil
	})
	t.Log("Envoy expired its on-demand certificate while all issuers were offline")
	if err := restoreReplicas(ctx, 1); err != nil {
		t.Fatal(err)
	}
	harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
		fresh, err := probe()
		if err != nil {
			return err
		}
		if fresh.SerialNumber.Cmp(current.SerialNumber) == 0 {
			return fmt.Errorf("old certificate survived issuer recovery")
		}
		t.Logf("recovered serial=%s expires=%s", fresh.SerialNumber, fresh.NotAfter.Format(time.RFC3339Nano))
		return nil
	})
	final, err := environment.Cluster.Kube.CoreV1().Pods(namespace).Get(ctx, gateway.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if final.UID != gateway.UID {
		t.Fatal("Envoy was replaced during certificate rotation")
	}
	for i, status := range final.Status.ContainerStatuses {
		if status.RestartCount != gateway.Status.ContainerStatuses[i].RestartCount {
			t.Fatal("Envoy restarted during certificate rotation")
		}
	}
}
