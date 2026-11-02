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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// This changes only the suite-owned signing Secret and issuer deployment. It
// deliberately keeps the gateway alive across both live and offline CA changes.
func TestSandboxOnDemandCARotation(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	namespace := resolvedAgentioConfig.Namespace
	scale := configureCertificateIssuer(t, environment, map[string]string{
		"AGENTIO_MITM_SIGN_MODE": "SECRET",
	})
	ctx, cancel := e2e.Context(t, 6*time.Minute)
	defer cancel()
	secrets := environment.Cluster.Kube.CoreV1().Secrets(namespace)
	original, err := secrets.Get(ctx, "agentio-mitm-ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		current, err := secrets.Get(cleanupCtx, original.Name, metav1.GetOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		current.Data = original.Data
		if _, err := secrets.Update(cleanupCtx, current, metav1.UpdateOptions{}); err != nil {
			t.Error(err)
		}
	})
	const serviceName = "upstream-tls-ca"
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
	if _, err := environment.Kube.WaitReadyPods(ctx, namespace, "app=upstream-tls", 1); err != nil {
		t.Fatal(err)
	}
	// Isolate certificate convergence from EPE availability during issuer changes.
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
      extProc: {}
      tlsTermination:
        includeHosts: ["{{ .Host }}"]
`)
	gateway, err := firstReadyPod(ctx, environment, namespace, harness.GatewayPodSelector)
	if err != nil {
		t.Fatal(err)
	}
	roots := string(original.Data["root-cert.pem"])
	var previous *x509.Certificate
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		previous, err = rotationCertificate(ctx, environment, host, roots)
		return err
	})
	if _, ok := previous.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("leaf public key is %T, want ECDSA", previous.PublicKey)
	}
	for _, offline := range []bool{false, true} {
		// Use a fresh CA key, not just another leaf under the original CA.
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("e2e-CA-offline-%t", offline)},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		signingCA, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(caKey)
		if err != nil {
			t.Fatal(err)
		}
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if offline {
			if err := scale(ctx, 0); err != nil {
				t.Fatal(err)
			}
			harness.RetryAssertion(t, time.Minute, time.Second, func() error {
				pods, err := environment.Cluster.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
					LabelSelector: "app.kubernetes.io/name=agentiod",
				})
				if err != nil {
					return err
				}
				if len(pods.Items) != 0 {
					return fmt.Errorf("%d issuers still running", len(pods.Items))
				}
				return nil
			})
			// Porter intentionally drops identity readiness when ADS disconnects,
			// so new HBONE CONNECTs cannot prove SDS cache retention during outage.
			active, err := activeCertificateCopies(ctx, environment, gateway.Name, host)
			if err != nil || active == 0 {
				t.Fatalf("cached SDS secret during outage: active=%d error=%v", active, err)
			}
		}
		current, err := secrets.Get(ctx, original.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		current.Data["ca.crt"] = caPEM
		current.Data["ca.key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
		current.Data["root-cert.pem"] = caPEM
		if _, err := secrets.Update(ctx, current, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		oldRoots := roots
		roots = string(caPEM)
		if offline {
			if err := scale(ctx, 1); err != nil {
				t.Fatal(err)
			}
		}
		var fresh *x509.Certificate
		harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
			fresh, err = rotationCertificate(ctx, environment, host, roots)
			if err != nil {
				return err
			}
			return fresh.CheckSignatureFrom(signingCA)
		})
		publicKey, ok := fresh.PublicKey.(*ecdsa.PublicKey)
		if !ok || publicKey.Equal(previous.PublicKey) {
			t.Fatal("CA rotation did not replace the ECDSA leaf key")
		}
		if _, err := rotationCertificate(ctx, environment, host, oldRoots); err == nil {
			t.Fatal("new handshake still accepted the old CA trust bundle")
		}
		// After convergence, repeated fresh connections must succeed without retries.
		for range 5 {
			leaf, err := rotationCertificate(ctx, environment, host, roots)
			if err != nil {
				t.Fatal(err)
			}
			if leaf.SerialNumber.Cmp(fresh.SerialNumber) != 0 {
				t.Fatal("warm demand unnecessarily reissued the leaf")
			}
		}
		t.Logf("CA rotation offline=%t: verified new CA, new ECDSA key, old-root rejection and warm reuse", offline)
		previous = fresh
	}
	final, err := environment.Cluster.Kube.CoreV1().Pods(namespace).Get(ctx, gateway.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if final.UID != gateway.UID {
		t.Fatal("gateway was replaced")
	}
	for i, status := range final.Status.ContainerStatuses {
		if status.RestartCount != gateway.Status.ContainerStatuses[i].RestartCount {
			t.Fatal("gateway restarted")
		}
	}
}
