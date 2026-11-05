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

package agentgateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openkruise/agentio/test/e2e"
	native "github.com/openkruise/agentio/test/e2e/components/agentgateway"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestAgentgatewayStaticTLSInterception(t *testing.T) {
	env, scope := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 5*time.Minute)
	defer cancel()
	const name = "tls-egress"
	host := fmt.Sprintf("tls-origin.%s.svc.cluster.local", traffic.Namespace.Name())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "native e2e MITM"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{host},
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	originSecret := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": name, "namespace": traffic.Namespace.Name()},
		"stringData": map[string]any{
			"tls.crt": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
			"tls.key": string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		},
	}}
	if _, err := scope.Apply(ctx, originSecret, kube.CreateOnly); err != nil {
		t.Fatal(err)
	}
	e2econfig.New(scope).Eval(traffic.Namespace.Name(), map[string]any{"Image": echo.DefaultImage}, `
apiVersion: v1
kind: Service
metadata: {name: tls-origin}
spec:
  selector: {app: tls-origin}
  ports: [{name: https, port: 443, targetPort: 18443}]
---
apiVersion: v1
kind: Pod
metadata: {name: tls-origin, labels: {app: tls-origin}}
spec:
  containers:
  - name: app
    image: {{ .Image }}
    args: ["--port=18443", "--tls=18443", "--crt=/certs/tls.crt", "--key=/certs/tls.key"]
    volumeMounts: [{name: certs, mountPath: /certs, readOnly: true}]
  volumes:
  - name: certs
    secret: {secretName: tls-egress}
`).ApplyOrFail(t, kube.CreateOnly)
	origin, err := env.Cluster.Kube.CoreV1().Services(traffic.Namespace.Name()).
		Get(ctx, "tls-origin", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": name, "namespace": config.Namespace},
		"stringData": map[string]any{
			"ca.crt": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			"ca.key": string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		},
	}}
	settings := native.Configuration(config.Namespace, name, "")
	settings.Object["data"] = map[string]any{"config": fmt.Sprintf(`
serviceEntries:
- hosts: [%s]
  endpoints: [{address: %s}]
tlsTermination: {includeHosts: [%s]}
upstreamTrustBundle:
  additionalSources: [{secretRef: {name: %s, key: ca.crt}}]
extProc:
  serviceRef: {name: ext-proc, namespace: %s}
  response: {headerMode: SEND}
`, host, origin.Spec.ClusterIP, host, name, config.Namespace)}
	gateway := native.Gateway(config.Namespace, name)
	gateway.SetAnnotations(map[string]string{"gateway.agentio.kruise.io/agentgateway-certs": name})
	for _, object := range []*unstructured.Unstructured{secret, settings, gateway} {
		if _, err := scope.Apply(ctx, object, kube.CreateOnly); err != nil {
			t.Fatal(err)
		}
	}
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": config.Namespace}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressGateways:
    - {name: tls-egress, namespace: {{ .Namespace }}}
    egressPolicies:
    - policy: GATEWAY
      gateway: {service: tls-egress.{{ .Namespace }}.svc.cluster.local}
`)
	if err := native.WaitReadyHash(ctx, env, config.Namespace, name, "generated-v1.7.0"); err != nil {
		t.Fatal(err)
	}
	traffic.Client.CallOrFail(t, echo.CallOptions{
		Protocol:   echo.HTTPS,
		Address:    "192.0.2.1",
		Port:       443,
		ServerName: host,
		Path:       "/native-static-tls",
		Count:      1,
		Headers:    map[string]string{"Host": host},
		Check: check.And(
			check.OK(),
			check.RequestHeader("X-Hello-To-Ext-Proc", "true"),
			check.ResponseHeader("X-Hello-From-Ext-Proc", "true"),
		),
		Retry: harness.FixedRetry(2*time.Minute, time.Second),
	})
	e2econfig.New(scope).Eval(traffic.Namespace.Name(), nil, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata: {name: native-tls-workload}
spec:
  selector:
    matchLabels: {app: client}
  rules:
  - name: tls-workload
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: /native-tls-identity}]
    actions:
      block: {statusCode: 453, body: native-tls-workload-block}
`).ApplyOrFail(t, kube.CreateOnly)
	data := settings.Object["data"].(map[string]any)
	data["config"] = strings.Replace(
		data["config"].(string),
		fmt.Sprintf("serviceRef: {name: ext-proc, namespace: %s}\n  response: {headerMode: SEND}", config.Namespace),
		fmt.Sprintf(
			"serviceRef: {name: agentio-epe, namespace: %s}\n  request: {attributes: [\"filter_state['agentio.workload.uid']\"]}",
			config.Namespace,
		),
		1,
	)
	if _, err := scope.Apply(ctx, settings, kube.ReconcileOwned); err != nil {
		t.Fatal(err)
	}
	if err := native.WaitReadyHash(ctx, env, config.Namespace, name, "generated-v1.7.0-identity"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/native-tls-identity", "/native-static-tls"} {
		want := 200
		if path == "/native-tls-identity" {
			want = 453
		}
		traffic.Client.CallOrFail(t, echo.CallOptions{
			Protocol:   echo.HTTPS,
			Address:    "192.0.2.1",
			Port:       443,
			ServerName: host,
			Path:       path,
			Count:      1,
			Headers: map[string]string{
				"Host":                    host,
				"X-Agentio-Workload-Name": "forged",
				"X-Agentio-Sandbox-Uid":   "forged",
			},
			Check: check.NoErrorAndStatus(want),
			Retry: harness.FixedRetry(2*time.Minute, time.Second),
		})
	}
}
