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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	clientretry "k8s.io/client-go/util/retry"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/command"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestEPEHelmMTLSCertificateSources exercises the chart-owned EPE Deployment.
// Only tls.enabled is set for CA mode; endpoint, trust mounts and peer identity
// must come from chart defaults. File mode then rotates real projected material.
func TestEPEHelmMTLSCertificateSources(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 20*time.Minute)
	defer cancel()
	namespace := resolvedAgentioConfig.Namespace
	identity := "spiffe://cluster.local/ns/" + namespace + "/sa/" + epeName
	const materialName = "epe-helm-mtls"

	helm := func(ctx context.Context, args ...string) (command.Result, error) {
		args = append(args, "--namespace", namespace, "--kubeconfig", environment.Cluster.Kubeconfig)
		if environment.Cluster.Context != "" {
			args = append(args, "--kube-context", environment.Cluster.Context)
		}
		return environment.Commands.Run(ctx, command.Request{Name: "helm", Args: args, Artifact: "epe-mtls/helm"})
	}
	status, err := helm(ctx, "status", agentioInstance.ReleaseName(), "--output", "json")
	if err != nil {
		t.Fatal(err)
	}
	var release struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal([]byte(status.Stdout), &release); err != nil || release.Version < 1 {
		t.Fatalf("read original Helm revision: %v, %s", err, status.Stdout)
	}
	secrets := environment.Cluster.Kube.CoreV1().Secrets(namespace)
	originalCA, err := secrets.Get(ctx, "agentio-ca-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	setAuthority := func(ctx context.Context, data map[string][]byte) error {
		return clientretry.RetryOnConflict(clientretry.DefaultRetry, func() error {
			current, err := secrets.Get(ctx, originalCA.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			current.Data = maps.Clone(data)
			_, err = secrets.Update(ctx, current, metav1.UpdateOptions{})
			return err
		})
	}
	// Restore shared installation state even when an assertion fails. The scope
	// still preserves the scenario's own objects and diagnostics on failure.
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 7*time.Minute)
		defer stop()
		if err := setAuthority(cleanupCtx, originalCA.Data); err != nil {
			t.Errorf("restore Agentiod CA: %v", err)
		}
		if err := waitEPETrustBundle(cleanupCtx, environment, namespace, originalCA.Data["root-cert.pem"]); err != nil {
			t.Errorf("restore workload roots: %v", err)
		}
		if _, err := helm(cleanupCtx, "rollback", agentioInstance.ReleaseName(), strconv.Itoa(release.Version),
			"--wait", "--timeout", "5m"); err != nil {
			t.Errorf("restore Helm release: %v", err)
		}
		// The gateway may now hold a B identity. Reacquire A before the next test.
		if err := restartEPEGateway(cleanupCtx, environment, namespace); err != nil {
			t.Errorf("restore gateway identity: %v", err)
		}
	})
	attachEPELogsOnFailure(t, environment, "Helm-managed EPE mTLS failure")

	upgrade := func(t *testing.T, values string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "values.yaml")
		if err := os.WriteFile(path, []byte(values), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := helm(ctx, "upgrade", agentioInstance.ReleaseName(), resolvedAgentioConfig.ChartPath,
			"--reuse-values", "--values", path, "--wait", "--timeout", "5m", "--skip-crds"); err != nil {
			t.Fatal(err)
		}
	}
	pod := func(t *testing.T) corev1.Pod {
		t.Helper()
		var result corev1.Pod
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			pods, err := environment.Kube.ReadyPods(ctx, namespace, harness.EPEPodSelector)
			if err != nil {
				return err
			}
			if len(pods) != 1 || pods[0].DeletionTimestamp != nil {
				return fmt.Errorf("expected one ready EPE, got %d", len(pods))
			}
			result = pods[0]
			return nil
		})
		return result
	}
	unchanged := func(t *testing.T, initial corev1.Pod) {
		t.Helper()
		current := pod(t)
		if current.UID != initial.UID || restartCount(current) != 0 {
			t.Fatalf("certificate update restarted EPE: initial=%s current=%s restarts=%d",
				initial.UID, current.UID, restartCount(current))
		}
	}
	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}
	caA, err := tls.X509KeyPair(originalCA.Data["ca-cert.pem"], originalCA.Data["ca-key.pem"])
	if err != nil {
		t.Fatal(err)
	}
	caB := newEPECertificate(t, nil, "")
	rootsA := originalCA.Data["root-cert.pem"]
	rootsB := epeCertificatePEM(caB)
	rootsAB := bytes.Join([][]byte{rootsA, rootsB}, []byte("\n"))
	clientA := newEPECertificate(t, &caA, identity)
	clientB := newEPECertificate(t, &caB, identity)
	var initial corev1.Pod
	probe := func(t *testing.T, roots []byte, client tls.Certificate) (*x509.Certificate, error) {
		t.Helper()
		// A rejected TLS handshake can terminate kind's port forward. Isolate
		// every attempt so expected rejection cannot break subsequent probes.
		address, stop := startEPEPortForward(t, environment, namespace, initial.Name, 9002)
		defer stop()
		return probeEPECertificate(ctx, address, identity, roots, client)
	}
	observe := func(t *testing.T, roots []byte, client tls.Certificate, want *x509.Certificate) {
		t.Helper()
		// Allow kubelet's projected-volume propagation plus the file watch.
		harness.RetryAssertion(t, 3*time.Minute, time.Second, func() error {
			leaf, err := probe(t, roots, client)
			if err != nil {
				return err
			}
			if want != nil && !leaf.Equal(want) {
				return fmt.Errorf("serving certificate serial = %s, want %s", leaf.SerialNumber, want.SerialNumber)
			}
			return nil
		})
	}
	source := trafficFixture.Client
	traffic := func(t *testing.T) {
		t.Helper()
		callEPEPathOrFail(
			t,
			source,
			trafficFixture.Server,
			"/epe-helm-mtls",
			statusIdentityBlock,
			"epe-helm-mtls",
		)
	}

	step("helm_defaults_enable_mtls", func(t *testing.T) {
		upgrade(t, "epe:\n  tls:\n    enabled: true\n")
		initial = pod(t)
		observe(t, rootsA, clientA, nil)
		if _, err := probe(t, rootsA, tls.Certificate{}); err == nil || !strings.Contains(err.Error(), "tls:") {
			t.Fatalf("expected TLS rejection without a client certificate, got %v", err)
		}
		// Do not override sandboxExtProc: its endpoint and mTLS settings must be
		// supplied by the chart's base ConfigMap, including the default SPIFFE ID.
		rig.ApplyConfig(t, scope, map[string]any{"Namespace": namespace}, `
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
`)
		e2econfig.New(scope).YAML(trafficFixture.Namespace.Name(), `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-helm-mtls
spec:
  selector: {}
  rules:
  - name: proof
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: /epe-helm-mtls}]
    actions:
      block: {statusCode: 452, body: epe-helm-mtls}
`).ApplyOrFail(t, kube.CreateOnly)
		traffic(t)
	})
	step("agentiod_CA_A_to_B_without_EPE_restart", func(t *testing.T) {
		data := maps.Clone(originalCA.Data)
		data["root-cert.pem"] = rootsAB
		if err := setAuthority(ctx, data); err != nil {
			t.Fatal(err)
		}
		if err := waitEPETrustBundle(ctx, environment, namespace, rootsAB); err != nil {
			t.Fatal(err)
		}
		// The gateway's SDS ROOTCA is cached with its workload certificate;
		// publishing the ConfigMap does not refresh that cache. Reacquire an A
		// identity with A+B roots before EPE starts serving a B certificate.
		if err := restartEPEGateway(ctx, environment, namespace); err != nil {
			t.Fatal(err)
		}
		traffic(t)
		data["ca-cert.pem"] = rootsB
		data["ca-key.pem"] = epePrivateKeyPEM(t, caB)
		// Reorder the overlap bundle with the signer change to trigger CA-mode
		// EPE renewal immediately, retaining A for existing workloads.
		data["root-cert.pem"] = bytes.Join([][]byte{rootsB, rootsA}, []byte("\n"))
		if err := setAuthority(ctx, data); err != nil {
			t.Fatal(err)
		}
		// Trust only B on this fresh client connection. Success proves the EPE
		// renewed with the new signing CA, not merely that the bundle changed.
		observe(t, rootsB, clientB, nil)
		traffic(t)
		unchanged(t, initial)
	})

	applyMaterial := func(t *testing.T, kind string, data map[string]any, mode kube.Mode) {
		t.Helper()
		object := map[string]any{"apiVersion": "v1", "kind": kind, "metadata": map[string]any{"name": materialName}}
		maps.Copy(object, data)
		if _, err := scope.ApplyInNamespace(
			ctx,
			namespace,
			&unstructured.Unstructured{Object: object},
			mode,
		); err != nil {
			t.Fatal(err)
		}
	}
	writeCertificate := func(t *testing.T, cert tls.Certificate, mode kube.Mode) {
		t.Helper()
		applyMaterial(t, "Secret", map[string]any{"stringData": map[string]any{
			"tls.crt": string(epeCertificatePEM(cert)),
			"tls.key": string(epePrivateKeyPEM(t, cert)),
		}}, mode)
	}
	writeRoots := func(t *testing.T, roots []byte, mode kube.Mode) {
		t.Helper()
		applyMaterial(t, "ConfigMap", map[string]any{"data": map[string]any{"ca.crt": string(roots)}}, mode)
	}
	step("helm_file_source_mounts_Secret_and_ConfigMap", func(t *testing.T) {
		cert := newEPECertificate(t, &caA, identity)
		writeCertificate(t, cert, kube.CreateOnly)
		writeRoots(t, rootsA, kube.CreateOnly)
		upgrade(t, `epe:
  tls:
    enabled: true
    certificateSource:
      file:
        certificateFile: /custom/identity/tls.crt
        privateKeyFile: /custom/identity/tls.key
        caCertificateFile: /custom/trust/ca.crt
  extraVolumes:
  - name: serving-identity
    secret: {secretName: epe-helm-mtls}
  - name: client-trust
    configMap: {name: epe-helm-mtls}
  extraVolumeMounts:
  - {name: serving-identity, mountPath: /custom/identity, readOnly: true}
  - {name: client-trust, mountPath: /custom/trust, readOnly: true}
`)
		initial = pod(t)
		observe(t, rootsA, clientA, cert.Leaf)
		traffic(t)
	})
	step("file_leaf_rotation_without_restart", func(t *testing.T) {
		cert := newEPECertificate(t, &caA, identity)
		writeCertificate(t, cert, kube.ReconcileOwned)
		observe(t, rootsA, clientA, cert.Leaf)
		traffic(t)
		unchanged(t, initial)
	})
	step("file_trust_overlap_accepts_A_and_B", func(t *testing.T) {
		writeRoots(t, rootsAB, kube.ReconcileOwned)
		observe(t, rootsA, clientB, nil)
		observe(t, rootsA, clientA, nil)
	})
	// The fixture's workload proxy retains its initial roots. Use a fresh caller
	// with the overlap bundle for B, without changing the shared A fixture or
	// claiming to test workload-proxy trust rotation as part of EPE rotation.
	source = echo.Deploy(t, environment, echo.Config{
		Name:         "epe-ca-b-client",
		Namespace:    trafficFixture.Namespace.Name(),
		Replicas:     1,
		Image:        echo.DefaultImage,
		Ports:        echo.DefaultPorts(),
		CallTimeout:  90 * time.Second,
		Converge:     3,
		Labels:       map[string]string{"app": "epe-ca-b-client"},
		Capabilities: harness.ClientCapabilities(),
	})
	step("file_CA_B_certificate_and_gateway_identity", func(t *testing.T) {
		cert := newEPECertificate(t, &caB, identity)
		writeCertificate(t, cert, kube.ReconcileOwned)
		observe(t, rootsB, clientB, cert.Leaf)
		// The gateway's long-lived A certificate is valid during overlap. Restart
		// only the gateway to obtain B from real Agentiod/SDS before withdrawing A.
		if err := restartEPEGateway(ctx, environment, namespace); err != nil {
			t.Fatal(err)
		}
		traffic(t)
		unchanged(t, initial)
	})
	step("file_withdraws_A_and_keeps_B_without_restart", func(t *testing.T) {
		writeRoots(t, rootsB, kube.ReconcileOwned)
		harness.RetryAssertion(t, 3*time.Minute, time.Second, func() error {
			if _, err := probe(t, rootsB, clientB); err != nil {
				return fmt.Errorf("B client rejected: %w", err)
			}
			if _, err := probe(t, rootsB, clientA); err == nil {
				return fmt.Errorf("withdrawn A client still accepted")
			} else if !strings.Contains(err.Error(), "tls:") {
				return fmt.Errorf("expected TLS rejection of withdrawn A client: %w", err)
			}
			return nil
		})
		traffic(t)
		unchanged(t, initial)
	})
}

func waitEPETrustBundle(ctx context.Context, environment *e2e.Environment, namespace string, want []byte) error {
	return retry.UntilSuccess(
		ctx,
		retry.Policy{Timeout: 2 * time.Minute, Delay: time.Second, Backoff: 1},
		func() error {
			bundle, err := environment.Cluster.Kube.CoreV1().
				ConfigMaps(namespace).
				Get(ctx, "agentio-ca-root-cert", metav1.GetOptions{})
			if err != nil {
				return err
			}
			if bundle.Data["root-cert.pem"] != string(want) {
				return fmt.Errorf("workload trust bundle has not propagated")
			}
			return nil
		},
	)
}

func restartEPEGateway(ctx context.Context, environment *e2e.Environment, namespace string) error {
	pods, err := environment.Kube.ReadyPods(ctx, namespace, harness.GatewayPodSelector)
	if err != nil {
		return err
	}
	old := make(map[types.UID]bool)
	for _, pod := range pods {
		old[pod.UID] = true
		if err := environment.Cluster.Kube.CoreV1().
			Pods(namespace).
			Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	return retry.UntilSuccess(
		ctx,
		retry.Policy{Timeout: 2 * time.Minute, Delay: time.Second, Backoff: 1},
		func() error {
			ready, err := environment.Kube.ReadyPods(ctx, namespace, harness.GatewayPodSelector)
			if err != nil {
				return err
			}
			for _, pod := range ready {
				if !old[pod.UID] && pod.DeletionTimestamp == nil {
					return nil
				}
			}
			return fmt.Errorf("replacement gateway is not ready")
		},
	)
}

func newEPECertificate(t *testing.T, issuer *tls.Certificate, identity string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "EPE rotation test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	parent, signingKey := cert, any(key)
	if issuer == nil {
		cert.IsCA = true
		cert.BasicConstraintsValid = true
		cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		cert.NotAfter = time.Now().AddDate(10, 0, 0)
	} else {
		id, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		cert.URIs = []*url.URL{id}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		parent, signingKey = issuer.Leaf, issuer.PrivateKey
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, parent, key.Public(), signingKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func epeCertificatePEM(cert tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

func epePrivateKeyPEM(t *testing.T, cert tls.Certificate) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Each probe opens a new TLS connection and completes an ext_proc exchange;
// TLS 1.3 can report client-certificate rejection after the client's handshake.
func probeEPECertificate(
	ctx context.Context,
	address, identity string,
	rootsPEM []byte,
	cert tls.Certificate,
) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return nil, fmt.Errorf("invalid probe trust bundle")
	}
	var observed atomic.Pointer[x509.Certificate]
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil },
		// Workload identities use URI SANs. Verify chain and exact URI below.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("missing EPE certificate")
			}
			leaf := state.PeerCertificates[0]
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			if _, err := leaf.Verify(
				x509.VerifyOptions{
					Roots:         roots,
					Intermediates: intermediates,
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				},
			); err != nil {
				return err
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity {
				return fmt.Errorf("unexpected EPE SPIFFE identity: %v", leaf.URIs)
			}
			observed.Store(leaf)
			return nil
		},
	})))
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stream, err := extprocv3.NewExternalProcessorClient(conn).Process(callCtx)
	if err == nil {
		err = stream.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{EndOfStream: true},
		}})
		if err == nil || errors.Is(err, io.EOF) {
			err = stream.CloseSend()
			if err == nil {
				_, err = stream.Recv()
				if err == nil {
					_, err = stream.Recv()
					if errors.Is(err, io.EOF) {
						err = nil
					}
				}
			}
		}
	}
	return observed.Load(), errors.Join(err, conn.Close())
}
