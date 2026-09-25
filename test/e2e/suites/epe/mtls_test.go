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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	securityapi "istio.io/api/security/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestEPEGatewayMTLS uses the production CA, gateway SDS, EPE process and
// trust-bundle watches. The test client also holds one HTTP/2 connection open
// to verify serving readiness during certificate and trust-material outages.
func TestEPEGatewayMTLS(t *testing.T) {
	rig.RequireLive(t)
	environment, scope := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 10*time.Minute)
	defer cancel()
	namespace := resolvedAgentioConfig.Namespace
	const name = "epe-gateway-mtls"
	pods, err := environment.Kube.ReadyPods(ctx, namespace, harness.GatewayPodSelector)
	if err != nil || len(pods) == 0 {
		t.Fatalf("gateway pods: %v", err)
	}
	gatewaySA := pods[0].Spec.ServiceAccountName
	gatewayID := "spiffe://cluster.local/ns/" + namespace + "/sa/" + gatewaySA
	epeID := "spiffe://cluster.local/ns/" + namespace + "/sa/agentio-epe"
	cm, err := environment.Cluster.Kube.CoreV1().
		ConfigMaps(namespace).
		Get(ctx, "agentio-ca-root-cert", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := cm.Data["root-cert.pem"]
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(rootPEM)) {
		t.Fatal("workload trust bundle is empty")
	}
	caPods, err := environment.Kube.ReadyPods(ctx, namespace, "app.kubernetes.io/name=agentiod")
	if err != nil || len(caPods) == 0 {
		t.Fatalf("agentiod pods: %v", err)
	}
	caAddress := epeForwardPort(t, environment, namespace, caPods[0].Name, 15012)
	caConn, err := grpc.NewClient(caAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: "agentiod." + namespace + ".svc",
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caConn.Close(); err != nil {
			t.Error(err)
		}
	})
	issue := func(t *testing.T, sa string) ([]byte, []byte) {
		t.Helper()
		token, err := environment.Cluster.Kube.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, sa,
			&authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{Audiences: []string{"agentio-ca"}},
			}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			t.Fatal(err)
		}
		response, err := securityapi.NewIstioCertificateServiceClient(caConn).CreateCertificate(
			metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token.Status.Token),
			&securityapi.IstioCertificateRequest{
				Csr:              string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
				ValidityDuration: 3600,
			})
		if err != nil {
			t.Fatalf("issue certificate for %s: %v", sa, err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(
				strings.Join(response.CertChain, "\n"),
			), pem.EncodeToMemory(
				&pem.Block{Type: "EC PRIVATE KEY", Bytes: der},
			)
	}
	apply := func(t *testing.T, kind, resource string, data map[string]any, mode kube.Mode) kube.ResourceRecord {
		t.Helper()
		object := map[string]any{"apiVersion": "v1", "kind": kind, "metadata": map[string]any{"name": resource}}
		maps.Copy(object, data)
		record, err := scope.ApplyInNamespace(ctx, namespace, &unstructured.Unstructured{Object: object}, mode)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	// Start without an EPEConfig: client authentication depends only on CA trust.
	applyRoots := func(t *testing.T, value string, mode kube.Mode) {
		apply(t, "ConfigMap", name+"-roots", map[string]any{"data": map[string]any{"root-cert.pem": value}}, mode)
	}
	applyRoots(t, rootPEM, kube.CreateOnly)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		logCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		logs, err := environment.Kube.Logs(logCtx, namespace, name, "epe", nil)
		t.Logf("EPE logs (%v):\n%s", err, logs)
	})
	e2econfig.New(scope).
		Eval(namespace, map[string]any{"Name": name, "Namespace": namespace, "Image": resolvedAgentioConfig.EPEImage}, mtlsEPEYAML).
		ApplyOrFail(t, kube.CreateOnly)
	if _, err := environment.Kube.WaitReadyPods(ctx, namespace, "app="+name, 1); err != nil {
		t.Fatal(err)
	}
	initial, err := environment.Cluster.Kube.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e2econfig.New(scope).YAML(trafficFixture.Namespace.Name(), `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: epe-mtls-proof
spec:
  selector: {}
  rules:
  - name: proof
    match:
    - domains: ["*"]
      paths:
      - type: Exact
        value: /epe-mtls
    actions:
      block:
        statusCode: 452
        body: epe-mtls-proof
`).ApplyOrFail(t, kube.CreateOnly)
	gatewayConfig := func(t *testing.T, peer string) {
		t.Helper()
		rig.ApplyConfig(t, scope, map[string]any{"Namespace": namespace, "Name": name, "Peer": peer}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: {{ .Name }}.{{ .Namespace }}.svc.cluster.local
      port: 9002
      messageTimeout: 5s
      request:
        attributes:
        - filter_state['sandbox.id']
        - filter_state['agentio.workload.name']
        - filter_state['agentio.workload.namespace']
        - filter_state['downstream_peer'].name
        - filter_state['downstream_peer'].namespace
      tls:
        mode: MUTUAL
        peerSpiffeIDs: [{{ .Peer | printf "%q" }}]
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
`)
	}
	traffic := func(t *testing.T, want int) {
		t.Helper()
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			output, stderr, err := trafficFixture.Client.Exec(
				ctx,
				[]string{
					"curl",
					"-sS",
					"--max-time",
					"10",
					"--noproxy",
					"*",
					"-o",
					"/dev/null",
					"-w",
					"%{http_code}",
					"http://" + trafficFixture.Server.Address() + "/epe-mtls",
				},
			)
			if err != nil {
				return fmt.Errorf("traffic: %w: %s", err, stderr)
			}
			if strings.TrimSpace(output) != fmt.Sprint(want) {
				return fmt.Errorf("status %s, want %d", output, want)
			}
			return nil
		})
	}
	address := epeForwardPort(t, environment, namespace, name, 9002)
	clientPEM, clientKey := issue(t, gatewaySA)
	clientCert, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}

	var initialServing atomic.Pointer[x509.Certificate]
	clientTLS := func(cert *tls.Certificate) *tls.Config {
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS13,
			// SPIFFE certificates have URI SANs, not DNS SANs. Verify both the
			// chain and exact URI explicitly; trust verification remains mandatory.
			InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return fmt.Errorf("missing EPE certificate")
				}
				intermediates := x509.NewCertPool()
				for _, cert := range state.PeerCertificates[1:] {
					intermediates.AddCert(cert)
				}
				leaf := state.PeerCertificates[0]
				if _, err := leaf.Verify(
					x509.VerifyOptions{
						Roots:         roots,
						Intermediates: intermediates,
						KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					},
				); err != nil {
					return err
				}
				for _, id := range leaf.URIs {
					if id.String() == epeID {
						initialServing.CompareAndSwap(nil, leaf)
						return nil
					}
				}
				return fmt.Errorf("unexpected EPE identity")
			},
		}
		if cert != nil {
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return cert, nil
			}
		}
		return cfg
	}

	var dials atomic.Int32
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS(&clientCert))),
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	call := func(conn *grpc.ClientConn) error {
		callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		stream, err := extprocv3.NewExternalProcessorClient(conn).Process(callCtx)
		if err == nil {
			if err := stream.Send(
				&extprocv3.ProcessingRequest{
					Request: &extprocv3.ProcessingRequest_RequestHeaders{
						RequestHeaders: &extprocv3.HttpHeaders{EndOfStream: true},
					},
				},
			); err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if closeErr := stream.CloseSend(); closeErr != nil {
				return closeErr
			}
			_, err = stream.Recv()
			if err == nil {
				_, err = stream.Recv()
				if errors.Is(err, io.EOF) {
					return nil
				}
			}
		}
		return err
	}
	wantStream := func(t *testing.T, want codes.Code) {
		t.Helper()
		harness.RetryAssertion(t, 30*time.Second, 100*time.Millisecond, func() error {
			err := call(conn)
			if status.Code(err) != want {
				return fmt.Errorf("stream returned %v, want %v: %w", status.Code(err), want, err)
			}
			return nil
		})
	}
	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}
	step("gateway_workload_SDS", func(t *testing.T) {
		gatewayConfig(t, epeID)
		traffic(t, statusIdentityBlock)
		wantStream(t, codes.OK)
	})
	step("accept_other_trusted_workload", func(t *testing.T) {
		// This is deliberately not a gateway identity. CA-only authentication
		// currently admits every client issued by the trusted CA.
		certPEM, keyPEM := issue(t, "agentio-epe")
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		trusted, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS(&cert))))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := trusted.Close(); err != nil {
				t.Error(err)
			}
		}()
		if err := call(trusted); err != nil {
			t.Fatalf("trusted workload rejected: %v", err)
		}
	})
	step("reject_plaintext_missing_and_untrusted_certificates", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := url.Parse(gatewayID)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			URIs:         []*url.URL{identity},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		foreign := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		for _, transport := range []credentials.TransportCredentials{insecure.NewCredentials(), credentials.NewTLS(clientTLS(nil)), credentials.NewTLS(clientTLS(&foreign))} {
			rejected, err := grpc.NewClient(
				epeForwardPort(t, environment, namespace, name, 9002),
				grpc.WithTransportCredentials(transport),
			)
			if err != nil {
				t.Fatal(err)
			}
			err = call(rejected)
			if closeErr := rejected.Close(); closeErr != nil {
				t.Error(closeErr)
			}
			if err == nil {
				t.Fatal("unauthorized client reached EPE")
			}
		}
	})
	step("gateway_rejects_wrong_EPE_identity", func(t *testing.T) {
		gatewayConfig(t, gatewayID)
		traffic(t, 500)
		gatewayConfig(t, epeID)
		traffic(t, statusIdentityBlock)
	})
	step("server_certificate_rotates_without_restart", func(t *testing.T) {
		certificateAddress := epeForwardPort(t, environment, namespace, name, 9002)
		harness.RetryAssertion(t, 2*time.Minute, 2*time.Second, func() error {
			var observed atomic.Pointer[x509.Certificate]
			cfg := clientTLS(&clientCert)
			verify := cfg.VerifyConnection
			cfg.VerifyConnection = func(state tls.ConnectionState) error {
				if err := verify(state); err != nil {
					return err
				}
				observed.Store(state.PeerCertificates[0])
				return nil
			}
			fresh, err := grpc.NewClient(certificateAddress, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
			if err != nil {
				return err
			}
			defer func() {
				if err := fresh.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := call(fresh); err != nil {
				return err
			}
			got := observed.Load()
			if got == nil || got.Equal(initialServing.Load()) {
				return fmt.Errorf("old serving certificate is still loaded")
			}
			return nil
		})
		traffic(t, statusIdentityBlock)
	})
	healthAddress := epeForwardPort(t, environment, namespace, name, 9003)
	healthConn, err := grpc.NewClient(healthAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := healthConn.Close(); err != nil {
			t.Error(err)
		}
	})
	wantHealth := func(t *testing.T, service string, want healthpb.HealthCheckResponse_ServingStatus) {
		t.Helper()
		harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
			checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			response, err := healthpb.NewHealthClient(healthConn).
				Check(checkCtx, &healthpb.HealthCheckRequest{Service: service})
			if err != nil {
				return err
			}
			if response.Status != want {
				return fmt.Errorf("health %s: %s, want %s", service, response.Status, want)
			}
			return nil
		})
	}
	step("CA_outage_expiry_and_recovery", func(t *testing.T) {
		deployments, err := environment.Cluster.Kube.AppsV1().
			Deployments(namespace).
			List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=agentiod"})
		if err != nil || len(deployments.Items) != 1 {
			t.Fatalf("find Agentiod: %v", err)
		}
		deployment := deployments.Items[0]
		replicas := *deployment.Spec.Replicas
		scale := func(ctx context.Context, replicas int32) error {
			api := environment.Cluster.Kube.AppsV1().Deployments(namespace)
			current, err := api.GetScale(ctx, deployment.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			current.Spec.Replicas = replicas
			_, err = api.UpdateScale(ctx, deployment.Name, current, metav1.UpdateOptions{})
			return err
		}
		t.Cleanup(func() {
			cleanupCtx, stop := context.WithTimeout(context.Background(), time.Minute)
			defer stop()
			if err := scale(cleanupCtx, replicas); err != nil {
				t.Error(err)
			}
		})
		if err := scale(ctx, 0); err != nil {
			t.Fatal(err)
		}
		wantHealth(t, "readiness", healthpb.HealthCheckResponse_NOT_SERVING)
		wantHealth(t, "liveness", healthpb.HealthCheckResponse_SERVING)
		wantStream(t, codes.Unavailable)
		if err := scale(ctx, replicas); err != nil {
			t.Fatal(err)
		}
		wantHealth(t, "readiness", healthpb.HealthCheckResponse_SERVING)
		wantStream(t, codes.OK)
		traffic(t, statusIdentityBlock)
		if dials.Load() != 1 {
			t.Fatalf("CA recovery changed the held connection: %d dials", dials.Load())
		}
	})
	step("trust_bundle_updates_without_restart", func(t *testing.T) {
		applyRoots(t, "invalid trust bundle", kube.ReconcileOwned)
		wantHealth(t, "readiness", healthpb.HealthCheckResponse_NOT_SERVING)
		wantHealth(t, "liveness", healthpb.HealthCheckResponse_SERVING)
		wantStream(t, codes.Unavailable)
		applyRoots(t, rootPEM, kube.ReconcileOwned)
		wantHealth(t, "readiness", healthpb.HealthCheckResponse_SERVING)
		wantStream(t, codes.OK)
		traffic(t, statusIdentityBlock)
	})
	final, err := environment.Cluster.Kube.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if final.UID != initial.UID || restartCount(*final) != 0 {
		t.Fatal("EPE restarted during hot updates")
	}
}

func epeForwardPort(t *testing.T, environment *e2e.Environment, namespace, pod string, port int) string {
	t.Helper()
	address, _ := startEPEPortForward(t, environment, namespace, pod, port)
	return address
}

func startEPEPortForward(t *testing.T, environment *e2e.Environment, namespace, pod string, port int) (string, func()) {
	t.Helper()
	transport, upgrader, err := spdy.RoundTripperFor(environment.Cluster.RESTConfig)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := environment.Cluster.Kube.CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Namespace(namespace).
		Name(pod).
		SubResource("portforward").
		URL()
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, endpoint)
	stop, ready := make(chan struct{}), make(chan struct{})
	forward, err := portforward.NewOnAddresses(
		dialer,
		[]string{"127.0.0.1"},
		[]string{fmt.Sprintf("0:%d", port)},
		stop,
		ready,
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- forward.ForwardPorts() }()
	stopForward := sync.OnceFunc(func() { close(stop) })
	t.Cleanup(stopForward)
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("port forward %s: %v", pod, err)
	case <-time.After(30 * time.Second):
		t.Fatal("port forward did not become ready")
	}
	ports, err := forward.GetPorts()
	if err != nil || len(ports) != 1 {
		t.Fatalf("forwarded ports: %v, %v", ports, err)
	}
	return fmt.Sprintf("127.0.0.1:%d", ports[0].Local), stopForward
}

const mtlsEPEYAML = `
apiVersion: v1
kind: Service
metadata:
  name: {{ .Name }}
spec:
  selector: {app: {{ .Name }}}
  ports: [{name: grpc, port: 9002, targetPort: 9002}]
---
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Name }}
  labels: {app: {{ .Name }}, agentio.kruise.io/dataplane-mode: none}
spec:
  serviceAccountName: agentio-epe
  containers:
  - name: epe
    image: {{ .Image }}
    args:
    - -epe-config={{ .Name }}
    - -epe-config-primary={{ .Name }}-primary
    - -epe-config-namespace={{ .Namespace }}
    - -tls-source=ca
    - -ca-address=agentiod.{{ .Namespace }}.svc:15012
    - -tls-spiffe-id=spiffe://cluster.local/ns/{{ .Namespace }}/sa/agentio-epe
    - -tls-cert-lifetime=20s
    env: [{name: CREDENTIAL_PROVIDER_MTLS_SOURCE, value: none}]
    readinessProbe:
      grpc: {port: 9003, service: readiness}
      periodSeconds: 1
    livenessProbe:
      grpc: {port: 9003, service: liveness}
      periodSeconds: 1
    volumeMounts:
    - {name: roots, mountPath: /var/run/secrets/agentio, readOnly: true}
    - {name: token, mountPath: /var/run/secrets/tokens, readOnly: true}
    resources:
      requests: {cpu: 100m, memory: 128Mi}
      limits: {cpu: "1", memory: 512Mi}
  volumes:
  - name: roots
    configMap: {name: {{ .Name }}-roots}
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          audience: agentio-ca
          expirationSeconds: 3600
          path: agentio-token
`
