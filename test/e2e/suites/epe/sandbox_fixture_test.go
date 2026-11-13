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
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	securityapi "istio.io/api/security/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/hbone"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

var sandboxPolicyGVR = schema.GroupVersionResource{
	Group:    "agents.kruise.io",
	Version:  "v1alpha1",
	Resource: "sandboxes",
}

type sandboxCaller struct {
	name string
	id   string
	pod  corev1.Pod
	tls  *tls.Config
}

type sandboxPolicyFixture struct {
	environment *e2e.Environment
	scope       *kube.ResourceScope
	ctx         context.Context
	namespace   string
	serverIP    string
	gateway     string
	debug       string
	roots       *x509.CertPool
	ca          securityapi.IstioCertificateServiceClient
	gatewayID   string
}

func newSandboxPolicyFixture(t *testing.T) *sandboxPolicyFixture {
	t.Helper()
	environment, scope := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 10*time.Minute)
	t.Cleanup(cancel)
	f := &sandboxPolicyFixture{
		environment: environment,
		scope:       scope,
		ctx:         ctx,
		namespace:   trafficFixture.Namespace.Name(),
	}
	f.serverIP = trafficFixture.Server.ServiceIPOrFail(t)
	applySandboxPolicyConfig(t, scope)
	pods, err := environment.Kube.ReadyPods(ctx, resolvedAgentioConfig.Namespace, harness.GatewayPodSelector)
	if err != nil || len(pods) != 1 {
		t.Fatalf("find gateway: %v, pods=%d", err, len(pods))
	}
	f.gateway = epeForwardPort(t, environment, resolvedAgentioConfig.Namespace, pods[0].Name, 15008)
	f.gatewayID = "spiffe://cluster.local/ns/" + resolvedAgentioConfig.Namespace + "/sa/" + pods[0].Spec.ServiceAccountName
	pods, err = environment.Kube.ReadyPods(ctx, resolvedAgentioConfig.Namespace, "app.kubernetes.io/name=agentiod")
	if err != nil || len(pods) != 1 {
		t.Fatalf("find agentiod: %v, pods=%d", err, len(pods))
	}
	f.debug = "http://" + epeForwardPort(
		t,
		environment,
		resolvedAgentioConfig.Namespace,
		pods[0].Name,
		15014,
	) + "/debug/configz"
	caAddress := epeForwardPort(t, environment, resolvedAgentioConfig.Namespace, pods[0].Name, 15012)
	cm, err := environment.Cluster.Kube.CoreV1().
		ConfigMaps(resolvedAgentioConfig.Namespace).
		Get(ctx, "agentio-ca-root-cert", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f.roots = x509.NewCertPool()
	if !f.roots.AppendCertsFromPEM([]byte(cm.Data["root-cert.pem"])) {
		t.Fatal("empty Agentio trust bundle")
	}
	conn, err := grpc.NewClient(caAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    f.roots,
		ServerName: "agentiod." + resolvedAgentioConfig.Namespace + ".svc",
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close CA client: %v", err)
		}
	})
	f.ca = securityapi.NewIstioCertificateServiceClient(conn)
	return f
}

func (f *sandboxPolicyFixture) caller(t *testing.T, name string, owned bool) sandboxCaller {
	t.Helper()
	caller := sandboxCaller{name: name}
	var owners []any
	if owned {
		// Delivery identity deliberately differs from the namespace/name alias.
		caller.id = "kruise:delivery-" + name
		record, err := f.scope.ApplyInNamespace(f.ctx, f.namespace, sandboxPolicyObject(name, ""), kube.CreateOnly)
		if err != nil {
			t.Fatal(err)
		}
		owners = []any{
			map[string]any{
				"apiVersion": "agents.kruise.io/v1alpha1",
				"kind":       "Sandbox",
				"name":       name,
				"uid":        string(record.UID),
				"controller": true,
			},
		}
	}
	_, err := f.scope.ApplyInNamespace(f.ctx, f.namespace, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":            name,
			"labels":          map[string]any{"app": name, "agentio.kruise.io/dataplane-mode": "none"},
			"ownerReferences": owners,
		},
		"spec": map[string]any{"containers": []any{
			map[string]any{
				"name":  "app",
				"image": echo.DefaultImage,
				"args":  []any{"--port=18080"},
				"readinessProbe": map[string]any{
					"tcpSocket":     map[string]any{"port": int64(18080)},
					"periodSeconds": int64(1),
				},
			},
		}},
	}}, kube.CreateOnly)
	if err != nil {
		t.Fatal(err)
	}
	pods, err := f.environment.Kube.WaitReadyPods(f.ctx, f.namespace, "app="+name, 1)
	if err != nil {
		t.Fatal(err)
	}
	caller.pod = pods[0]
	if owned {
		f.bind(t, caller, string(caller.pod.UID))
	}
	caller.tls = f.certificate(t, caller.pod)
	return caller
}

func sandboxPolicyObject(name, rules string) *unstructured.Unstructured {
	annotations := map[string]any{}
	if rules != "" {
		annotations["agents.kruise.io/security-rules"] = rules
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1",
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name":        name,
			"labels":      map[string]any{"agents.kruise.io/sandbox-id": "delivery-" + name},
			"annotations": annotations,
		},
		"spec": map[string]any{},
	}}
}

func (f *sandboxPolicyFixture) rules(t *testing.T, caller sandboxCaller, rules string) {
	t.Helper()
	if _, err := f.scope.ApplyInNamespace(
		f.ctx,
		f.namespace,
		sandboxPolicyObject(caller.name, rules),
		kube.ReconcileOwned,
	); err != nil {
		t.Fatal(err)
	}
}

func (f *sandboxPolicyFixture) bind(t *testing.T, caller sandboxCaller, podUID string) {
	t.Helper()
	api := f.environment.Cluster.Dynamic.Resource(sandboxPolicyGVR).Namespace(f.namespace)
	object, err := api.Get(f.ctx, caller.name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(object.Object, podUID, "status", "podInfo", "podUID"); err != nil {
		t.Fatal(err)
	}
	if _, err := api.UpdateStatus(f.ctx, object, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (f *sandboxPolicyFixture) certificate(t *testing.T, pod corev1.Pod) *tls.Config {
	t.Helper()
	token, err := f.environment.Cluster.Kube.CoreV1().
		ServiceAccounts(pod.Namespace).
		CreateToken(f.ctx, pod.Spec.ServiceAccountName,
			&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
				Audiences: []string{"agentio-ca"},
				BoundObjectRef: &authenticationv1.BoundObjectReference{
					APIVersion: "v1",
					Kind:       "Pod",
					Name:       pod.Name,
					UID:        pod.UID,
				},
			}}, metav1.CreateOptions{})
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
	var response *securityapi.IstioCertificateResponse
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
		defer cancel()
		response, err = f.ca.CreateCertificate(
			metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token.Status.Token),
			&securityapi.IstioCertificateRequest{
				Csr:              string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
				ValidityDuration: 3600,
			},
		)
		return err
	})
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		[]byte(strings.Join(response.CertChain, "\n")),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
		Certificates: []tls.Certificate{cert},
		// Gateway workload certificates identify a SPIFFE URI rather than a DNS name.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			if _, err := state.PeerCertificates[0].Verify(
				x509.VerifyOptions{
					Roots:         f.roots,
					Intermediates: intermediates,
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				},
			); err != nil {
				return err
			}
			for _, uri := range state.PeerCertificates[0].URIs {
				if uri.String() == f.gatewayID {
					return nil
				}
			}
			return fmt.Errorf("gateway certificate does not identify %s", f.gatewayID)
		},
	}
}

type sandboxReply struct {
	connect int
	status  int
	body    string
	peer    *x509.Certificate
}

func (f *sandboxPolicyFixture) request(
	ctx context.Context,
	caller sandboxCaller,
	id, path, port string,
	secure bool,
) (reply sandboxReply, err error) {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	headers := make(http.Header)
	if id != "" {
		headers.Set("X-Agentio-Sandbox-Id", id)
	}
	// These client claims must never change the authenticated WDS lookup.
	headers.Set("X-Agentio-Workload-Name", "forged")
	headers.Set("X-Agentio-Workload-Namespace", "forged")
	conn, status, err := hbone.Dial(ctx, f.gateway, net.JoinHostPort(f.serverIP, port), caller.tls, headers)
	reply = sandboxReply{connect: status}
	if err != nil || status != http.StatusOK {
		return reply, err
	}
	// Close the HBONE tunnel directly; inner TLS Close changes the shared socket's write deadline.
	defer func(tunnel net.Conn) { err = errors.Join(err, tunnel.Close()) }(conn)
	if secure {
		// The echo origin uses a fixture certificate; certificate assertions follow the handshake.
		inner := tls.Client(
			conn,
			&tls.Config{
				ServerName:         trafficFixture.Server.Address(),
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
			},
		)
		if err := inner.HandshakeContext(ctx); err != nil {
			return reply, fmt.Errorf("inner TLS handshake: %w", err)
		}
		reply.peer = inner.ConnectionState().PeerCertificates[0]
		conn = inner
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		scheme+"://"+net.JoinHostPort(trafficFixture.Server.Address(), port)+path,
		nil,
	)
	if err != nil {
		return reply, err
	}
	req.Close = true
	req.Header.Set("X-Sandbox-Policy", "must-be-replaced")
	if err := req.Write(conn); err != nil {
		return reply, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return reply, err
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	reply.status, reply.body = response.StatusCode, string(body)
	return reply, err
}

func (f *sandboxPolicyFixture) check(
	t *testing.T,
	caller sandboxCaller,
	id, path string,
	secure bool,
	status int,
	body string,
) sandboxReply {
	t.Helper()
	var reply sandboxReply
	port := "80"
	if secure {
		port = "443"
	}
	harness.RetryAssertion(t, 90*time.Second, time.Second, func() error {
		ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
		defer cancel()
		var err error
		reply, err = f.request(ctx, caller, id, path, port, secure)
		if err != nil {
			return err
		}
		if reply.connect != http.StatusOK || reply.status != status || !strings.Contains(reply.body, body) {
			return fmt.Errorf(
				"Sandbox %s CONNECT=%d HTTP=%d body=%q, want HTTP=%d containing %q",
				id,
				reply.connect,
				reply.status,
				reply.body,
				status,
				body,
			)
		}
		return nil
	})
	return reply
}

func (f *sandboxPolicyFixture) compileFailure(t *testing.T, caller sandboxCaller) {
	t.Helper()
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.debug, nil)
		if err != nil {
			return err
		}
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer func() {
			if err := response.Body.Close(); err != nil {
				t.Errorf("close config debug response: %v", err)
			}
		}()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("config debug returned %d", response.StatusCode)
		}
		var dump struct{ Failures []struct{ Key string } }
		if err := json.NewDecoder(response.Body).Decode(&dump); err != nil {
			return err
		}
		for _, failure := range dump.Failures {
			if failure.Key == "SandboxPolicies/"+caller.id {
				return nil
			}
		}
		return fmt.Errorf("Sandbox compiler has not reported the invalid update")
	})
}

func (f *sandboxPolicyFixture) staleProfiles(t *testing.T, want int) {
	t.Helper()
	endpoint := fmt.Sprintf(
		"http://%s.%s.svc.cluster.local:%d/metrics",
		epeName,
		resolvedAgentioConfig.Namespace,
		epeMetricsPort,
	)
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
		defer cancel()
		output, stderr, err := trafficFixture.Client.Exec(ctx, []string{"curl", "-fsS", "--max-time", "8", endpoint})
		if err != nil {
			return fmt.Errorf("read EPE policy state: %w; stderr=%s", err, stderr)
		}
		if !strings.Contains(output, fmt.Sprintf("\nepe_profile_stale{scope=\"pod\"} %d\n", want)) {
			return fmt.Errorf("EPE has not observed the Sandbox policy state, want stale=%d", want)
		}
		return nil
	})
}

func sandboxTLSRejected(err error) bool {
	var networkError net.Error
	if err == nil || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &networkError) && networkError.Timeout() {
		return false
	}
	var reset http2.StreamError
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.As(err, &reset) &&
			reset.Code == http2.ErrCodeCancel || strings.Contains(err.Error(), "remote error: tls:")
}
