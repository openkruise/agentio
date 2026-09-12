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

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/ca"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

// Deliberately uses the legacy proxy name to exercise old injector ConfigMaps end to end.
const integrationInjectorTemplate = `apiVersion: v1
kind: Pod
metadata:
  labels:
    sidecar.agentio.kruise.io/injected: "true"
spec:
  containers:
  - name: agentio-proxy
    image: docker.io/agentio/ztunnel:test
    args:
    - proxy
    - ztunnel
    env:
    - name: CA_ADDRESS
      value: agentiod.agentio-system.svc:15012
    volumeMounts:
    - mountPath: /var/run/secrets/istio
      name: agentiod-ca-cert
  volumes:
  - name: agentiod-ca-cert
    configMap:
      name: {{ .Values.global.trustBundleName | default "agentio-ca-root-cert" }}
`

const integrationValues = `
global:
  hub: docker.io/agentio
  trustBundleName: agentio-ca-root-cert
  proxyZtunnel:
    image: docker.io/agentio/ztunnel:test
sidecarInjectorWebhook:
  rewriteAppHTTPProbe: false
`

type nilAuthenticator struct{}

func (nilAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	return model.PeerIdentity{}, fmt.Errorf("not implemented in this test")
}

// TestSidecarInjectorEndToEnd exercises the production wiring: a real
// Authority (self-generated CA), the ConfigMap watcher, the caBundle patcher,
// and the HTTPS listener, driven by a real TLS-verified HTTP client.
func TestSidecarInjectorEndToEnd(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("client-trust-%v", enabled), func(t *testing.T) {
			testSidecarInjectorEndToEnd(t, enabled)
		})
	}
}

func testSidecarInjectorEndToEnd(t *testing.T, enableClientTrust bool) {
	t.Helper()
	const namespace = "agentio-system"
	const configMapName = "agentio-sidecar-injector"
	const webhookConfigName = "agentio-sidecar-injector-agentio-system"

	injectorConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: configMapName, Namespace: namespace},
		Data: map[string]string{
			"config": "policy: enabled\ndefaultTemplates: [sidecar]\naliases:\n  sidecar: [ztunnel]\ntemplates:\n  ztunnel: |\n" +
				indentTemplate(integrationInjectorTemplate, "    "),
			"values": integrationValues + "\nclientTrust: {enabled: true}\nclientTrustBundle:\n  sources:\n  - agentioMITM: true\n",
		},
	}
	mutatingWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: webhookConfigName},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{Name: "rev.namespace.sidecar-injector.istio.io"},
		},
	}
	client := kube.NewFakeClient(injectorConfigMap, mutatingWebhook, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}})
	coreClient := client.Kube()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	authority, err := ca.LoadOrCreateAuthority(ctx, client, nilAuthenticator{}, ca.AuthorityOptions{
		Namespace:     namespace,
		SecretName:    "test-ca",
		ConfigMapName: "test-ca-certs",
		LeafLifetime:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	// Close the probe listener: the webhook server binds this address itself;
	// leaving the probe bound would stall its ListenAndServeTLS.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	secretInformer := kclient.NewFiltered[*corev1.Secret](client, kclient.Filter{Namespace: namespace})
	secretCollection := krt.WrapClient(secretInformer, krt.WithStop(ctx.Done()))
	secretInformer.Start(ctx.Done())
	serve, err := setupSidecarInjector(ctx, client, authority, SidecarInjectorOptions{
		EnableClientTrust: enableClientTrust,
		Secrets:           secretCollection,
		MITMTrustBundle:   krt.NewStatic(&mitm.TrustBundle{PEM: string(authority.RootPEM())}, true),
		Address:           address,
		Namespace:         namespace,
		ConfigMapName:     configMapName,
		WebhookConfigName: webhookConfigName,
		NativeSidecarMode: "false",
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = serve() }()

	tlsConfig := &tls.Config{ServerName: "localhost"}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.RootPEM()) {
		t.Fatal("failed to build root pool from authority root")
	}
	tlsConfig.RootCAs = roots
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://%s/inject", address)

	// The webhook rejects requests until the ConfigMap watcher loads the
	// templates; wait for it to accept.
	review := buildReview(t, "demo", "hello")
	var lastErr error
	waitFor(t, func() bool {
		response, err := postReview(t, httpClient, url, review)
		if err != nil {
			lastErr = err
			return false
		}
		lastErr = nil
		return response != nil && response.Allowed
	}, func() string { return fmt.Sprintf("webhook to accept injection requests (last error: %v)", lastErr) })

	response, err := postReview(t, httpClient, url, review)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Allowed || response.Patch == nil {
		t.Fatalf("response = allowed=%v patch=%s, want allowed patch", response.Allowed, response.Patch)
	}
	patch, err := jsonpatch.DecodePatch(response.Patch)
	if err != nil {
		t.Fatal(err)
	}
	patchedJSON, err := patch.Apply(review.Request.Object.Raw)
	if err != nil {
		t.Fatal(err)
	}
	injected := &corev1.Pod{}
	if err := json.Unmarshal(patchedJSON, injected); err != nil {
		t.Fatal(err)
	}
	if got := injected.Labels[clienttrust.ManagedLabel] == "true"; got != enableClientTrust {
		t.Fatalf("client trust injected=%v, process gate=%v", got, enableClientTrust)
	}
	if enableClientTrust {
		waitFor(t, func() bool {
			cm, err := coreClient.CoreV1().ConfigMaps("demo").Get(ctx, "agentio-client-ca", metav1.GetOptions{})
			return err == nil && cm.Data["ca-bundle.pem"] == string(authority.RootPEM())
		}, func() string { return "enabled client trust distributor to publish its bundle" })
	} else {
		for _, action := range coreClient.(*kubefake.Clientset).Actions() {
			if action.GetResource().Resource == "namespaces" && (action.GetVerb() == "list" || action.GetVerb() == "watch") {
				t.Fatalf("disabled distributor started a namespace informer: %v", action)
			}
		}
		if _, err := coreClient.CoordinationV1().Leases(namespace).Get(ctx, "agentiod-client-trust-leader", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("disabled distributor participated in leader election: %v", err)
		}
	}

	sidecar := findContainer(injected.Spec.Containers, "agentio-proxy")
	if sidecar == nil {
		t.Fatalf("injected pod missing agentio-proxy: %+v", injected.Spec.Containers)
	}
	if sidecar.Image != "docker.io/agentio/ztunnel:test" {
		t.Fatalf("sidecar image = %q, want the template image", sidecar.Image)
	}
	if injected.Labels["sidecar.agentio.kruise.io/injected"] != "true" {
		t.Fatalf("template labels not applied: %v", injected.Labels)
	}
	if status := injected.Annotations["sidecar.istio.io/status"]; status == "" {
		t.Fatal("injected pod missing sidecar.istio.io/status")
	}
	if revision, found := injected.Annotations["istio.io/rev"]; found {
		t.Fatalf("injected Pod has legacy revision annotation %q", revision)
	}
	statusFields := map[string]any{}
	if err := json.Unmarshal([]byte(injected.Annotations["sidecar.istio.io/status"]), &statusFields); err != nil {
		t.Fatalf("parse status annotation: %v", err)
	}
	if revision, found := statusFields["revision"]; found {
		t.Fatalf("status annotation has legacy revision field %v", revision)
	}

	// The caBundle patcher kept the webhook configuration in sync with the
	// workload root.
	current, err := coreClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, webhookConfigName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, wh := range current.Webhooks {
		if string(wh.ClientConfig.CABundle) != string(authority.RootPEM()) {
			t.Fatalf("caBundle = %q, want the authority root", wh.ClientConfig.CABundle)
		}
	}
}

func indentTemplate(s, prefix string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString(prefix + line + "\n")
	}
	return b.String()
}

func buildReview(t *testing.T, namespace, name string) *admissionv1.AdmissionReview {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "docker.io/library/nginx:1.27",
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)},
				}},
			}},
		},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("integration"),
			Namespace: namespace,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

func postReview(t *testing.T, client *http.Client, url string, review *admissionv1.AdmissionReview) (*admissionv1.AdmissionResponse, error) {
	t.Helper()
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	httpResponse, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", httpResponse.StatusCode, responseBody)
	}
	out := admissionv1.AdmissionReview{}
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return nil, err
	}
	return out.Response, nil
}

func findContainer(containers []corev1.Container, name string) *corev1.Container {
	for i := range containers {
		if containers[i].Name == name {
			return &containers[i]
		}
	}
	return nil
}

func waitFor(t *testing.T, condition func() bool, message func() string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", message())
}
