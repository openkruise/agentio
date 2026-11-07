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
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/security/ca"
)

func TestValidationWithoutInjector(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := kube.NewFakeClient()
	authority, err := ca.LoadOrCreateAuthority(ctx, client, nilAuthenticator{}, ca.AuthorityOptions{
		TrustDomain:   "cluster.local",
		Namespace:     "agentio-system",
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
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	serve, err := setupAdmissionWebhooks(ctx, client, authority, SidecarInjectorOptions{
		Address: address, ValidationWebhookConfigName: "validator",
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serve() }()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.RootPEM()) {
		t.Fatal("invalid root")
	}
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots}},
		Timeout:   time.Second,
	}
	defer httpClient.CloseIdleConnections()
	review := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID: "ambient-validation", Operation: admissionv1.Create, Namespace: "demo",
			Kind:   metav1.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: "TrafficPolicy"},
			Object: runtime.RawExtension{Raw: []byte(`{"metadata":{"name":"allow"},"spec":{"egress":{}}}`)},
		},
	}
	testutil.Eventually(t, func() bool {
		response, err := postReview(t, httpClient, "https://"+address+"/validate", review)
		return err == nil && response != nil && response.Allowed && response.UID == review.Request.UID
	}, "validation endpoint to accept without injection configuration")
	resp, err := httpClient.Get("https://" + address + "/inject")
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("inject status = %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
