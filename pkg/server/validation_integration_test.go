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
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/ca"
	"github.com/openkruise/agentio/pkg/validation"
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
	stop := ctx.Done()
	effective := model.AgentioConfiguration{Value: &configv1.AgentioConfig{}}
	references := validation.NewReferenceChecker(validation.ReferenceSources{
		AgentioConfig: krt.NewStatic(&effective, true, krt.WithStop(stop)).AsCollection(),
		ConfigMaps:    krt.NewStaticCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(stop)),
		Secrets:       krt.NewStaticCollection[*corev1.Secret](nil, nil, krt.WithStop(stop)),
		Services:      krt.NewStaticCollection[*corev1.Service](nil, nil, krt.WithStop(stop)),
		RootNamespace: "agentio-system",
	}, stop)
	serve, err := setupAdmissionWebhooks(ctx, client, authority, SidecarInjectorOptions{
		Address:                     address,
		ValidationWebhookConfigName: "validator",
		ValidationReferences:        references,
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
			UID:       "ambient-validation",
			Operation: admissionv1.Create,
			Namespace: "demo",
			Kind:      metav1.GroupVersionKind{Group: "agents.kruise.io", Version: "v1alpha1", Kind: "TrafficPolicy"},
			Object: runtime.RawExtension{Raw: []byte(`{
				"metadata":{"name":"allow"},
				"spec":{"egress":{"rules":[{"action":"allow","to":[{"service":{"name":"api"}}]}]}}
			}`)},
		},
	}
	testutil.Eventually(t, func() bool {
		response, err := postReview(t, httpClient, "https://"+address+"/validate", review)
		return err == nil && response != nil && response.Allowed && response.UID == review.Request.UID
	}, "validation endpoint to accept without injection configuration")
	response, err := postReview(t, httpClient, "https://"+address+"/validate", review)
	if err != nil || response == nil || !response.Allowed || len(response.Warnings) != 1 ||
		!strings.Contains(response.Warnings[0], "Service demo/api not found") {
		t.Fatalf("validation response = %+v error = %v, want a missing Service warning", response, err)
	}
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
