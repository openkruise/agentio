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

package ca

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/security/internal/casecret"
	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestLoadOrCreateAuthorityReusesAgentioCAByDefault(t *testing.T) {
	const namespace = "agentio-system"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	secret := newWorkloadCASecret(t, namespace, "agentio-ca-secret", 24*time.Hour)
	client := kube.NewFakeClient(secret)
	go client.Run(ctx.Done())
	authority, err := LoadOrCreateAuthority(
		ctx,
		client,
		staticAuthenticator{},
		AuthorityOptions{TrustDomain: "cluster.local",
			Namespace:     namespace,
			ConfigMapName: "agentio-ca-certs",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authority.RootPEM(), secret.Data[caBundleKey]) {
		t.Fatal("authority did not reuse the existing Agentio trust bundle")
	}
	published, err := client.Kube().CoreV1().ConfigMaps(namespace).Get(ctx, "agentio-ca-certs", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := []byte(published.Data[caBundleKey]); !bytes.Equal(got, secret.Data[caBundleKey]) {
		t.Fatal("published trust bundle does not match the reused Agentio CA")
	}
	if _, err := client.Kube().
		CoreV1().
		Secrets(namespace).
		Get(ctx, "agentiod-ca", metav1.GetOptions{}); !apierrors.IsNotFound(
		err,
	) {
		t.Fatalf("unexpected Agentio CA Secret was created: %v", err)
	}
}

func TestLoadOrCreateAuthorityBootstrapsMissingSecret(t *testing.T) {
	const namespace = "agentio-system"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client := kube.NewFakeClient()
	go client.Run(ctx.Done())
	authority, err := LoadOrCreateAuthority(
		ctx,
		client,
		staticAuthenticator{},
		AuthorityOptions{TrustDomain: "cluster.local",
			Namespace:     namespace,
			ConfigMapName: "agentio-ca-certs",
		},
	)
	if err != nil {
		t.Fatalf("LoadOrCreateAuthority() error = %v", err)
	}
	if len(authority.RootPEM()) == 0 {
		t.Fatal("bootstrapped authority has no root")
	}
	if _, err := client.Kube().CoreV1().Secrets(namespace).Get(ctx, "agentio-ca-secret", metav1.GetOptions{}); err != nil {
		t.Fatalf("bootstrapped CA Secret error = %v", err)
	}
}

func TestLoadOrCreateAuthorityRejectsInvalidTrustBundle(t *testing.T) {
	const namespace = "agentio-system"
	for _, tc := range []struct {
		name   string
		bundle func(*testing.T) []byte
	}{
		{name: "malformed", bundle: func(*testing.T) []byte { return []byte("not a certificate") }},
		{
			name: "unrelated",
			bundle: func(t *testing.T) []byte {
				return newWorkloadCASecret(t, namespace, "unrelated", 24*time.Hour).Data[caCertKey]
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := newWorkloadCASecret(t, namespace, "workload", 24*time.Hour)
			secret.Data[caBundleKey] = tc.bundle(t)
			client := kube.NewFakeClient(secret)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go client.Run(ctx.Done())

			_, err := LoadOrCreateAuthority(
				ctx,
				client,
				staticAuthenticator{},
				AuthorityOptions{TrustDomain: "cluster.local",
					Namespace:     namespace,
					SecretName:    "workload",
					ConfigMapName: "roots",
				},
			)
			if err == nil || !strings.Contains(err.Error(), "trust bundle") {
				t.Fatalf("LoadOrCreateAuthority() error = %v, want trust bundle rejection", err)
			}
			if _, getErr := client.Kube().
				CoreV1().
				ConfigMaps(namespace).
				Get(ctx, "roots", metav1.GetOptions{}); !apierrors.IsNotFound(
				getErr,
			) {
				t.Fatalf("root ConfigMap after rejected startup error = %v, want not found", getErr)
			}
		})
	}
}

func TestReconcileCARenewsCertificateAndReusesPrivateKey(t *testing.T) {
	const namespace = "agentio-system"
	now := time.Now().Truncate(time.Second)
	secret, err := casecret.New(namespace, "workload", workloadCAKeys, "Agentio Root CA", 30*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	oldCA, err := pki.ParseSigningCA(secret.Data[caCertKey], secret.Data[caKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := append([]byte(nil), secret.Data[caKeyKey]...)
	client := kube.NewFakeClient(secret)
	authority := &Authority{
		client: client,
		options: AuthorityOptions{TrustDomain: "cluster.local",
			Namespace:    namespace,
			SecretName:   "workload",
			RootLifetime: 24 * time.Hour,
			RenewBefore:  time.Hour,
		},
	}

	if err := authority.reconcileCA(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	rotated, err := client.Kube().CoreV1().Secrets(namespace).Get(context.Background(), "workload", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	newCA, err := pki.ParseSigningCA(rotated.Data[caCertKey], rotated.Data[caKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	if newCA.Revision() == oldCA.Revision() {
		t.Fatal("CA certificate did not rotate")
	}
	if !bytes.Equal(rotated.Data[caKeyKey], oldKey) {
		t.Fatal("CA rotation replaced the private key")
	}
	if !bytes.Equal(rotated.Data[caBundleKey], rotated.Data[caCertKey]) {
		t.Fatal("workload trust bundle is not exactly the renewed active root")
	}
}

func TestCASecretDeletionDisablesSigningAndRetainsCommittedTrust(t *testing.T) {
	const namespace = "agentio-system"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	secret := newWorkloadCASecret(t, namespace, "workload", 24*time.Hour)
	client := kube.NewFakeClient(secret)
	go client.Run(ctx.Done())
	authority, err := LoadOrCreateAuthority(
		ctx,
		client,
		staticAuthenticator{},
		AuthorityOptions{TrustDomain: "cluster.local",
			Namespace:     namespace,
			SecretName:    "workload",
			ConfigMapName: "roots",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantTrust := authority.RootPEM()

	if err := client.Kube().CoreV1().Secrets(namespace).Delete(ctx, "workload", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, func() bool {
		authority.mu.RLock()
		defer authority.mu.RUnlock()
		return !authority.ca.Available()
	}, "workload CA signing state to become unavailable")
	if !bytes.Equal(authority.RootPEM(), wantTrust) {
		t.Fatal("Secret deletion discarded the last committed trust bundle")
	}
}

func newWorkloadCASecret(t *testing.T, namespace, name string, lifetime time.Duration) *corev1.Secret {
	t.Helper()
	secret, err := casecret.New(namespace, name, workloadCAKeys, "Agentio Root CA", lifetime, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return secret
}
