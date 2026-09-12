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

package mitm

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/security/internal/casecret"
	"github.com/openkruise/agentio/pkg/security/pki"
)

func TestCanceledSigningIsRejectedBeforeMITMKeyGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	certificate, err := (&MITMSigner{}).SignDNS(ctx, "api.example.com", time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SignDNS error = %v, want context canceled", err)
	}
	if len(certificate.CertificateChain) != 0 || len(certificate.PrivateKey) != 0 {
		t.Fatalf("canceled SignDNS returned certificate %#v", certificate)
	}
}

func TestMITMSignerPreservesCertificateContractAndCapsExpiry(t *testing.T) {
	now := time.Now()
	secret := newMITMSecret(t, "agentio-system", "mitm", 2*time.Hour, now)
	ca, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	signer := newInstalledMITMSigner(ca, secret.UID, 30*time.Minute)

	signed, err := signer.SignDNS(context.Background(), "api.example.com", 3*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := signed.SignerRevision, ca.Revision(); got != want {
		t.Fatalf("SignerRevision = %q, want %q", got, want)
	}
	if got, want := signed.NotAfter, ca.NotAfter().Add(-30*time.Minute); !got.Equal(want) {
		t.Fatalf("NotAfter = %s, want expiry cap %s", got, want)
	}
	if signed.SignedAt.After(time.Now()) || time.Since(signed.SignedAt) > time.Minute {
		t.Fatalf("SignedAt = %s, want current time", signed.SignedAt)
	}

	leafBlock, chain := pem.Decode(signed.CertificateChain)
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" {
		t.Fatal("certificate chain does not start with a PEM certificate")
	}
	if !bytes.Equal(chain, secret.Data[mitmCACertKey]) {
		t.Fatal("certificate chain does not contain the active MITM CA PEM")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("api.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("ExtKeyUsage = %v, want only ServerAuth", leaf.ExtKeyUsage)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(secret.Data[mitmCACertKey]) {
		t.Fatal("failed to add MITM root")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     "api.example.com",
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: signed.SignedAt,
	}); err != nil {
		t.Fatalf("verify signed certificate: %v", err)
	}
	keyBlock, trailing := pem.Decode(signed.PrivateKey)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" || len(trailing) != 0 {
		t.Fatal("private key is not one RSA PRIVATE KEY PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if bits := key.N.BitLen(); bits != 2048 {
		t.Fatalf("RSA key size = %d, want 2048", bits)
	}
	if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("leaf public key type = %T, want RSA", leaf.PublicKey)
	}
}

func TestSecretModeReadsExistingSecretWithoutMutatingIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	secret := newMITMSecret(t, "agentio-system", "mitm", 24*time.Hour, time.Now())
	client := kube.NewFakeClient(secret)
	go client.Run(ctx.Done())
	signer, err := NewMITMSigner(ctx, client, MITMSignerOptions{
		Mode:       MITMSignModeSecret,
		Namespace:  secret.Namespace,
		SecretName: secret.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	waitForMITM(t, func() bool { return signer.State().Get() != nil }, "SECRET signer state")
	if _, err := signer.SignDNS(ctx, "api.example.com", time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, action := range client.Kube().(*kubefake.Clientset).Actions() {
		if action.GetResource().Resource == "secrets" && (action.GetVerb() == "create" || action.GetVerb() == "update") {
			t.Fatalf("SECRET mode mutated its CA Secret with %s", action.GetVerb())
		}
	}
}

func TestSecretModeDoesNotCreateMissingSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client := kube.NewFakeClient()
	go client.Run(ctx.Done())
	signer, err := NewMITMSigner(ctx, client, MITMSignerOptions{
		Mode:       MITMSignModeSecret,
		Namespace:  "agentio-system",
		SecretName: "mitm",
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if signer.State().Get() != nil {
		t.Fatal("SECRET mode became available without a Secret")
	}
	if _, err := client.Kube().CoreV1().Secrets("agentio-system").Get(ctx, "mitm", metav1.GetOptions{}); err == nil {
		t.Fatal("SECRET mode created a missing Secret")
	}
}

func TestSelfSignModeCreatesOneSharedSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client := kube.NewFakeClient()
	go client.Run(ctx.Done())
	signer, err := NewMITMSigner(ctx, client, MITMSignerOptions{
		Mode:       MITMSignModeSelfSign,
		Namespace:  "agentio-system",
		SecretName: "mitm",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitForMITM(t, func() bool { return signer.State().Get() != nil }, "SELF_SIGN signer state")
	secret, err := client.Kube().CoreV1().Secrets("agentio-system").Get(ctx, "mitm", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret.Data[mitmCACertKey]) == 0 || len(secret.Data[mitmCAKeyKey]) == 0 {
		t.Fatal("SELF_SIGN Secret does not contain CA material")
	}
}

func TestSelfSignDeletionFailsClosedBeforeRecreation(t *testing.T) {
	now := time.Now()
	secret := newMITMSecret(t, "agentio-system", "mitm", 24*time.Hour, now)
	ca, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], now)
	if err != nil {
		t.Fatal(err)
	}
	client := kube.NewFakeClient()
	signer := newInstalledMITMSigner(ca, secret.UID, time.Hour)
	signer.client = client
	signer.options.Mode = MITMSignModeSelfSign
	signer.options.Namespace = secret.Namespace
	signer.options.SecretName = secret.Name
	signer.options.RootLifetime = 24 * time.Hour
	signer.options.RootRenewBefore = time.Hour
	signer.reconcileNow = make(chan struct{}, 1)

	if err := signer.renewSelfSignedCA(context.Background()); err == nil {
		t.Fatal("renewSelfSignedCA succeeded after the Secret was deleted")
	}
	if signer.State().Get() != nil || signer.TrustBundles().Get() != nil {
		t.Fatal("deleted Secret left signer state or public trust available")
	}
	if _, err := signer.SignDNS(context.Background(), "api.example.com", time.Hour); err == nil {
		t.Fatal("deleted Secret left stale signing capability available")
	}
}

func newInstalledMITMSigner(ca pki.SigningCA, uid types.UID, expiryMargin time.Duration) *MITMSigner {
	return &MITMSigner{
		options:     MITMSignerOptions{LeafExpiryMargin: expiryMargin},
		caSingleton: krt.NewStatic(&caState{ca: ca, secretUID: uid}, true),
		signerState: krt.NewStatic(&SignerState{Revision: ca.Revision()}, true),
		trustBundle: krt.NewStatic(&TrustBundle{PEM: string(ca.BundlePEM()), Revision: ca.Revision()}, true),
	}
}

func newMITMSecret(t *testing.T, namespace, name string, lifetime time.Duration, now time.Time) *corev1.Secret {
	t.Helper()
	secret, err := casecret.New(namespace, name, mitmCAKeys, "Agentio MITM Root CA", lifetime, now)
	if err != nil {
		t.Fatal(err)
	}
	secret.UID = types.UID(name + "-uid")
	return secret
}

func waitForMITM(t *testing.T, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestMITMPublicTrustBundleLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	secret := newMITMSecret(t, "agentio-system", "mitm", 24*time.Hour, time.Now())
	client := kube.NewFakeClient(secret)
	go client.Run(ctx.Done())
	signer, err := NewMITMSigner(ctx, client, MITMSignerOptions{
		Mode: MITMSignModeSecret, Namespace: secret.Namespace, SecretName: secret.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertBundle := func(expected []byte) {
		t.Helper()
		waitForMITM(t, func() bool {
			bundle, state := signer.TrustBundles().Get(), signer.State().Get()
			return bundle != nil && state != nil && bundle.PEM == string(expected) && bundle.Revision == state.Revision
		}, "matching public trust and signing revision")
		if strings.Contains(signer.TrustBundles().Get().PEM, "PRIVATE KEY") {
			t.Fatal("exported signing key")
		}
	}
	assertBundle(secret.Data[mitmCACertKey])
	old := signer.TrustBundles().Get()
	staged := newMITMSecret(t, secret.Namespace, secret.Name, 24*time.Hour, time.Now())
	secret.Data[mitmCACertKey] = append(append([]byte(nil), secret.Data[mitmCACertKey]...), staged.Data[mitmCACertKey]...)
	if _, err := client.Kube().CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	assertBundle(secret.Data[mitmCACertKey])
	if old.PEM == signer.TrustBundles().Get().PEM {
		t.Fatal("staged roots did not change public trust")
	}
	if err := client.Kube().CoreV1().Secrets(secret.Namespace).Delete(ctx, secret.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForMITM(t, func() bool { return signer.State().Get() == nil && signer.TrustBundles().Get() == nil }, "CA deletion")
	staged.UID = "recreated-mitm"
	if _, err := client.Kube().CoreV1().Secrets(staged.Namespace).Create(ctx, staged, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	assertBundle(staged.Data[mitmCACertKey])
	staged.Data[mitmCACertKey] = []byte("invalid")
	if _, err := client.Kube().CoreV1().Secrets(staged.Namespace).Update(ctx, staged, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForMITM(t, func() bool { return signer.State().Get() == nil && signer.TrustBundles().Get() == nil }, "invalid CA removal")
}

func TestMITMPublicTrustRejectsStaleGeneration(t *testing.T) {
	old, err := pki.NewSelfSignedCA("old", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next, err := pki.NewSelfSignedCA("next", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signer := newInstalledMITMSigner(next, "next-uid", time.Hour)
	if signer.acceptAvailable(caState{ca: old, secretUID: "old-uid"}) {
		t.Fatal("accepted stale CA event")
	}
	if got := signer.TrustBundles().Get(); got == nil || got.PEM != string(next.BundlePEM()) {
		t.Fatal("stale CA replaced public trust")
	}
	signer.setUnavailable("next-uid")
	if signer.acceptAvailable(caState{ca: next, secretUID: "next-uid"}) || signer.TrustBundles().Get() != nil {
		t.Fatal("deleted CA reopened public trust")
	}
}

func TestMITMSecretInformerWaitsForReadPermission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		secret := newMITMSecret(t, "external-ca", "mitm", 24*time.Hour, time.Now())
		client := kube.NewFakeClient(secret)
		fake := client.Kube().(*kubefake.Clientset)
		var readAllowed atomic.Bool
		fake.PrependReactor("get", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
			if action.GetNamespace() != secret.Namespace || action.(kubetesting.GetAction).GetName() != secret.Name {
				return true, nil, errors.New("read escaped the named MITM Secret")
			}
			if !readAllowed.Load() {
				return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, secret.Name, nil)
			}
			return false, nil, nil
		})
		signer, err := NewMITMSigner(ctx, client, MITMSignerOptions{
			Mode: MITMSignModeSecret, Namespace: secret.Namespace, SecretName: secret.Name,
		})
		if err != nil {
			t.Fatal(err)
		}
		client.Run(ctx.Done())
		synctest.Wait()
		if signer.State().Get() != nil {
			t.Fatal("MITM signer became ready before read access was granted")
		}
		for _, action := range fake.Actions() {
			if action.GetResource().Resource == "secrets" && (action.GetVerb() == "list" || action.GetVerb() == "watch") {
				t.Fatal("MITM informer started before read access was granted")
			}
		}
		readAllowed.Store(true)
		// Advance the existing 30-second delayed permission retry without wall-clock waiting.
		time.Sleep(31 * time.Second)
		synctest.Wait()
		if signer.State().Get() == nil || signer.TrustBundles().Get() == nil {
			t.Fatal("MITM signer did not become ready after read access was granted")
		}
		for _, action := range fake.Actions() {
			if action.GetResource().Resource != "secrets" {
				continue
			}
			var selector string
			switch action.GetVerb() {
			case "list":
				selector = action.(kubetesting.ListAction).GetListRestrictions().Fields.String()
			case "watch":
				selector = action.(kubetesting.WatchAction).GetWatchRestrictions().Fields.String()
			default:
				continue
			}
			if action.GetNamespace() != secret.Namespace || selector != "metadata.name="+secret.Name {
				t.Fatalf("MITM informer escaped its fixed Secret: %v", action)
			}
		}
	})
}
