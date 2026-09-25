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

package extensionprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential/credentialtest"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/pkg/kube"
)

// TestEPEConfigWatchE2E exercises the production watcher against an explicitly
// selected API server, with real HTTP/mTLS providers. It creates and removes its
// own namespace. SecurityProfile/Envoy integration is intentionally separate.
func TestEPEConfigWatchE2E(t *testing.T) {
	path := os.Getenv("EPE_E2E_KUBECONFIG")
	if path == "" {
		t.Skip("set EPE_E2E_KUBECONFIG to run against a disposable Kubernetes cluster")
	}
	config, err := kube.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kube.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	t.Cleanup(cancel)
	ns, err := client.Kube().CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "epe-config-e2e-"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("testing API server %s in namespace %s", config.Host, ns.Name)
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := client.Kube().CoreV1().Namespaces().Delete(cleanupCtx, ns.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("delete test namespace: %v", err)
		}
	})

	// Wait for the actual rejection log before checking last-good retention.
	// Merely reading the old value immediately after Update would pass even if
	// the informer had not processed the invalid configuration yet.
	rejected := make(chan struct{}, 16)
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	slog.SetDefault(slog.New(logr.ToSlogHandler(funcr.New(func(_, line string) {
		if strings.Contains(line, "retain last-known-good configuration") && strings.Contains(line, ns.Name) {
			select {
			case rejected <- struct{}{}:
			default:
			}
		}
	}, funcr.Options{}))))

	environment := credentialtest.NewAPIKeyProvider(t, "environment")
	a := credentialtest.NewAPIKeyProvider(t, "A")
	b := credentialtest.NewAPIKeyProvider(t, "B")
	r := &Registry{}
	t.Cleanup(r.Close)
	callout := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/slow" {
			select {
			case <-time.After(100 * time.Millisecond):
			case <-req.Context().Done():
				return
			}
		}
		writeCalloutDecision(t, w, req, req.URL.Path)
	}))
	t.Cleanup(callout.Close)
	// Keep one document with both provider kinds; only the default changes in
	// the cache-reuse case below.
	base := fmt.Sprintf(`extensionProviders:
- name: a
  credentialProvider: {url: %q}
- name: b
  credentialProvider: {url: %q}
- name: scanner
  httpCallout: {url: %q, timeout: 2s}
defaultProviders: {credentialProvider: a}
`, a.Server.URL, b.Server.URL, callout.URL+"/one")
	calloutOnly := fmt.Sprintf(`extensionProviders:
- name: scanner
  httpCallout: {url: %q, timeout: 2s}
`, callout.URL+"/one")
	cms := client.Kube().CoreV1().ConfigMaps(ns.Name)
	cm, err := cms.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "epe"},
		Data:       map[string]string{"config": calloutOnly},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	t.Cleanup(stopWatch)
	reg := watch(t, client, ns.Name, []string{cm.Name}, r, watchCtx.Done(), defaultConfig(environment.Server.URL))
	if !reg.WaitUntilSynced(ctx.Done()) {
		t.Fatal("initial sync did not complete")
	}
	update := func(t *testing.T, raw string) {
		t.Helper()
		next := cm.DeepCopy()
		next.Data = map[string]string{"config": raw}
		cm, err = cms.Update(ctx, next, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	step := func(name string, fn func(*testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}
	checkToken := func(t *testing.T, provider, want string) {
		t.Helper()
		if got := token(t, r, ctx, provider); got != want {
			t.Fatalf("provider %q token = %q, want %q", provider, got, want)
		}
	}

	step("callout_only_inherits_environment", func(t *testing.T) {
		checkToken(t, "", "environment")
		checkCallout(t, r, ctx, "/one")
		before := liveProvider(r, "default")
		update(t, base)
		waitDefault(t, r, "a")
		checkToken(t, "default", "environment")
		if liveProvider(r, "default") != before || environment.Calls.Load() != 1 {
			t.Fatal("adding providers rebuilt the inherited provider/cache")
		}
	})
	step("initial_multiple_providers", func(t *testing.T) {
		checkToken(t, "", "A")
		checkToken(t, "a", "A")
		checkToken(t, "b", "B")
		checkToken(t, "default", "environment")
		checkCallout(t, r, ctx, "/one")
		if a.Calls.Load() != 1 || b.Calls.Load() != 1 {
			t.Fatal("named/default references did not share their provider cache")
		}
		var request map[string]any
		if err := json.Unmarshal(a.LastRequestBody.Load().([]byte), &request); err != nil {
			t.Fatal(err)
		}
		if request["credentialProviderName"] != "remote" || a.LastAuthorization.Load() != "Bearer access" {
			t.Fatalf("local provider selection changed remote name or authorization: %v", request)
		}
	})
	step("default_only_update_preserves_caches", func(t *testing.T) {
		beforeA, beforeB := liveProvider(r, "a"), liveProvider(r, "b")
		update(t, strings.Replace(base, "credentialProvider: a}", "credentialProvider: b}", 1))
		waitDefault(t, r, "b")
		checkToken(t, "", "B")
		checkToken(t, "a", "A")
		if liveProvider(r, "a") != beforeA || liveProvider(r, "b") != beforeB ||
			a.Calls.Load() != 1 || b.Calls.Load() != 1 {
			t.Fatal("changing only the default rebuilt an unchanged provider/cache")
		}
	})
	step("endpoint_update_preserves_other_providers", func(t *testing.T) {
		beforeA, beforeB := liveProvider(r, "a"), liveProvider(r, "b")
		base = strings.Replace(base, a.Server.URL, b.Server.URL, 1)
		base = strings.Replace(base, "/one", "/two", 1)
		update(t, base)
		waitProviderChange(t, r, "a", beforeA)
		checkToken(t, "", "B")
		checkCallout(t, r, ctx, "/two")
		if liveProvider(r, "b") != beforeB || b.Calls.Load() != 2 {
			t.Fatal("endpoint change reused the old cache or flushed another provider")
		}
	})
	step("credential_timeout_update_rebuilds_cache", func(t *testing.T) {
		before := liveProvider(r, "a")
		base = strings.Replace(
			base,
			"credentialProvider: {url:",
			"credentialProvider: {timeout: 3s, url:",
			1,
		)
		update(t, base)
		waitProviderChange(t, r, "a", before)
		hits := b.Calls.Load()
		checkToken(t, "a", "B")
		checkToken(t, "a", "B")
		if b.Calls.Load() != hits+1 {
			t.Fatal("provider update did not rebuild the cache with the global policy")
		}
	})
	step("callout_timeout_update", func(t *testing.T) {
		before := liveProvider(r, "scanner")
		update(t, strings.Replace(strings.Replace(base, "/two", "/slow", 1), "timeout: 2s", "timeout: 1ms", 1))
		waitProviderChange(t, r, "scanner", before)
		if _, err := httpcallout.NewHTTPClient(r).Call(ctx, "scanner", liveInvocation()); err == nil {
			t.Fatal("updated callout timeout was not enforced")
		}
		before = liveProvider(r, "scanner")
		update(t, base)
		waitProviderChange(t, r, "scanner", before)
		checkCallout(t, r, ctx, "/two")
	})
	step("invalid_config_retains_last_good", func(t *testing.T) {
		before := liveProvider(r, "a")
		for _, raw := range []string{
			"extensionProviders: [", "unknownField: true",
			strings.Replace(base, "timeout: 2s", "timeout: -1s", 1),
			strings.Replace(base, "name: b", "name: a", 1),
		} {
			update(t, raw)
			waitRejection(t, ctx, rejected)
			checkToken(t, "", "B")
			checkCallout(t, r, ctx, "/two")
			if liveProvider(r, "a") != before {
				t.Fatal("invalid config replaced the last-good provider")
			}
		}
	})
	step("explicit_bad_default_never_falls_back", func(t *testing.T) {
		for _, name := range []string{"missing", "scanner"} {
			update(t, strings.Replace(base, "credentialProvider: a}", "credentialProvider: "+name+"}", 1))
			waitDefault(t, r, name)
			if _, err := r.Fetch(ctx, liveCredentialRef("")); err == nil {
				t.Fatalf("unavailable/wrong-type default %q fell back", name)
			}
			checkToken(t, "default", "environment")
		}
	})
	step("provider_deletion_and_recreation", func(t *testing.T) {
		before := liveProvider(r, "a")
		update(t, "defaultProviders: {credentialProvider: a}")
		waitProviderChange(t, r, "a", before)
		if liveProvider(r, "a") != nil {
			t.Fatal("deleted provider is still installed")
		}
		if _, err := r.Fetch(ctx, liveCredentialRef("")); err == nil {
			t.Fatal("deleted configured default fell back")
		}
		if _, err := httpcallout.NewHTTPClient(r).Call(ctx, "scanner", liveInvocation()); err == nil {
			t.Fatal("deleted callout is still usable")
		}
		update(t, base)
		waitProviderChange(t, r, "a", nil)
		checkToken(t, "", "B")
		checkCallout(t, r, ctx, "/two")
	})

	step("mtls_and_secret_watch", func(t *testing.T) {
		liveSecretLifecycle(t, ctx, client, ns.Name, r, update, rejected, b)
	})
	step("configmap_deletion_and_recreation", func(t *testing.T) {
		if err := cms.Delete(ctx, cm.Name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		waitDefault(t, r, "default")
		checkToken(t, "", "environment")
		if liveProvider(r, "a") != nil || liveProvider(r, "scanner") != nil {
			t.Fatal("ConfigMap deletion retained dynamic providers")
		}
		cm, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "epe"},
			Data:       map[string]string{"config": base},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		waitDefault(t, r, "a")
		checkToken(t, "", "B")
		checkCallout(t, r, ctx, "/two")
		update(t, strings.Replace(base, "defaultProviders: {credentialProvider: a}", "", 1))
		waitDefault(t, r, "default")
		checkToken(t, "", "environment")
		checkToken(t, "a", "B")
	})
}

func liveCredentialRef(provider string) tokentransform.Ref {
	return tokentransform.Ref{
		Provider:        provider,
		Name:            "remote",
		Kind:            tokentransform.CredentialKindToken,
		SandboxClientID: "sandbox",
		AccessToken:     "access",
	}
}

func liveInvocation() httpcallout.Invocation {
	return httpcallout.Invocation{
		Version: "0.1",
		Phase:   httpcallout.PhaseRequest,
		Request: &httpcallout.HTTPRequest{Method: "GET", Path: "/resource"},
	}
}

func writeCalloutDecision(t *testing.T, w http.ResponseWriter, req *http.Request, value string) {
	t.Helper()
	var invocation httpcallout.Invocation
	if err := json.NewDecoder(req.Body).Decode(&invocation); err != nil || invocation.Validate() != nil {
		t.Error("invalid callout invocation on the wire")
		http.Error(w, "invalid invocation", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).
		Encode(map[string]any{"version": "0.1", "request": map[string]any{"body": value}}); err != nil {
		t.Error(err)
	}
}

func checkCallout(t *testing.T, r *Registry, ctx context.Context, want string) {
	t.Helper()
	d, err := httpcallout.NewHTTPClient(r).Call(ctx, "scanner", liveInvocation())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(httpcallout.PhaseRequest); err != nil {
		t.Fatal(err)
	}
	if d.Request == nil || d.Request.Body == nil || *d.Request.Body != want {
		t.Fatalf("callout = %+v, want body %q", d, want)
	}
}

func liveProvider(r *Registry, name string) *instance {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current.providers[name]
}

func waitProviderChange(t *testing.T, r *Registry, name string, previous *instance) {
	t.Helper()
	testsupport.Eventually(t, 10*time.Second, func() error {
		if liveProvider(r, name) == previous {
			return fmt.Errorf("provider %q has not changed", name)
		}
		return nil
	})
}

func waitDefault(t *testing.T, r *Registry, name string) {
	t.Helper()
	testsupport.Eventually(t, 10*time.Second, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.current.defaultCredential != name {
			return fmt.Errorf("default = %q, want %q", r.current.defaultCredential, name)
		}
		return nil
	})
}

func waitRejection(t *testing.T, ctx context.Context, rejected <-chan struct{}) {
	t.Helper()
	select {
	case <-rejected:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(10 * time.Second):
		t.Fatal("watcher did not report invalid configuration")
	}
}

func liveSecretLifecycle(t *testing.T, ctx context.Context, client kube.Client, namespace string,
	r *Registry, update func(*testing.T, string), rejected <-chan struct{}, stable *credentialtest.FakeProvider,
) {
	ca := certstest.New(t)
	const serverID = "spiffe://test/ns/security/sa/provider"
	serverCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 2, URIs: []string{serverID}})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		serial := req.TLS.PeerCertificates[0].SerialNumber.String()
		if req.URL.Path == "/callout" {
			writeCalloutDecision(t, w, req, serial)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"apiKey": serial}); err != nil {
			t.Error(err)
		}
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.Pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()
	secrets := client.Kube().CoreV1().Secrets(namespace)
	material := func(serial int64) map[string][]byte {
		certPEM, keyPEM := certstest.PEM(t, ca.Loopback(t, serial, x509.ExtKeyUsageClientAuth))
		return map[string][]byte{"ca.crt": ca.CAPEM(), "tls.crt": certPEM, "tls.key": keyPEM}
	}
	putSecret := func(name string, data map[string][]byte) {
		t.Helper()
		sec, err := secrets.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = secrets.Create(
				ctx,
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}, Data: data},
				metav1.CreateOptions{},
			)
		} else if err == nil {
			sec.Data = data
			_, err = secrets.Update(ctx, sec, metav1.UpdateOptions{})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	raw := fmt.Sprintf(`extensionProviders:
- name: a
  credentialProvider:
    url: %q
    tls:
      peerSpiffeIDs: [%q]
      caSecretRef: {name: material}
      clientCertificateSecretRef: {name: material}
- name: scanner
  httpCallout:
    url: %q
    tls:
      peerSpiffeIDs: [%q]
      caSecretRef: {name: material}
      clientCertificateSecretRef: {name: material}
- name: b
  credentialProvider: {url: %q}
defaultProviders: {credentialProvider: a}
`, server.URL+"/credential", serverID, server.URL+"/callout", serverID, stable.Server.URL)
	before := liveProvider(r, "a")
	update(t, raw)
	waitProviderChange(t, r, "a", before)
	check := func(want string) {
		t.Helper()
		if got := token(t, r, ctx, ""); got != want {
			t.Fatalf("mTLS credential = %q, want client serial %q", got, want)
		}
		checkCallout(t, r, ctx, want)
	}
	unavailable := func() {
		t.Helper()
		testsupport.Eventually(t, 10*time.Second, func() error {
			if _, err := r.Fetch(ctx, liveCredentialRef("")); err == nil {
				return fmt.Errorf("credential still usable with revoked/missing TLS material")
			}
			if _, err := httpcallout.NewHTTPClient(r).Call(ctx, "scanner", liveInvocation()); err == nil {
				return fmt.Errorf("callout still usable with revoked/missing TLS material")
			}
			return nil
		})
	}
	unavailable()
	before = liveProvider(r, "a")
	putSecret("material", material(3))
	waitProviderChange(t, r, "a", before)
	check("3") // Warm both the credential cache and TLS keep-alive connection.
	if token(t, r, ctx, "b") != "B" {
		t.Fatal("unrelated credential provider is unavailable")
	}
	stableInstance, stableHits := liveProvider(r, "b"), stable.Calls.Load()
	before = liveProvider(r, "a")
	putSecret("material", material(4))
	waitProviderChange(t, r, "a", before)
	check("4")
	if token(t, r, ctx, "b") != "B" || liveProvider(r, "b") != stableInstance || stable.Calls.Load() != stableHits {
		t.Fatal("Secret rotation flushed an unrelated provider/cache")
	}
	t.Log("client certificate rotation refreshed both provider types and preserved unrelated cache")

	// Invalid authoring tries to move the dependencies. The retained version
	// must continue watching material, including revocation and recreation.
	update(t, strings.ReplaceAll(raw, "name: material", "name: unaccepted")+"unknownField: true\n")
	waitRejection(t, ctx, rejected)
	if err := secrets.Delete(ctx, "material", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	unavailable()
	before = liveProvider(r, "a")
	putSecret("material", material(5))
	waitProviderChange(t, r, "a", before)
	check("5")
	t.Log("invalid ConfigMap retained live Secret dependencies; deletion failed closed and recreation recovered")

	for _, bad := range []map[string][]byte{
		{"ca.crt": []byte("not a certificate")},
		{"ca.crt": ca.CAPEM(), "tls.crt": []byte("broken"), "tls.key": []byte("broken")},
		func() map[string][]byte {
			data := material(6)
			data["ca.crt"] = certstest.New(t).CAPEM()
			return data
		}(),
	} {
		putSecret("material", bad)
		unavailable()
		before = liveProvider(r, "a")
		putSecret("material", material(7))
		waitProviderChange(t, r, "a", before)
		check("7")
	}
	t.Log("invalid CA, invalid key pair and valid-but-untrusted CA all failed closed and recovered")

	update(t, strings.ReplaceAll(raw, serverID, "spiffe://test/ns/security/sa/wrong"))
	unavailable()
	before = liveProvider(r, "a")
	update(t, raw)
	waitProviderChange(t, r, "a", before)
	check("7")
	t.Log("SPIFFE allow-list changes took effect without restarting the watcher")

	update(t, strings.ReplaceAll(raw, "name: material", "name: replacement"))
	unavailable()
	before = liveProvider(r, "a")
	putSecret("replacement", material(8))
	waitProviderChange(t, r, "a", before)
	check("8")
	t.Log("switching to a missing Secret failed closed; creating it recovered without a ConfigMap change")
}
