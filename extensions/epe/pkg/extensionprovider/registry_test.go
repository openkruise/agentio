// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential/credentialtest"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/kube"
)

func decodeConfig(raw string) (*configv1.EPEConfig, error) {
	cfg, err := config.Apply(raw, &configv1.EPEConfig{})
	if err != nil {
		return nil, err
	}
	return cfg, Validate(cfg)
}

func apply(t testing.TB, r *Registry, raw string) {
	t.Helper()
	cfg, err := decodeConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
}
func credentialConfig(a, b string) string {
	return fmt.Sprintf(`extensionProviders:
- name: a
  credentialProvider: {url: %q}
- name: b
  credentialProvider: {url: %q}
defaultProviders: {credentialProvider: a}
`, a, b)
}

// token fetches a credential through the registry.
func token(t testing.TB, r tokentransform.CredentialSource, ctx context.Context, provider string) string {
	t.Helper()
	c, err := r.Fetch(
		ctx,
		tokentransform.Ref{
			Kind:            tokentransform.CredentialKindToken,
			Provider:        provider,
			Name:            "remote",
			SandboxClientID: "sandbox",
			AccessToken:     "access",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return c.Token
}
func TestRegistryRoutesAndIsolatesRevisions(t *testing.T) {
	var callsA, callsB atomic.Int32
	server := func(value string, calls *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			var req struct {
				Name string `json:"credentialProviderName"`
				Kind string `json:"credentialType"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.Name != "remote" || r.Header.Get("Authorization") != "Bearer access" {
				t.Errorf("wrong remote name/auth: %+v", req)
			}
			if req.Kind == "stsToken" {
				sts := map[string]any{
					"accessKeyId":     value,
					"accessKeySecret": "secret",
					"securityToken":   "session",
					"expiration":      time.Now().Add(time.Hour).Format(time.RFC3339),
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"stsToken": sts}); err != nil {
					t.Error(err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"apiKey": value}); err != nil {
				t.Error(err)
			}
		}))
	}
	a, b := server("A", &callsA), server("B", &callsB)
	defer a.Close()
	defer b.Close()
	r := &Registry{}
	defer r.Close()
	apply(t, r, credentialConfig(a.URL, b.URL))
	if token(t, r, t.Context(), "a") != "A" ||
		token(t, r, t.Context(), "b") != "B" ||
		token(t, r, t.Context(), "") != "A" {
		t.Fatal("wrong provider")
	}
	if callsA.Load() != 1 || callsB.Load() != 1 {
		t.Fatal("provider caches not reused")
	}
	apply(t, r, credentialConfig(b.URL, b.URL))
	if token(t, r, t.Context(), "a") != "B" {
		t.Fatal("updated provider used the old revision")
	}
	if token(t, r, t.Context(), "b") != "B" || callsB.Load() != 2 {
		t.Fatal("unchanged provider lost cache")
	}
	sts, err := r.Fetch(
		t.Context(),
		tokentransform.Ref{
			Kind:            tokentransform.CredentialKindSTS,
			Provider:        "a",
			Name:            "remote",
			SandboxClientID: "sandbox",
			AccessToken:     "access",
		},
	)
	if err != nil || sts.AccessKeyID != "B" {
		t.Fatalf("STS: %+v %v", sts, err)
	}
	if err := r.Apply(&configv1.EPEConfig{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Fetch(
		t.Context(),
		tokentransform.Ref{Kind: tokentransform.CredentialKindToken, Provider: "a", Name: "remote"},
	); err == nil {
		t.Fatal("deleted provider was served")
	}
}

func TestRegistryCredentialFetchAcrossUpdates(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	var newCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		value := "new"
		if req.URL.Path == "/old" {
			close(started)
			select {
			case <-finish:
			case <-req.Context().Done():
				return
			}
			value = "old"
		} else {
			newCalls.Add(1)
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"apiKey": value}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	finishRequest := sync.OnceFunc(func() { close(finish) })
	t.Cleanup(finishRequest)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	r := &Registry{}
	t.Cleanup(r.Close)
	configure := func(path string) {
		apply(t, r, fmt.Sprintf(`extensionProviders:
- name: a
  credentialProvider: {url: %q, timeout: 5s}
`, server.URL+path))
	}
	configure("/old")
	type result struct {
		credential tokentransform.Credential
		err        error
	}
	done := make(chan result, 1)
	go func() {
		credential, err := r.Fetch(ctx, tokentransform.Ref{
			Kind:            tokentransform.CredentialKindToken,
			Provider:        "a",
			Name:            "remote",
			SandboxClientID: "sandbox",
			AccessToken:     "access",
		})
		done <- result{credential: credential, err: err}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("old provider request did not start")
	}
	configure("/new")
	if got := token(t, r, ctx, "a"); got != "new" {
		t.Fatalf("updated provider returned %q", got)
	}
	finishRequest()
	select {
	case got := <-done:
		if got.err != nil || got.credential.Token != "old" {
			t.Fatalf("in-flight request changed across update: %+v, %v", got.credential, got.err)
		}
	case <-ctx.Done():
		t.Fatal("old provider request did not finish")
	}
	if got := token(t, r, ctx, "a"); got != "new" || newCalls.Load() != 1 {
		t.Fatalf("old response changed the new cache: token=%q, calls=%d", got, newCalls.Load())
	}
}

func TestDecodeRejectsInvalidRegistry(t *testing.T) {
	for _, raw := range []string{
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {caSecretRef: {name: ca}, caCertificateFile: /ca}}}]",
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {caSecretRef: {name: ca}, caConfigMapRef: {name: ca}}}}]",
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {caConfigMapRef: {name: ca}, caCertificateFile: /ca}}}]",
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {caCertificateFile: ''}}}]",
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {caConfigMapRef: {}}}}]",
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {clientCertificateSecretRef: {name: client}, clientCertificateFiles: {certificateFile: /cert, privateKeyFile: /key}}}}]",
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {clientCertificateFiles: {}}}}]",
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {clientCertificateFiles: {certificateFile: /cert}}}}]",
		"extensionProviders: [{name: a, httpCallout: {url: https://example, tls: {insecureSkipVerify: true, peerSpiffeIDs: [spiffe://domain/server]}}}]",
		"unknown: true",
		"extensionProviders: [{name: a}, {name: a}]",
		"extensionProviders: [{name: a, httpCallout: {url: http://example}, credentialProvider: {url: http://example}}]",
		"extensionProviders: [{name: a, httpCallout: {url: http://user:pass@example}}]",
		"extensionProviders: [{name: a, httpCallout: {url: http://example, timeout: -1s}}]",
		"extensionProviders: [{name: a, credentialProvider: {url: http://example, cache: {}}}]",
		"extensionProviders: [{name: a, credentialProvider: {url: http://example, tls: {}}}]",
		"extensionProviders: [{name: a, credentialProvider: {url: https://example, tls: {caSecretRef: {}}}}]",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := decodeConfig(raw); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestRegistryGlobalCacheSettings(t *testing.T) {
	for _, tt := range []struct {
		name     string
		kind     tokentransform.CredentialKind
		ttl      time.Duration
		response string
		calls    int64
	}{
		{"API key capacity", tokentransform.CredentialKindToken, time.Minute, `{"apiKey":"key"}`, 3},
		{"API key without fallback", tokentransform.CredentialKindToken, 0, `{"apiKey":"key"}`, 4},
		{"API key with remote TTL", tokentransform.CredentialKindToken, 0, `{"apiKey":"key","cacheExpiresInSeconds":60}`, 3},
		{"STS capacity", tokentransform.CredentialKindSTS, 0, fmt.Sprintf(
			`{"stsToken":{"accessKeyId":"ak","accessKeySecret":"sk","securityToken":"token","expiration":%q}}`,
			time.Now().Add(time.Hour).Format(time.RFC3339)), 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testsupport.SetForTest(t, &cacheTTL, tt.ttl)
			testsupport.SetForTest(t, &cacheMaxSize, 1)
			testsupport.SetForTest(t, &stsCacheMaxSize, 1)
			remote := credentialtest.NewRawProvider(t, tt.response)
			r := &Registry{}
			t.Cleanup(r.Close)
			apply(
				t,
				r,
				fmt.Sprintf("extensionProviders: [{name: a, credentialProvider: {url: %q}}]", remote.Server.URL),
			)
			for _, provider := range []string{"a", "b"} {
				if provider == "b" {
					// Providers added through a later configuration use the same
					// global policy, but must start with an independent cache.
					apply(t, r, credentialConfig(remote.Server.URL, remote.Server.URL))
				}
				before := remote.Calls.Load()
				for _, resource := range []string{"one", "one", "two", "one"} {
					_, err := r.Fetch(t.Context(), tokentransform.Ref{
						Provider:        provider,
						Kind:            tt.kind,
						Name:            "remote",
						SandboxClientID: resource,
						AccessToken:     "access",
					})
					if err != nil {
						t.Fatal(err)
					}
				}
				if got := remote.Calls.Load() - before; got != tt.calls {
					t.Fatalf("provider %s made %d remote calls, want %d", provider, got, tt.calls)
				}
			}
		})
	}
}

func TestWatchConfigMapCAForServerTLS(t *testing.T) {
	ca := certstest.New(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("server-only TLS presented a client certificate")
		}
		if _, err := w.Write([]byte(`{"apiKey":"server-tls"}`)); err != nil {
			t.Error(err)
		}
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.Loopback(t, 8001, x509.ExtKeyUsageServerAuth)},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "epe", Namespace: "system"},
		Data: map[string]string{"config": fmt.Sprintf(`extensionProviders:
- name: corporate
  credentialProvider:
    url: %q
    tls:
      caConfigMapRef: {name: provider-ca, namespace: other}
defaultProviders: {credentialProvider: corporate}
`, server.URL)},
	}
	client := kube.NewFakeClient(cm)
	registry := &Registry{}
	t.Cleanup(registry.Close)
	reg := watch(t, client, "system", []string{"epe"}, registry, t.Context().Done())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if !reg.WaitUntilSynced(ctx.Done()) {
		t.Fatal("missing CA must not block initial sync")
	}
	if _, err := registry.Fetch(t.Context(), liveCredentialRef("")); err == nil {
		t.Fatal("missing CA ConfigMap allowed a call")
	}
	trust := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "provider-ca", Namespace: "other"},
		Data:       map[string]string{"ca.crt": string(ca.CAPEM())},
	}
	maps := client.Kube().CoreV1().ConfigMaps("other")
	if _, err := maps.Create(t.Context(), trust, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	wait := func(available bool) {
		t.Helper()
		testsupport.Eventually(t, 5*time.Second, func() error {
			credential, err := registry.Fetch(t.Context(), liveCredentialRef(""))
			if available {
				if err != nil {
					return fmt.Errorf("server TLS call failed: %w", err)
				}
				if credential.Token != "server-tls" {
					return fmt.Errorf("unexpected credential from TLS server")
				}
			} else if err == nil {
				return fmt.Errorf("unavailable CA still serves cached credentials")
			}
			return nil
		})
	}
	wait(true)
	for _, data := range []map[string]string{
		{"unrecognized-key": string(ca.CAPEM())},
		{"ca.crt": "invalid PEM"},
	} {
		trust = trust.DeepCopy()
		trust.Data = data
		if _, err := maps.Update(t.Context(), trust, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		wait(false)
		trust = trust.DeepCopy()
		trust.Data = map[string]string{"ca.crt": string(ca.CAPEM())}
		if _, err := maps.Update(t.Context(), trust, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		wait(true)
	}
	if err := maps.Delete(t.Context(), trust.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	wait(false)
}

func TestRegistryDefaultIsAnOrdinaryProvider(t *testing.T) {
	r := &Registry{}
	defer r.Close()
	cfg := defaultConfig("https://credentials.example")
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	first := r.current.providers["default"]
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if r.current.providers["default"] != first {
		t.Fatal("unchanged default was rebuilt")
	}
	if err := r.Apply(&configv1.EPEConfig{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.current.providers) != 0 || r.current.defaultCredential != "" {
		t.Fatal("empty configuration retained a special default")
	}
	r.Close()
	if err := r.Apply(cfg, nil); err == nil {
		t.Fatal("closed registry reopened")
	}
}

func TestRegistryHTTPTimeoutAndType(t *testing.T) {
	// The protocol client enforces the response limit, not the registry's transport.
	t.Setenv("HTTP_CALLOUT_MAX_RESPONSE_BYTES", "1")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
				return
			}
		}
		if _, err := w.Write([]byte("plain HTTP response")); err != nil {
			t.Error(err)
		}
	}))
	defer s.Close()
	r := &Registry{}
	defer r.Close()
	apply(t, r, fmt.Sprintf(`extensionProviders:
- name: ok
  httpCallout: {url: %q}
- name: slow
  httpCallout: {url: %q, timeout: 10ms}
- name: wrong
  credentialProvider: {url: %q}
`, s.URL, s.URL+"/slow", s.URL))
	for _, name := range []string{"ok", "slow", "wrong", "missing"} {
		resp, err := r.Do(t.Context(), name, http.MethodGet, nil, nil)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			if closeErr := resp.Body.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
		if (err == nil) != (name == "ok") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRegistryHTTPResponseAcrossUpdates(t *testing.T) {
	finish := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/new" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, err := io.ReadAll(req.Body)
		if err != nil || string(body) != "event" || req.Method != http.MethodPut ||
			req.Header.Get("Content-Type") != "text/plain" || req.URL.RawQuery != "kind=audit" {
			t.Errorf("unexpected HTTP request: method=%s url=%s headers=%v body=%q error=%v",
				req.Method, req.URL, req.Header, body, err)
		}
		w.Header().Set("X-Receipt", "accepted")
		w.WriteHeader(http.StatusAccepted)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		select {
		case <-finish:
		case <-req.Context().Done():
			return
		}
		if _, err := io.WriteString(w, "receipt"); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(s.Close)
	finishResponse := sync.OnceFunc(func() { close(finish) })
	t.Cleanup(finishResponse)
	r := &Registry{}
	t.Cleanup(r.Close)
	configure := func(path string) {
		apply(t, r, fmt.Sprintf(`extensionProviders:
- name: http
  httpCallout: {url: %q, timeout: 5s}
`, s.URL+path))
	}
	configure("/old?kind=audit")
	resp, err := r.Do(t.Context(), "http", http.MethodPut,
		http.Header{"Content-Type": {"text/plain"}}, strings.NewReader("event"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if resp.StatusCode != http.StatusAccepted || resp.Header.Get("X-Receipt") != "accepted" {
		t.Fatalf("unexpected HTTP response: %s, %v", resp.Status, resp.Header)
	}
	configure("/new")
	next, err := r.Do(t.Context(), "http", http.MethodGet, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if next.StatusCode != http.StatusNoContent {
		t.Fatalf("new provider returned %s", next.Status)
	}
	r.Close()
	finishResponse()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "receipt" {
		t.Fatalf("in-flight response lost its original provider: %q, %v", body, err)
	}
}

func TestWatchConfigMapAndSecretLifecycle(t *testing.T) {
	ca := certstest.New(t)
	const serverID = "spiffe://test/ns/security/sa/provider"
	serverCert, _ := ca.Issue(t, certstest.LeafSpec{Serial: 2, URIs: []string{serverID}})
	clientCert := ca.Loopback(t, 3, x509.ExtKeyUsageClientAuth)
	certPEM, keyPEM := certstest.PEM(t, clientCert)
	var hits atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if _, err := w.Write([]byte(`{"apiKey":"watched"}`)); err != nil {
			t.Error(err)
		}
	}))
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.Pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	s.StartTLS()
	defer s.Close()
	raw := fmt.Sprintf(`extensionProviders:
- name: a
  credentialProvider:
    url: %q
    tls:
      peerSpiffeIDs: [%q]
      caSecretRef: {name: material}
      clientCertificateSecretRef: {name: material}
`, s.URL, serverID)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "epe", Namespace: "system"},
		Data:       map[string]string{"config": raw},
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "material", Namespace: "system"},
		Data:       map[string][]byte{"ca.crt": ca.CAPEM(), "tls.crt": certPEM, "tls.key": keyPEM},
	}
	c := kube.NewFakeClient(cm, sec)
	r := &Registry{}
	reg := watch(t, c, "system", []string{"epe"}, r, t.Context().Done())
	if !reg.WaitUntilSynced(t.Context().Done()) {
		t.Fatal("initial sync did not complete")
	}
	if token(t, r, t.Context(), "a") != "watched" {
		t.Fatal("wrong token")
	}
	update := func(raw string) {
		t.Helper()
		obj := cm.DeepCopy()
		obj.Data["config"] = raw
		if _, err := c.Kube().
			CoreV1().
			ConfigMaps("system").
			Update(t.Context(), obj, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// A malformed update keeps LKG. Secret deletion must still invalidate its cache.
	update("extensionProviders: broken")
	if err := c.Kube().CoreV1().Secrets("system").Delete(t.Context(), "material", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	unavailable := func() error {
		_, err := r.Fetch(
			t.Context(),
			tokentransform.Ref{Provider: "a", Name: "remote", Kind: tokentransform.CredentialKindToken},
		)
		if err == nil {
			return fmt.Errorf("provider still available")
		}
		return nil
	}
	testsupport.Eventually(t, 5*time.Second, unavailable)
	if _, err := c.Kube().CoreV1().Secrets("system").Create(t.Context(), sec, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		_, err := r.Fetch(
			t.Context(),
			tokentransform.Ref{Provider: "a", Name: "remote", Kind: tokentransform.CredentialKindToken},
		)
		return err
	})
	// Secret data rotation invalidates the old transport and cache, including
	// removal of the peer's trust root on an established keep-alive connection.
	bad := sec.DeepCopy()
	bad.Data["ca.crt"] = certstest.New(t).CAPEM()
	if _, err := c.Kube().CoreV1().Secrets("system").Update(t.Context(), bad, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, unavailable)
	update("extensionProviders: []")
	testsupport.Eventually(t, 5*time.Second, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.current.providers) != 0 {
			return fmt.Errorf("provider not deleted")
		}
		return nil
	})
	update(raw)
	testsupport.Eventually(t, 5*time.Second, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.current.providers["a"] == nil {
			return fmt.Errorf("provider not recreated")
		}
		return nil
	})
	if err := c.Kube().CoreV1().ConfigMaps("system").Delete(t.Context(), "epe", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.current.providers) != 0 {
			return fmt.Errorf("ConfigMap deletion kept providers")
		}
		return nil
	})
}

func TestRegistryConcurrentReconfiguration(t *testing.T) {
	s := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write([]byte(`{"apiKey":"token"}`)); err != nil {
				t.Error(err)
			}
		}),
	)
	defer s.Close()
	cfg, err := decodeConfig(credentialConfig(s.URL, s.URL))
	if err != nil {
		t.Fatal(err)
	}
	r := &Registry{}
	defer r.Close()
	if err := r.Apply(cfg, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 30 {
				token(t, r, t.Context(), "a")
			}
		})
	}
	for i := range 30 {
		changed, err := decodeConfig(credentialConfig(s.URL+fmt.Sprintf("/%d", i), s.URL))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Apply(changed, nil); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestRegistryOptionalMaterialDoesNotDisableVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"apiKey":"tls-token"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	for _, tt := range []struct {
		name     string
		optional bool
		insecure bool
		success  bool
	}{
		{name: "optional material with explicit insecure TLS", optional: true, insecure: true, success: true},
		{name: "optional material still verifies the server", optional: true},
		{name: "required material stays required", insecure: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig(server.URL)
			cfg.ExtensionProviders[0].GetCredentialProvider().Tls = &configv1.ClientTLS{
				CaSource: &configv1.ClientTLS_CaSecretRef{
					CaSecretRef: &configv1.TargetReference{Name: "missing"},
				},
				ClientCertificateSource: &configv1.ClientTLS_ClientCertificateSecretRef{
					ClientCertificateSecretRef: &configv1.TargetReference{Name: "missing"},
				},
				Optional:           tt.optional,
				InsecureSkipVerify: tt.insecure,
			}
			registry := &Registry{}
			defer registry.Close()
			if err := registry.Apply(cfg, nil); err != nil {
				t.Fatal(err)
			}
			credential, err := registry.Fetch(t.Context(), liveCredentialRef(""))
			if tt.success {
				if err != nil || credential.Token != "tls-token" {
					t.Fatalf("fetch: %v, %v", credential, err)
				}
			} else if err == nil {
				t.Fatal("TLS configuration unexpectedly allowed the call")
			}
		})
	}
}
