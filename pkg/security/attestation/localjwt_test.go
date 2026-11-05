// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

type localJWTFixture struct {
	auth     *LocalJWTAuthenticator
	key      *ecdsa.PrivateKey
	claims   localJWTClaims
	pods     krt.StaticCollection[*corev1.Pod]
	accounts krt.StaticCollection[*corev1.ServiceAccount]
	now      time.Time
	mu       sync.Mutex
	keys     jose.JSONWebKeySet
	fail     atomic.Bool
	requests atomic.Int64
	client   rest.Interface
}

func newLocalJWTFixture(t *testing.T) *localJWTFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &localJWTFixture{key: key, now: time.Now()}
	f.keys = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "first", Algorithm: "ES256", Use: "sig"}},
	}
	f.claims.Claims = jwt.Claims{
		Issuer:    "https://issuer.example",
		Subject:   "system:serviceaccount:demo:app",
		Audience:  jwt.Audience{"agentio-ca"},
		Expiry:    jwt.NewNumericDate(f.now.Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(f.now.Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(f.now.Add(-time.Minute)),
	}
	f.claims.Kubernetes.Namespace = "demo"
	f.claims.Kubernetes.Pod.Name = "app-1"
	f.claims.Kubernetes.Pod.UID = "pod-1"
	f.claims.Kubernetes.ServiceAccount.Name = "app"
	f.claims.Kubernetes.ServiceAccount.UID = "sa-1"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "app-1", UID: "pod-1"},
		Spec:       corev1.PodSpec{ServiceAccountName: "app"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "app", UID: "sa-1"}}
	f.pods = krt.NewMutableCollection(nil, []*corev1.Pod{pod}, krt.WithStop(t.Context().Done()))
	f.accounts = krt.NewMutableCollection(nil, []*corev1.ServiceAccount{account}, krt.WithStop(t.Context().Done()))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, err := w.Write(
				[]byte(`{"issuer":"https://issuer.example","jwks_uri":"https://unreachable.example/keys"}`),
			)
			if err != nil {
				t.Error(err)
			}
		case "/openid/v1/jwks":
			f.requests.Add(1)
			if f.fail.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if err := json.NewEncoder(w).Encode(f.keys); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected Kubernetes request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	f.client = client.CoreV1().RESTClient()
	f.auth, err = NewLocalJWTAuthenticator(
		t.Context(),
		f.client,
		f.pods.AsCollection(),
		f.accounts.AsCollection(),
		"agentio-ca",
	)
	if err != nil {
		t.Fatal(err)
	}
	f.auth.now = func() time.Time { return f.now }
	f.auth.nextRefresh = f.now.Add(localJWTRefreshInterval)
	f.auth.validUntil = f.now.Add(localJWTKeyLifetime)
	return f
}

func signLocalJWT(t *testing.T, key any, id string, c localJWTClaims) string {
	t.Helper()
	algorithm := jose.ES256
	switch key.(type) {
	case *rsa.PrivateKey:
		algorithm = jose.RS256
	case []byte:
		algorithm = jose.HS256
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: algorithm, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", id),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestLocalJWTAuthenticatesWithoutPerRequestKubernetesCalls(t *testing.T) {
	f := newLocalJWTFixture(t)
	token := signLocalJWT(t, f.key, "first", f.claims)
	for range 5 {
		peer, err := f.auth.Authenticate(bearerContext(token))
		if err != nil {
			t.Fatal(err)
		}
		want := model.PeerIdentity{
			AttestedBy: model.AttestationKubernetes,
			Kubernetes: model.KubernetesPeer{
				Namespace:      "demo",
				ServiceAccount: "app",
				WorkloadName:   "app-1",
				WorkloadUID:    "pod-1",
			},
		}
		if peer != want {
			t.Fatalf("identity = %+v, want %+v", peer, want)
		}
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1", got)
	}
}

func TestLocalJWTRejectsInvalidCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*localJWTClaims)
	}{
		{"issuer", func(c *localJWTClaims) { c.Issuer = "https://other.example" }},
		{"audience", func(c *localJWTClaims) { c.Audience = jwt.Audience{"other"} }},
		{"expired", func(c *localJWTClaims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Minute)) }},
		{"missing expiry", func(c *localJWTClaims) { c.Expiry = nil }},
		{"not before", func(c *localJWTClaims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour)) }},
		{"issued in future", func(c *localJWTClaims) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) }},
		{"subject", func(c *localJWTClaims) { c.Subject = "system:serviceaccount:demo:other" }},
		{"unbound", func(c *localJWTClaims) { c.Kubernetes.Pod.UID = "" }},
		{"missing SA UID", func(c *localJWTClaims) { c.Kubernetes.ServiceAccount.UID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalJWTFixture(t)
			tc.mutate(&f.claims)
			_, err := f.auth.Authenticate(bearerContext(signLocalJWT(t, f.key, "first", f.claims)))
			if err == nil || errors.Is(err, ErrUnsupportedCredentials) {
				t.Fatalf("recognized credential rejection = %v", err)
			}
		})
	}
	f := newLocalJWTFixture(t)
	for _, raw := range []string{"malformed", signLocalJWT(t, f.key, "first", f.claims) + "x", signLocalJWT(t, []byte(strings.Repeat("s", 32)), "first", f.claims)} {
		if _, err := f.auth.Authenticate(bearerContext(raw)); err == nil || errors.Is(err, ErrUnsupportedCredentials) {
			t.Fatalf("accepted invalid bearer: %v", err)
		}
	}
	if _, err := f.auth.Authenticate(t.Context()); !errors.Is(err, ErrUnsupportedCredentials) {
		t.Fatalf("missing bearer = %v", err)
	}
}

func TestLocalJWTRechecksResourceBindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*localJWTFixture)
	}{
		{"deleted Pod", func(f *localJWTFixture) { f.pods.DeleteObject("demo/app-1") }},
		{"recreated Pod", func(f *localJWTFixture) {
			p := (*f.pods.GetKey("demo/app-1")).DeepCopy()
			p.UID = "pod-2"
			f.pods.UpdateObject(p)
		}},
		{"terminating Pod", func(f *localJWTFixture) {
			p := (*f.pods.GetKey("demo/app-1")).DeepCopy()
			now := metav1.Now()
			p.DeletionTimestamp = &now
			f.pods.UpdateObject(p)
		}},
		{"completed Pod", func(f *localJWTFixture) {
			p := (*f.pods.GetKey("demo/app-1")).DeepCopy()
			p.Status.Phase = corev1.PodSucceeded
			f.pods.UpdateObject(p)
		}},
		{"failed Pod", func(f *localJWTFixture) {
			p := (*f.pods.GetKey("demo/app-1")).DeepCopy()
			p.Status.Phase = corev1.PodFailed
			f.pods.UpdateObject(p)
		}},
		{"Pod SA mismatch", func(f *localJWTFixture) {
			p := (*f.pods.GetKey("demo/app-1")).DeepCopy()
			p.Spec.ServiceAccountName = "other"
			f.pods.UpdateObject(p)
		}},
		{"deleted SA", func(f *localJWTFixture) { f.accounts.DeleteObject("demo/app") }},
		{"recreated SA", func(f *localJWTFixture) {
			s := (*f.accounts.GetKey("demo/app")).DeepCopy()
			s.UID = "sa-2"
			f.accounts.UpdateObject(s)
		}},
		{"terminating SA", func(f *localJWTFixture) {
			s := (*f.accounts.GetKey("demo/app")).DeepCopy()
			now := metav1.Now()
			s.DeletionTimestamp = &now
			f.accounts.UpdateObject(s)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalJWTFixture(t)
			ctx := bearerContext(signLocalJWT(t, f.key, "first", f.claims))
			if _, err := f.auth.Authenticate(ctx); err != nil {
				t.Fatal(err)
			}
			tc.mutate(f)
			if _, err := f.auth.Authenticate(ctx); err == nil {
				t.Fatal("stale resource binding accepted")
			}
		})
	}
}

type localJWTUnsynced struct{}

func (localJWTUnsynced) HasSynced() bool                      { return false }
func (localJWTUnsynced) WaitUntilSynced(<-chan struct{}) bool { return false }

func TestLocalJWTRejectsBeforeInitialSync(t *testing.T) {
	f := newLocalJWTFixture(t)
	f.auth.accounts = krt.NewStaticCollection[*corev1.ServiceAccount](localJWTUnsynced{}, nil)
	if _, err := f.auth.Authenticate(bearerContext(signLocalJWT(t, f.key, "first", f.claims))); err == nil {
		t.Fatal("unsynced identity collection accepted")
	}
}

func TestLocalJWTKeyRotationAndRefreshFailures(t *testing.T) {
	f := newLocalJWTFixture(t)
	old := signLocalJWT(t, f.key, "first", f.claims)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.keys = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "second", Algorithm: "RS256", Use: "sig"}},
	}
	f.mu.Unlock()
	rotated := signLocalJWT(t, key, "second", f.claims)
	f.now = f.now.Add(localJWTRefreshInterval)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := f.auth.Authenticate(bearerContext(rotated)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := f.requests.Load(); got != 2 {
		t.Fatalf("concurrent rotation fetched JWKS %d times, want 2 total", got)
	}
	for range 5 {
		if _, err := f.auth.Authenticate(bearerContext(old)); err == nil {
			t.Fatal("removed key accepted")
		}
	}
	if got := f.requests.Load(); got != 2 {
		t.Fatalf("failed verification bypassed refresh limit: %d", got)
	}
	f.fail.Store(true)
	f.now = f.now.Add(localJWTKeyLifetime)
	if _, err := f.auth.Authenticate(bearerContext(rotated)); err == nil {
		t.Fatal("expired signing key cache accepted during outage")
	}
	if got := f.requests.Load(); got != 3 {
		t.Fatalf("refresh requests = %d, want 3", got)
	}
	if _, err := f.auth.Authenticate(bearerContext(rotated)); err == nil {
		t.Fatal("failed refresh accepted")
	}
	if got := f.requests.Load(); got != 3 {
		t.Fatalf("failed refresh retried without interval: %d", got)
	}
	f.fail.Store(false)
	f.now = f.now.Add(localJWTRefreshInterval)
	if _, err := f.auth.Authenticate(bearerContext(rotated)); err != nil {
		t.Fatalf("refresh did not recover: %v", err)
	}
}

func TestLocalJWTInitializationFailsWithoutSigningKeys(t *testing.T) {
	f := newLocalJWTFixture(t)
	f.mu.Lock()
	f.keys = jose.JSONWebKeySet{}
	f.mu.Unlock()
	if _, err := NewLocalJWTAuthenticator(
		context.Background(),
		f.client,
		f.pods.AsCollection(),
		f.accounts.AsCollection(),
		"agentio-ca",
	); err == nil {
		t.Fatal("empty JWKS accepted at startup")
	}
	f.fail.Store(true)
	if _, err := NewLocalJWTAuthenticator(
		context.Background(),
		f.client,
		f.pods.AsCollection(),
		f.accounts.AsCollection(),
		"agentio-ca",
	); err == nil {
		t.Fatal("JWKS outage accepted at startup")
	}
}

func TestLocalJWTUsesUnexpiredKeysDuringAPIOutage(t *testing.T) {
	f := newLocalJWTFixture(t)
	token := signLocalJWT(t, f.key, "first", f.claims)
	f.fail.Store(true)
	f.now = f.now.Add(localJWTRefreshInterval)
	if _, err := f.auth.Authenticate(bearerContext(token)); err != nil {
		t.Fatalf("cached key unavailable during outage: %v", err)
	}
	unknown := signLocalJWT(t, f.key, "unknown", f.claims)
	if _, err := f.auth.Authenticate(bearerContext(unknown)); err == nil {
		t.Fatal("unknown signing key accepted")
	}
	if _, err := f.auth.Authenticate(bearerContext(token)); err != nil {
		t.Fatalf("failed refresh invalidated unexpired keys: %v", err)
	}
	if got := f.requests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want initial fetch and one failed refresh", got)
	}
}
