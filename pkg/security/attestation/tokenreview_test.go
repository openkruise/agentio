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

package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/flowcontrol"

	"google.golang.org/grpc/metadata"

	"github.com/openkruise/agentio/pkg/model"
)

// countingReviewer builds a TokenReviewer over a fake client that records how many
// TokenReviews reached the API server and answers them from a script.
type countingReviewer struct {
	reviewer *TokenReviewer

	mu    sync.Mutex
	calls int
}

func newCountingReviewer(
	t *testing.T,
	authenticate func(token string) authenticationv1.TokenReviewStatus,
) *countingReviewer {
	t.Helper()
	counter := &countingReviewer{}
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review, ok := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		if !ok {
			return false, nil, nil
		}
		counter.mu.Lock()
		counter.calls++
		counter.mu.Unlock()
		return true, &authenticationv1.TokenReview{Status: authenticate(review.Spec.Token)}, nil
	})
	reviewer, err := NewTokenReviewer(client, []string{"agentio-ca"})
	if err != nil {
		t.Fatal(err)
	}
	counter.reviewer = reviewer
	return counter
}

func (c *countingReviewer) reviews() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func bearerContext(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

// Synthetic JWT payloads are only used with fake TokenReview responses.
func tokenWithClaims(claims string) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".synthetic"
}

func expiringToken(subject string, expiry time.Time) string {
	return tokenWithClaims(fmt.Sprintf(`{"sub":%q,"exp":%d}`, subject, expiry.Unix()))
}

func authenticatedAs(username string) authenticationv1.TokenReviewStatus {
	return authenticationv1.TokenReviewStatus{
		Authenticated: true,
		User: authenticationv1.UserInfo{
			Username: username,
			Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			Extra: map[string]authenticationv1.ExtraValue{
				podNameExtra: {"client-pod"},
				podUIDExtra:  {"pod-uid"},
			},
		},
	}
}

func TestAuthenticateMissingBearerIsUnsupported(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		t.Fatal("TokenReview called without a Kubernetes Bearer credential")
		return authenticationv1.TokenReviewStatus{}
	})

	_, err := counter.reviewer.Authenticate(context.Background())
	if !errors.Is(err, ErrUnsupportedCredentials) {
		t.Fatalf("Authenticate() error = %v, want ErrUnsupportedCredentials", err)
	}
	if got := counter.reviews(); got != 0 {
		t.Fatalf("TokenReviews = %d, want 0", got)
	}
}

func TestAuthenticateRejectedBearerIsHardFailure(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticationv1.TokenReviewStatus{Authenticated: false, Error: "rejected"}
	})

	_, err := counter.reviewer.Authenticate(bearerContext("not-a-kubernetes-token"))
	if err == nil {
		t.Fatal("Authenticate() accepted a rejected Kubernetes Bearer credential")
	}
	if errors.Is(err, ErrUnsupportedCredentials) {
		t.Fatalf("Authenticate() error = %v, want a hard rejection", err)
	}
	if errors.Is(err, ErrTokenReviewUnavailable) {
		t.Fatalf("rejected token classified as unavailable: %v", err)
	}
	if got := counter.reviews(); got != 1 {
		t.Fatalf("TokenReviews = %d, want 1", got)
	}
}

func TestTokenReviewCancelsNetworkAndDoesNotCacheFailure(t *testing.T) {
	for _, tc := range []struct {
		name          string
		reviewTimeout time.Duration
		callerTimeout time.Duration
		cancelOnStart bool
		want          error
	}{
		{name: "review timeout", reviewTimeout: 100 * time.Millisecond, callerTimeout: 5 * time.Second, want: context.DeadlineExceeded},
		{name: "shorter caller timeout", reviewTimeout: 5 * time.Second, callerTimeout: 100 * time.Millisecond, want: context.DeadlineExceeded},
		{name: "caller cancellation", reviewTimeout: 5 * time.Second, callerTimeout: 5 * time.Second, cancelOnStart: true, want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := expiringToken("app", time.Now().Add(time.Hour))
			ctx, cancel := context.WithTimeout(bearerContext(token), tc.callerTimeout)
			defer cancel()
			var requests atomic.Int32
			canceled := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read TokenReview: %v", err)
					return
				}
				if requests.Add(1) == 1 {
					if tc.cancelOnStart {
						cancel()
					}
					<-r.Context().Done()
					close(canceled)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(&authenticationv1.TokenReview{
					Status: authenticatedAs("system:serviceaccount:demo:app"),
				}); err != nil {
					t.Errorf("write TokenReview: %v", err)
				}
			}))
			defer server.Close()
			client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			reviewer, err := NewTokenReviewer(client, []string{"agentio-ca"})
			if err != nil {
				t.Fatal(err)
			}
			reviewer.timeout = tc.reviewTimeout
			_, err = reviewer.Authenticate(ctx)
			if !errors.Is(err, ErrTokenReviewUnavailable) || !errors.Is(err, tc.want) {
				t.Fatalf("Authenticate() error = %v, want unavailable and %v", err, tc.want)
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("TokenReview HTTP request was not canceled")
			}
			if _, found := reviewer.cached(token, time.Now()); found {
				t.Fatal("canceled review was cached")
			}
			reviewer.timeout = tokenReviewTimeout
			for range 2 {
				if _, err := reviewer.Authenticate(bearerContext(token)); err != nil {
					t.Fatal(err)
				}
			}
			if got := requests.Load(); got != 2 {
				t.Fatalf("HTTP requests = %d, want canceled request, retry, then cache hit", got)
			}
		})
	}
}

func TestTokenReviewBoundsClientThrottleAndBypassesItOnCacheHit(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	limiter := flowcontrol.NewTokenBucketRateLimiter(1, 1)
	if !limiter.TryAccept() {
		t.Fatal("could not exhaust initial API burst")
	}
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, RateLimiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := NewTokenReviewer(client, []string{"agentio-ca"})
	if err != nil {
		t.Fatal(err)
	}
	reviewer.timeout = 50 * time.Millisecond
	token := expiringToken("app", time.Now().Add(time.Hour))
	started := time.Now()
	_, err = reviewer.Authenticate(bearerContext(token))
	if !errors.Is(err, ErrTokenReviewUnavailable) {
		t.Fatalf("Authenticate() error = %v, want unavailable", err)
	}
	if time.Since(started) >= time.Second {
		t.Fatal("TokenReview waited for an API token beyond its budget")
	}
	if _, found := reviewer.cached(token, time.Now()); found {
		t.Fatal("throttled review was cached")
	}
	caller := model.PeerIdentity{AttestedBy: model.AttestationKubernetes}
	reviewer.remember(token, caller, time.Now())
	got, err := reviewer.Authenticate(bearerContext(token))
	if err != nil || got.AttestedBy != caller.AttestedBy {
		t.Fatalf("cache hit = %v, %v", got, err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("HTTP requests = %d, want none while throttled or cached", got)
	}
}

func TestAuthenticateRejectsUsernameWithoutServiceAccountGroup(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1.UserInfo{
				Username: "system:serviceaccount:demo:app",
				Groups:   []string{"system:authenticated", "system:serviceaccounts:demo"},
			},
		}
	})

	if _, err := counter.reviewer.Authenticate(bearerContext("not-a-service-account-token")); err == nil {
		t.Fatal("Authenticate accepted a TokenReview without system:serviceaccounts group")
	}
	if got := counter.reviews(); got != 1 {
		t.Fatalf("TokenReviews = %d, want 1", got)
	}
	if _, err := counter.reviewer.Authenticate(bearerContext("not-a-service-account-token")); err == nil {
		t.Fatal("Authenticate cached a TokenReview without system:serviceaccounts group")
	}
	if got := counter.reviews(); got != 2 {
		t.Fatalf("TokenReviews after retry = %d, want 2", got)
	}
}

// A repeated token presentation is answered from cache.
func TestAuthenticateCachesSuccessfulReviews(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("system:serviceaccount:demo:app")
	})

	token := expiringToken("app", time.Now().Add(time.Hour))
	for range 5 {
		caller, err := counter.reviewer.Authenticate(bearerContext(token))
		if err != nil {
			t.Fatal(err)
		}
		if caller.Kubernetes.Namespace != "demo" || caller.Kubernetes.ServiceAccount != "app" {
			t.Fatalf("principal = %+v", caller.Kubernetes)
		}
		if caller.AttestedBy != model.AttestationKubernetes || caller.Kubernetes.WorkloadName != "client-pod" || caller.Kubernetes.WorkloadUID != "pod-uid" {
			t.Fatalf("bound pod identity lost through the cache: %+v", caller)
		}
	}
	if got := counter.reviews(); got != 1 {
		t.Fatalf("TokenReviews = %d, want 1", got)
	}
}

// Distinct tokens are distinct cache entries: one client's review must never
// answer for another's token.
func TestAuthenticateDoesNotShareEntriesBetweenTokens(t *testing.T) {
	counter := newCountingReviewer(t, func(token string) authenticationv1.TokenReviewStatus {
		if token == "token-a" {
			return authenticatedAs("system:serviceaccount:demo:a")
		}
		return authenticatedAs("system:serviceaccount:demo:b")
	})

	first, err := counter.reviewer.Authenticate(bearerContext("token-a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := counter.reviewer.Authenticate(bearerContext("token-b"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Kubernetes.ServiceAccount == second.Kubernetes.ServiceAccount {
		t.Fatalf("two tokens resolved to the same identity: %+v", first.Kubernetes)
	}
	if got := counter.reviews(); got != 2 {
		t.Fatalf("TokenReviews = %d, want 2", got)
	}
}

// A cache entry expires, which bounds how long a revoked token stays usable.
func TestAuthenticateReReviewsAfterTTL(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("system:serviceaccount:demo:app")
	})
	counter.reviewer.ttl = 10 * time.Millisecond
	token := expiringToken("app", time.Now().Add(time.Hour))

	if _, err := counter.reviewer.Authenticate(bearerContext(token)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := counter.reviewer.Authenticate(bearerContext(token)); err != nil {
		t.Fatal(err)
	}
	if got := counter.reviews(); got != 2 {
		t.Fatalf("TokenReviews = %d, want 2 after expiry", got)
	}
}

// Rejections are never cached.
func TestAuthenticateDoesNotCacheRejections(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticationv1.TokenReviewStatus{Authenticated: false, Error: "nope"}
	})

	for range 3 {
		if _, err := counter.reviewer.Authenticate(bearerContext("a-token")); err == nil {
			t.Fatal("an unauthenticated token was accepted")
		}
	}
	if got := counter.reviews(); got != 3 {
		t.Fatalf("TokenReviews = %d, want one per attempt", got)
	}
}

// A username that is not a service account is refused, and not cached.
func TestAuthenticateRejectsNonServiceAccountUsers(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("kubernetes-admin")
	})
	if _, err := counter.reviewer.Authenticate(bearerContext("a-token")); err == nil {
		t.Fatal("a non-service-account user was accepted")
	}
	if _, err := counter.reviewer.Authenticate(bearerContext("a-token")); err == nil {
		t.Fatal("the rejection was cached")
	}
	if got := counter.reviews(); got != 2 {
		t.Fatalf("TokenReviews = %d, want one per attempt", got)
	}
}

// The cache never exceeds tokenReviewCacheEntries.
func TestTokenReviewCacheIsBounded(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("system:serviceaccount:demo:app")
	})
	now := time.Now()
	for index := range tokenReviewCacheEntries + 500 {
		counter.reviewer.remember(expiringToken(fmt.Sprint(index), now.Add(time.Hour)), model.PeerIdentity{}, now)
	}
	counter.reviewer.mu.Lock()
	size := len(counter.reviewer.cache)
	counter.reviewer.mu.Unlock()
	if size != tokenReviewCacheEntries {
		t.Fatalf("cache grew to %d entries, cap is %d", size, tokenReviewCacheEntries)
	}
}

func TestAuthenticateRequiresBearerToken(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticatedAs("system:serviceaccount:demo:app")
	})
	for _, ctx := range []context.Context{
		context.Background(),
		metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic abc")),
		metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer ")),
	} {
		if _, err := counter.reviewer.Authenticate(ctx); err == nil {
			t.Fatal("a request without a bearer token was accepted")
		}
	}
	if got := counter.reviews(); got != 0 {
		t.Fatalf("TokenReviews = %d, want none for malformed credentials", got)
	}
}

func TestTokenReviewCacheExpiresAtCredentialDeadline(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for _, tc := range []struct {
		name                   string
		lifetime, wantLifetime time.Duration
	}{
		{name: "token expires before cache TTL", lifetime: 10 * time.Second, wantLifetime: 10 * time.Second},
		{name: "cache TTL expires first", lifetime: time.Hour, wantLifetime: tokenReviewCacheTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
				return authenticatedAs("system:serviceaccount:demo:app")
			})
			token := expiringToken("app", now.Add(tc.lifetime))
			counter.reviewer.remember(token, model.PeerIdentity{}, now)
			deadline := now.Add(tc.wantLifetime)
			if _, found := counter.reviewer.cached(token, deadline.Add(-time.Nanosecond)); !found {
				t.Fatal("valid cached review was not reused")
			}
			if _, found := counter.reviewer.cached(token, deadline); found {
				t.Fatal("review was reused at or after its deadline")
			}
		})
	}
}

func TestAuthenticateReReviewsAfterTokenExpiry(t *testing.T) {
	counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
		return authenticationv1.TokenReviewStatus{Authenticated: false, Error: "token expired"}
	})
	now := time.Now().Truncate(time.Second)
	token := expiringToken("app", now.Add(-time.Second))
	// Model a successful review ten seconds ago. Its one-minute TTL has not
	// elapsed, but the credential has expired and must be reviewed again.
	counter.reviewer.remember(token, model.PeerIdentity{}, now.Add(-10*time.Second))
	if _, err := counter.reviewer.Authenticate(bearerContext(token)); err == nil {
		t.Fatal("expired token accepted from cache")
	}
	if got := counter.reviews(); got != 1 {
		t.Fatalf("reviews = %d, want expired token rechecked", got)
	}
}

func TestAuthenticateDoesNotCacheWithoutFutureExpiry(t *testing.T) {
	for _, token := range []string{
		"opaque-token", "header.invalid!.signature", tokenWithClaims(`{`),
		tokenWithClaims(`{}`), tokenWithClaims(`{"exp":null}`),
		tokenWithClaims(`{"exp":"9999999999"}`), tokenWithClaims(`{"exp":1.5}`),
		tokenWithClaims(`{"exp":9999999999999999999999}`),
		expiringToken("app", time.Now().Add(-time.Hour)),
	} {
		counter := newCountingReviewer(t, func(string) authenticationv1.TokenReviewStatus {
			return authenticatedAs("system:serviceaccount:demo:app")
		})
		for range 2 {
			// Local claim parsing only governs caching, never overrides the API
			// server's authentication decision for opaque/unsupported tokens.
			if _, err := counter.reviewer.Authenticate(bearerContext(token)); err != nil {
				t.Fatal(err)
			}
		}
		if got := counter.reviews(); got != 2 {
			t.Fatalf("reviews = %d, want 2 without usable expiry", got)
		}
	}
}
