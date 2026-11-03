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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openkruise/agentio/pkg/model"
)

const (
	podNameExtra = "authentication.kubernetes.io/pod-name"
	podUIDExtra  = "authentication.kubernetes.io/pod-uid"
)

type Authenticator interface {
	Authenticate(context.Context) (model.PeerIdentity, error)
}

// tokenReviewCacheTTL bounds how long a successful review is reused.
const (
	tokenReviewCacheTTL     = time.Minute
	tokenReviewCacheEntries = 4096
	tokenReviewTimeout      = 5 * time.Second
)

// ErrTokenReviewUnavailable marks API failures, not rejected credentials.
var ErrTokenReviewUnavailable = errors.New("Kubernetes token review unavailable")

type tokenReviewEntry struct {
	caller  model.PeerIdentity
	expires time.Time
}

type TokenReviewer struct {
	client    kubernetes.Interface
	audiences []string
	ttl       time.Duration
	timeout   time.Duration

	mu    sync.Mutex
	cache map[string]tokenReviewEntry
}

var _ Authenticator = (*TokenReviewer)(nil)

// NewTokenReviewer authenticates Kubernetes tokens for the configured audiences.
func NewTokenReviewer(client kubernetes.Interface, audiences []string) (*TokenReviewer, error) {
	if client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}
	if len(audiences) == 0 {
		audiences = []string{"agentio-ca"}
	}
	return &TokenReviewer{
		client:    client,
		audiences: append([]string(nil), audiences...),
		ttl:       tokenReviewCacheTTL,
		timeout:   tokenReviewTimeout,
		cache:     make(map[string]tokenReviewEntry),
	}, nil
}

// cacheKey never stores the bearer token itself; a digest is enough to recognise
// a repeat presentation.
func cacheKey(token string) string {
	digest := sha256.Sum256([]byte(token))
	return string(digest[:])
}

func (a *TokenReviewer) cached(token string, now time.Time) (model.PeerIdentity, bool) {
	key := cacheKey(token)
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, found := a.cache[key]
	if !found {
		return model.PeerIdentity{}, false
	}
	if !entry.expires.After(now) {
		delete(a.cache, key)
		return model.PeerIdentity{}, false
	}
	return entry.caller, true
}

// remember caches a successful review, never beyond the token's expiry.
// Parsing exp does not authenticate the token: TokenReview remains authoritative.
// Opaque tokens and JWTs without a usable expiry are reviewed on every request.
func (a *TokenReviewer) remember(token string, caller model.PeerIdentity, now time.Time) {
	expires, ok := tokenExpiration(token)
	if !ok || !expires.After(now) {
		return
	}
	if deadline := now.Add(a.ttl); deadline.Before(expires) {
		expires = deadline
	}
	key := cacheKey(token)
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) >= tokenReviewCacheEntries {
		// Drop expired entries, then an arbitrary one, to stay bounded.
		for candidate, entry := range a.cache {
			if !entry.expires.After(now) {
				delete(a.cache, candidate)
			}
		}
		for candidate := range a.cache {
			if len(a.cache) < tokenReviewCacheEntries {
				break
			}
			delete(a.cache, candidate)
		}
	}
	a.cache[key] = tokenReviewEntry{caller: caller, expires: expires}
}

// tokenExpiration only extracts a cache bound from an already reviewed JWT.
// Unsupported encodings disable caching rather than weaken authentication.
func tokenExpiration(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		ExpiresAt *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.ExpiresAt == nil {
		return time.Time{}, false
	}
	return time.Unix(*claims.ExpiresAt, 0), true
}

func (a *TokenReviewer) Authenticate(ctx context.Context) (model.PeerIdentity, error) {
	token, err := bearerToken(ctx)
	if err != nil {
		return model.PeerIdentity{}, err
	}
	now := time.Now()
	if caller, found := a.cached(token, now); found {
		return caller, nil
	}
	// Bound both client-side API throttling and the network call on cache misses.
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	review, err := a.client.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: append([]string(nil), a.audiences...)},
	}, metav1.CreateOptions{})
	if err != nil {
		return model.PeerIdentity{}, fmt.Errorf("%w: %w", ErrTokenReviewUnavailable, err)
	}
	if !review.Status.Authenticated {
		message := review.Status.Error
		if message == "" {
			message = "token was not authenticated"
		}
		return model.PeerIdentity{}, fmt.Errorf("review Kubernetes token: %s", message)
	}
	serviceAccountGroup := false
	for _, group := range review.Status.User.Groups {
		if group == "system:serviceaccounts" {
			serviceAccountGroup = true
			break
		}
	}
	if !serviceAccountGroup {
		return model.PeerIdentity{}, fmt.Errorf(
			"TokenReview user %q is not in the Kubernetes service account group",
			review.Status.User.Username,
		)
	}
	parts := strings.Split(review.Status.User.Username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" {
		return model.PeerIdentity{}, fmt.Errorf(
			"TokenReview username %q is not a Kubernetes service account",
			review.Status.User.Username,
		)
	}
	caller := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			Namespace:      parts[2],
			ServiceAccount: parts[3],
			WorkloadName:   firstExtra(review.Status.User.Extra, podNameExtra),
			WorkloadUID:    firstExtra(review.Status.User.Extra, podUIDExtra),
		},
	}
	a.remember(token, caller, now)
	return caller, nil
}

func bearerToken(ctx context.Context) (string, error) {
	values := metadata.ValueFromIncomingContext(ctx, "authorization")
	for _, value := range values {
		parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1]), nil
		}
	}
	return "", fmt.Errorf("%w: bearer token is required", ErrUnsupportedCredentials)
}

func firstExtra(extra map[string]authenticationv1.ExtraValue, key string) string {
	if values := extra[key]; len(values) > 0 {
		return values[0]
	}
	return ""
}
