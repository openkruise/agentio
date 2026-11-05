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
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

const (
	localJWTKeyLifetime     = 5 * time.Minute
	localJWTRefreshInterval = 5 * time.Second
	localJWTRequestTimeout  = 5 * time.Second
)

// LocalJWTAuthenticator verifies Pod-bound credentials against the configured cluster.
// Resource collections must belong to that same cluster and share its client lifecycle.
type LocalJWTAuthenticator struct {
	client   rest.Interface
	pods     krt.Collection[*corev1.Pod]
	accounts krt.Collection[*corev1.ServiceAccount]
	issuer   string
	audience string
	now      func() time.Time

	mu          sync.RWMutex
	keys        jose.JSONWebKeySet
	generation  uint64
	validUntil  time.Time
	nextRefresh time.Time
}

var _ Authenticator = (*LocalJWTAuthenticator)(nil)

type localJWTClaims struct {
	jwt.Claims
	Kubernetes struct {
		Namespace string `json:"namespace"`
		Pod       struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

// NewLocalJWTAuthenticator loads discovery and signing keys through the authenticated
// Kubernetes client. It registers no informers and does not wait for their initial sync.
func NewLocalJWTAuthenticator(
	ctx context.Context,
	client rest.Interface,
	pods krt.Collection[*corev1.Pod],
	accounts krt.Collection[*corev1.ServiceAccount],
	audience string,
) (*LocalJWTAuthenticator, error) {
	data, err := client.Get().AbsPath("/.well-known/openid-configuration").Timeout(localJWTRequestTimeout).DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes issuer discovery: %w", err)
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(data, &discovery); err != nil {
		return nil, fmt.Errorf("decode Kubernetes issuer discovery: %w", err)
	}
	issuer, err := url.Parse(discovery.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, fmt.Errorf("Kubernetes discovery must publish an HTTPS issuer URL")
	}
	a := &LocalJWTAuthenticator{
		client:   client,
		pods:     pods,
		accounts: accounts,
		issuer:   discovery.Issuer,
		audience: audience,
		now:      time.Now,
	}
	if _, err := a.refreshKeys(ctx, 0); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *LocalJWTAuthenticator) refreshKeys(ctx context.Context, generation uint64) (jose.JSONWebKeySet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.generation != generation && now.Before(a.validUntil) {
		return a.keys, nil
	}
	if now.Before(a.nextRefresh) {
		return jose.JSONWebKeySet{}, fmt.Errorf("Kubernetes signing key refresh is rate limited")
	}
	a.nextRefresh = now.Add(localJWTRefreshInterval)
	// Keep key discovery on the trusted Kubernetes connection, including with an external issuer URL.
	data, err := a.client.Get().AbsPath("/openid/v1/jwks").Timeout(localJWTRequestTimeout).DoRaw(ctx)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("load Kubernetes signing keys: %w", err)
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(data, &keys); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("decode Kubernetes signing keys: %w", err)
	}
	if len(keys.Keys) == 0 {
		return jose.JSONWebKeySet{}, fmt.Errorf("Kubernetes signing key set is empty")
	}
	for _, key := range keys.Keys {
		if !key.Valid() || !key.IsPublic() || (key.Use != "" && key.Use != "sig") {
			return jose.JSONWebKeySet{}, fmt.Errorf("Kubernetes signing key set contains an invalid verification key")
		}
	}
	a.keys = keys
	a.generation++
	a.validUntil = a.now().Add(localJWTKeyLifetime)
	return keys, nil
}

// Authenticate verifies the token locally and requires active Pod and ServiceAccount bindings.
func (a *LocalJWTAuthenticator) Authenticate(ctx context.Context) (model.PeerIdentity, error) {
	raw, err := bearerToken(ctx)
	if err != nil {
		return model.PeerIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return model.PeerIdentity{}, err
	}
	if !a.pods.HasSynced() || !a.accounts.HasSynced() {
		return model.PeerIdentity{}, fmt.Errorf("Kubernetes identity collections are not synced")
	}
	claims, err := a.verifyToken(ctx, raw)
	if err != nil {
		return model.PeerIdentity{}, err
	}
	k := claims.Kubernetes
	pod := a.pods.GetKey(k.Namespace + "/" + k.Pod.Name)
	if pod == nil || string((*pod).UID) != k.Pod.UID || (*pod).Spec.ServiceAccountName != k.ServiceAccount.Name ||
		(*pod).DeletionTimestamp != nil || (*pod).Status.Phase == corev1.PodFailed || (*pod).Status.Phase == corev1.PodSucceeded {
		return model.PeerIdentity{}, fmt.Errorf("Kubernetes JWT is not bound to an active Pod")
	}
	account := a.accounts.GetKey(k.Namespace + "/" + k.ServiceAccount.Name)
	if account == nil || string((*account).UID) != k.ServiceAccount.UID || (*account).DeletionTimestamp != nil {
		return model.PeerIdentity{}, fmt.Errorf("Kubernetes JWT service account is not active")
	}
	return model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			Namespace:      k.Namespace,
			ServiceAccount: k.ServiceAccount.Name,
			WorkloadName:   k.Pod.Name,
			WorkloadUID:    k.Pod.UID,
		},
	}, nil
}

func (a *LocalJWTAuthenticator) verifyToken(ctx context.Context, raw string) (localJWTClaims, error) {
	token, err := jwt.ParseSigned(
		raw,
		[]jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512},
	)
	if err != nil {
		return localJWTClaims{}, fmt.Errorf("parse Kubernetes JWT: %w", err)
	}
	a.mu.RLock()
	keys, generation, validUntil, nextRefresh := a.keys, a.generation, a.validUntil, a.nextRefresh
	a.mu.RUnlock()
	now := a.now()
	var claims localJWTClaims
	if now.Before(validUntil) {
		err = token.Claims(keys, &claims)
	}
	if !now.Before(validUntil) || (err != nil && !now.Before(nextRefresh)) {
		keys, err = a.refreshKeys(ctx, generation)
		if err != nil {
			return localJWTClaims{}, err
		}
		err = token.Claims(keys, &claims)
	}
	if err != nil {
		return localJWTClaims{}, fmt.Errorf("verify Kubernetes JWT: %w", err)
	}
	if claims.Expiry == nil || !a.now().Before(claims.Expiry.Time()) {
		return localJWTClaims{}, fmt.Errorf("Kubernetes JWT requires a future expiry")
	}
	if err := claims.ValidateWithLeeway(
		jwt.Expected{Issuer: a.issuer, AnyAudience: jwt.Audience{a.audience}, Time: a.now()},
		0,
	); err != nil {
		return localJWTClaims{}, fmt.Errorf("validate Kubernetes JWT: %w", err)
	}
	k := claims.Kubernetes
	if k.Namespace == "" || k.ServiceAccount.Name == "" || k.ServiceAccount.UID == "" || k.Pod.Name == "" ||
		k.Pod.UID == "" ||
		claims.Subject != "system:serviceaccount:"+k.Namespace+":"+k.ServiceAccount.Name {
		return localJWTClaims{}, fmt.Errorf("Kubernetes JWT requires a consistent Pod-bound service account identity")
	}
	return claims, nil
}
