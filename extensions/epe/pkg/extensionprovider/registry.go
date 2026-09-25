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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/env"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/credential/tokencache"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpclient"
)

// Cache policy is fixed at process startup and applies to every credential
// provider, including providers added later through EPEConfig. Cache instances
// remain private to each provider configuration version.
var (
	cacheTTL = env.Register("TOKEN_CACHE_TTL", 15*time.Minute,
		"Fallback time-to-live for cached credential provider API keys, used when the provider's response omits "+
			"cacheExpiresInSeconds; a non-positive value disables caching").Get()
	cacheMaxSize = env.Register("TOKEN_CACHE_MAX_SIZE", tokencache.DefaultMaxSize,
		"Maximum number of cached credential provider API keys; a non-positive value falls back to the default").Get()
	stsCacheMaxSize = env.Register(
		"STS_CACHE_MAX_SIZE",
		tokencache.DefaultMaxSize,
		"Maximum number of cached credential provider STS credentials; a non-positive value falls back to the default",
	).Get()
)

type instance struct {
	fingerprint [32]byte
	client      *http.Client
	httpCallout *httpEndpoint
	credential  tokentransform.CredentialSource
	err         error
}
type snapshot struct {
	providers         map[string]*instance
	defaultCredential string
}

// ErrClosed is returned by Apply after Close.
var ErrClosed = errors.New("extension provider registry is closed")

// Registry publishes immutable versions. Unchanged entries retain their pools
// and caches; changes get fresh instances, so old in-flight calls cannot fill
// the new provider's cache. The zero value is ready to use.
type Registry struct {
	mu      sync.Mutex
	current snapshot
	closed  bool
}

// closeIdleConnections leaves active calls intact. Old instances remain alive
// through their callers; any later idle connections expire via IdleConnTimeout.
func (p *instance) closeIdleConnections() {
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
}

// Apply atomically replaces providers using resolved, immutable TLS material.
// Missing or invalid required material installs an unavailable instance instead
// of retaining revoked credentials. The caller must not mutate material during Apply.
func (r *Registry) Apply(cfg *configv1.EPEConfig, materials map[string]TLSMaterial) error {
	if err := Validate(cfg); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	next := snapshot{
		providers:         map[string]*instance{},
		defaultCredential: cfg.GetDefaultProviders().GetCredentialProvider(),
	}
	installed := false
	defer func() {
		if !installed {
			for name, p := range next.providers {
				if p != r.current.providers[name] {
					p.closeIdleConnections()
				}
			}
		}
	}()
	for _, p := range cfg.GetExtensionProviders() {
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(p)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(materials[p.Name])
		if err != nil {
			return err
		}
		fingerprintData := append(raw, encoded...)
		fingerprint := sha256.Sum256(fingerprintData)
		if old := r.current.providers[p.Name]; old != nil && old.fingerprint == fingerprint {
			next.providers[p.Name] = old
			continue
		}
		next.providers[p.Name] = build(p, fingerprint, materials[p.Name])
	}
	old := r.current
	r.current = next
	installed = true
	for name, p := range old.providers {
		if p != next.providers[name] {
			p.closeIdleConnections()
		}
	}
	return nil
}

// Close removes all providers and closes idle connections; active calls may finish.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.current.providers {
		p.closeIdleConnections()
	}
	r.current = snapshot{}
	r.closed = true
}

func build(p *configv1.ExtensionProvider, fingerprint [32]byte, material TLSMaterial) *instance {
	endpoint, timeout, tlsCfg := settings(p)
	d, err := duration(timeout, 500*time.Millisecond)
	i := &instance{fingerprint: fingerprint}
	if err != nil {
		i.err = err
		return i
	}
	tlsConfig, err := clientTLS(endpoint, tlsCfg, material)
	if err != nil {
		i.err = err
		return i
	}
	client := httpclient.New(httpclient.DefaultOptions())
	client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	client.Timeout = d
	i.client = client
	if p.GetHttpCallout() != nil {
		i.httpCallout = &httpEndpoint{url: endpoint}
	} else {
		credentials := credential.NewClient(
			endpoint,
			client,
			tokencache.NewCache(cacheTTL, cacheMaxSize),
			tokencache.NewSTSCache(stsCacheMaxSize),
		)
		i.credential = tokentransform.NewProviderSource(credentials, credentials)
	}
	return i
}

// find selects one immutable instance. Calls retain that instance across updates.
func (r *Registry) find(name string, credentials bool) (*instance, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" && credentials {
		name = r.current.defaultCredential
	}
	p := r.current.providers[name]
	if p == nil {
		return nil, fmt.Errorf("extension provider %q unavailable", name)
	}
	if p.err != nil {
		return nil, fmt.Errorf("extension provider %q unavailable: %w", name, p.err)
	}
	if (credentials && p.credential == nil) || (!credentials && p.httpCallout == nil) {
		return nil, fmt.Errorf("extension provider %q has the wrong type", name)
	}
	return p, nil
}

// Fetch implements the token transformation's provider source. Provider selects
// the local connection; Name remains the remote credentialProviderName.
func (r *Registry) Fetch(ctx context.Context, ref tokentransform.Ref) (tokentransform.Credential, error) {
	p, err := r.find(ref.Provider, true)
	if err != nil {
		return tokentransform.Credential{}, err
	}
	return p.credential.Fetch(ctx, ref)
}
