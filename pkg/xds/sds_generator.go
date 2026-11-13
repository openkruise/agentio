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

package xds

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
	"github.com/openkruise/agentio/pkg/util/nilutil"
)

// DomainCertificateProvider separates explicit issuance from passive validation.
// Get must return a certificate with its fixed UsableUntil deadline and signing
// revision. Passive refreshes must never consult the local certificate cache or sign.
type DomainCertificateProvider interface {
	Get(context.Context, model.ClientScope, string) (mitm.SignedCertificate, error)
	Authorize(model.ClientScope) error
	SignerRevision() string
	// SignerGeneration changes on local signer transitions, including unavailability.
	SignerGeneration() uint64
}

var _ DomainCertificateProvider = (*mitm.OnDemandIssuer)(nil)

// SDSGenerator issues explicit domain demands and invalidates revoked signing generations.
type SDSGenerator struct{ provider DomainCertificateProvider }

func NewSDSGenerator(provider DomainCertificateProvider) (*SDSGenerator, error) {
	if nilutil.IsNilInterface(provider) {
		return nil, fmt.Errorf("domain certificate provider is required")
	}
	return &SDSGenerator{provider: provider}, nil
}

// sdsVersionPrefix makes CA invalidation independent of cache contents, including
// across reconnects to another replica. xDS resource versions are opaque to Envoy.
func sdsVersionPrefix(revision string) string {
	return "sds/" + base64.RawURLEncoding.EncodeToString([]byte(revision)) + "/"
}

func sdsResourceVersion(revision string, deadline time.Time, content string) string {
	return sdsVersionPrefix(revision) + strconv.FormatInt(deadline.UnixNano(), 10) + "/" + content
}

func staticSDSNames(snapshot model.ResourceSet, scope model.ClientScope) sets.Set[string] {
	names := sets.New[string]()
	for _, resource := range snapshot.List(model.SecretType) {
		if scopeAllows(scope, resource) {
			names.Insert(resource.XDSName)
		}
	}
	return names
}

func sdsVersionCurrent(version, revision string, now time.Time) bool {
	parts := strings.Split(version, "/")
	if revision == "" || len(parts) != 4 || parts[0] != "sds" ||
		parts[1] != base64.RawURLEncoding.EncodeToString([]byte(revision)) || parts[3] == "" {
		return false
	}
	deadline, err := strconv.ParseInt(parts[2], 10, 64)
	return err == nil && now.Before(time.Unix(0, deadline))
}

func (g *SDSGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if request.TypeURL != model.SecretType {
		return GeneratedDelta{}, fmt.Errorf("SDS generator cannot generate type %q", request.TypeURL)
	}
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	if !request.Full {
		return (SnapshotGenerator{}).Generate(ctx, request)
	}

	selected := make(map[string]model.Resource)
	for _, resource := range request.Snapshot.List(request.TypeURL) {
		if scopeAllows(request.Scope, resource) && request.Subscription.allows(resource) {
			selected[resource.XDSName] = resource
		}
	}
	result := GeneratedDelta{expiresAt: make(map[string]time.Time), versions: make(map[string]string)}
	removed := sets.New[string]()
	explicit := sets.New(request.SubscribedNames...)
	revision := g.provider.SignerRevision()
	authErr := g.provider.Authorize(request.Scope)
	for name, version := range request.Subscription.sent {
		if _, static := selected[name]; static || explicit.Contains(name) {
			continue
		}
		// Only successful sent versions are candidates for passive invalidation.
		// An absent local cache entry says nothing about Envoy's copy. Legacy
		// versions without a signing generation are invalidated once on upgrade.
		if authErr != nil || !sdsVersionCurrent(version, revision, time.Now()) {
			removed.Insert(name)
			if authErr != nil {
				result.denied = append(result.denied, generatedDenial{name: name, err: authErr})
			}
		}
	}
	for name := range explicit {
		if name == "*" {
			continue
		}
		if _, static := selected[name]; static {
			continue
		}
		certificate, err := g.provider.Get(ctx, request.Scope, name)
		if err != nil {
			if ctx.Err() != nil {
				return GeneratedDelta{}, ctx.Err()
			}
			removed.Insert(name)
			result.denied = append(result.denied, generatedDenial{name: name, err: err})
			continue
		}
		secret := &tlsv3.Secret{
			Name: name,
			Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: inlineDataSource(certificate.CertificateChain),
				PrivateKey:       inlineDataSource(certificate.PrivateKey),
			}},
		}
		value, err := anypb.New(secret)
		if err != nil {
			return GeneratedDelta{}, fmt.Errorf("encode SDS secret %q: %w", name, err)
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.SecretType, Name: request.Scope.GatewayKey + "|" + name},
			name, model.Prebuilt(value), nil, model.ResourceFacts{GatewayOwner: request.Scope.GatewayKey})
		if err != nil {
			return GeneratedDelta{}, fmt.Errorf("build SDS secret %q: %w", name, err)
		}
		selected[name] = resource
		result.allowed = append(result.allowed, name)
		result.expiresAt[name] = certificate.UsableUntil
		result.versions[name] = sdsResourceVersion(certificate.SignerRevision, certificate.UsableUntil, resource.Hash)
	}
	for name, resource := range selected {
		version := resource.Hash
		if dynamic, ok := result.versions[name]; ok {
			version = dynamic
		}
		if explicit.Contains(name) || request.Subscription.sent[name] != version {
			result.Resources = append(result.Resources, resource)
		}
	}
	result.Removed = sortedNames(removed)
	sort.Slice(
		result.Resources,
		func(i, j int) bool { return result.Resources[i].XDSName < result.Resources[j].XDSName },
	)
	return result, nil
}

func inlineDataSource(value []byte) *corev3.DataSource {
	return &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: append([]byte(nil), value...)}}
}
