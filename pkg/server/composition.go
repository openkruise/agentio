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

package server

import (
	"context"
	"fmt"
	"maps"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/mitm"
	"github.com/openkruise/agentio/pkg/util/nilutil"
	"github.com/openkruise/agentio/pkg/xds"
)

// Option adjusts one integration seam at construction.
type Option func(*composition)

type composition struct {
	sandboxLookup                xds.SandboxLookup
	sourceCollectionTransforms   []SourceCollectionsTransform
	authenticators               []attestation.Authenticator
	scopeFuncs                   xds.ScopeFuncs
	delegatedIdentityAuthorizers attestation.DelegatedIdentityAuthorizers
	domainSigner                 *mitm.DomainSignerSource
}

// SourceCollections is the registry input boundary consumed by DNS and the
// compiler.
type SourceCollections struct {
	Sandboxes                  *registry.Source[model.Sandbox]
	Workloads                  krt.Collection[model.Workload]
	Services                   krt.Collection[model.Service]
	Endpoints                  krt.Collection[model.Endpoint]
	Gateways                   krt.Collection[model.Gateway]
	TrafficPolicies            krt.Collection[model.TrafficPolicy]
	SecurityProfiles           krt.Collection[model.SecurityProfile]
	GatewayPatches             krt.Collection[model.GatewayPatch]
	Telemetry                  krt.Collection[model.Telemetry]
	TelemetryProviderOverrides krt.Singleton[model.TelemetryProviderOverrides]
	AgentioConfig              krt.Collection[model.AgentioConfiguration]
}

// SourceCollectionsTransform replaces or combines default Kubernetes-backed
// source collections. Transforms run in option order after the default registry
// is constructed and before any downstream graph is built.
type SourceCollectionsTransform func(SourceCollections) (SourceCollections, error)

func WithSourceCollections(transform SourceCollectionsTransform) Option {
	return func(cmp *composition) {
		cmp.sourceCollectionTransforms = append(cmp.sourceCollectionTransforms, transform)
	}
}

func WithTrafficPolicySource(c krt.Collection[model.TrafficPolicy]) Option {
	return WithSourceCollections(func(sources SourceCollections) (SourceCollections, error) {
		sources.TrafficPolicies = c
		return sources, nil
	})
}

// WithSandboxLookup reads and compiles one Sandbox for each authenticated RPC.
// lookup receives its canonical UID or workload namespace/name. Return nil, nil for absence.
func WithSandboxLookup(lookup func(context.Context, model.ClientScope, string) (*model.Sandbox, error)) Option {
	return func(cmp *composition) {
		cmp.sandboxLookup = func(ctx context.Context, scope model.ClientScope, name string) (*sandboxv1.Sandbox, error) {
			row, err := lookup(ctx, scope, name)
			if err != nil || row == nil {
				return nil, err
			}
			payload, err := compiler.CompileSandboxPayload(*row)
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "compile Sandbox %q: %v", name, err)
			}
			return payload, nil
		}
	}
}

func WithAuthenticator(a attestation.Authenticator) Option {
	return func(cmp *composition) { cmp.authenticators = append(cmp.authenticators, a) }
}

// WithScopeFunc registers or overrides one attestation's scope construction.
func WithScopeFunc(at model.Attestation, fn xds.ScopeFunc) Option {
	return func(cmp *composition) {
		if cmp.scopeFuncs == nil {
			cmp.scopeFuncs = xds.ScopeFuncs{}
		}
		cmp.scopeFuncs[at] = fn
	}
}

func WithDelegatedAuthorizer(at model.Attestation, a attestation.DelegatedIdentityAuthorizer) Option {
	return func(cmp *composition) {
		if cmp.delegatedIdentityAuthorizers == nil {
			cmp.delegatedIdentityAuthorizers = attestation.DelegatedIdentityAuthorizers{}
		}
		cmp.delegatedIdentityAuthorizers[at] = a
	}
}

func WithDomainSigner(source mitm.DomainSignerSource) Option {
	return func(cmp *composition) { cmp.domainSigner = &source }
}

func applyOptions(opts []Option) composition {
	var cmp composition
	for _, opt := range opts {
		if opt != nil {
			opt(&cmp)
		}
	}
	return cmp
}

func applySourceCollectionTransforms(
	defaults SourceCollections,
	transforms []SourceCollectionsTransform,
) (SourceCollections, error) {
	resolved := defaults
	for index, transform := range transforms {
		if transform == nil {
			return SourceCollections{}, fmt.Errorf("source collection transform %d is nil", index+1)
		}
		var err error
		resolved, err = transform(resolved)
		if err != nil {
			return SourceCollections{}, fmt.Errorf("source collection transform %d: %w", index+1, err)
		}
	}
	if err := validateSourceCollections(resolved); err != nil {
		return SourceCollections{}, err
	}
	return resolved, nil
}

func validateSourceCollections(sources SourceCollections) error {
	switch {
	case sources.Sandboxes == nil || sources.Sandboxes.Collection == nil || sources.Sandboxes.Registry == nil:
		return fmt.Errorf("sandbox source collection is required")
	case nilutil.IsNilInterface(sources.Workloads):
		return fmt.Errorf("workload source collection is required")
	case nilutil.IsNilInterface(sources.Services):
		return fmt.Errorf("service source collection is required")
	case nilutil.IsNilInterface(sources.Endpoints):
		return fmt.Errorf("endpoint source collection is required")
	case nilutil.IsNilInterface(sources.Gateways):
		return fmt.Errorf("gateway source collection is required")
	case nilutil.IsNilInterface(sources.TrafficPolicies):
		return fmt.Errorf("traffic policy source collection is required")
	case nilutil.IsNilInterface(sources.SecurityProfiles):
		return fmt.Errorf("security profile source collection is required")
	case nilutil.IsNilInterface(sources.GatewayPatches):
		return fmt.Errorf("GatewayPatch source collection is required")
	case nilutil.IsNilInterface(sources.Telemetry):
		return fmt.Errorf("Telemetry source collection is required")
	case nilutil.IsNilInterface(sources.TelemetryProviderOverrides):
		return fmt.Errorf("Telemetry provider override singleton is required")
	case nilutil.IsNilInterface(sources.AgentioConfig):
		return fmt.Errorf("agentio config source collection is required")
	default:
		return nil
	}
}

func mergeAuthenticators(
	defaults attestation.AuthenticatorChain,
	registered []attestation.Authenticator,
) attestation.AuthenticatorChain {
	merged := make(attestation.AuthenticatorChain, 0, len(registered)+len(defaults))
	merged = append(merged, registered...)
	merged = append(merged, defaults...)
	return merged
}

func mergeScopeFuncs(defaults, overrides xds.ScopeFuncs) (xds.ScopeFuncs, error) {
	merged := make(xds.ScopeFuncs, len(defaults)+len(overrides))
	maps.Copy(merged, defaults)
	maps.Copy(merged, overrides)
	for attestation, fn := range merged {
		if fn == nil {
			return nil, fmt.Errorf("nil scope function registered for attestation %q", attestation)
		}
	}
	if _, found := merged[model.AttestationKubernetes]; !found {
		return nil, fmt.Errorf("composition requires a scope function for attestation %q", model.AttestationKubernetes)
	}
	return merged, nil
}

func mergeDelegatedAuthorizers(
	defaults, overrides attestation.DelegatedIdentityAuthorizers,
) attestation.DelegatedIdentityAuthorizers {
	merged := make(attestation.DelegatedIdentityAuthorizers, len(defaults)+len(overrides))
	maps.Copy(merged, defaults)
	maps.Copy(merged, overrides)
	return merged
}
