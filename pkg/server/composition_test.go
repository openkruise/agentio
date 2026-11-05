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
	"errors"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/mitm"
	"github.com/openkruise/agentio/pkg/xds"
)

func TestWithTrafficPolicySourceReplacesCollection(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	policy := model.TrafficPolicy{Name: "policy", Namespace: "default"}
	source := krt.NewStaticCollection[model.TrafficPolicy](nil, []model.TrafficPolicy{policy}, krt.WithStop(stop))

	composition := applyOptions([]Option{WithTrafficPolicySource(source)})
	resolved, err := applySourceCollectionTransforms(
		testSourceCollections(stop),
		composition.sourceCollectionTransforms,
	)
	if err != nil {
		t.Fatal(err)
	}
	got := resolved.TrafficPolicies.List()
	if len(got) != 1 || got[0].ResourceName() != policy.ResourceName() {
		t.Fatalf("WithTrafficPolicySource installed %v, want %s", got, policy.ResourceName())
	}
}

func TestSourceCollectionsApplyTransformsInOrder(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	defaults := testSourceCollections(stop)
	extraSandboxes := krt.NewStaticCollection[model.Sandbox](nil, []model.Sandbox{{UID: "vm-1"}}, krt.WithStop(stop))
	replacementPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil,
		[]model.TrafficPolicy{{Name: "database-policy", Namespace: "default"}}, krt.WithStop(stop))

	got, err := applySourceCollectionTransforms(defaults, []SourceCollectionsTransform{
		func(sources SourceCollections) (SourceCollections, error) {
			sources.Sandboxes = registry.JoinSources(
				[]*registry.Source[model.Sandbox]{
					sources.Sandboxes,
					registry.NewSource(extraSandboxes),
				},
				krt.WithStop(stop),
			)
			return sources, nil
		},
		func(sources SourceCollections) (SourceCollections, error) {
			sources.TrafficPolicies = replacementPolicies
			return sources, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Sandboxes.WaitUntilSynced(stop) {
		t.Fatal("joined sandbox collection did not sync")
	}
	if sandboxes := got.Sandboxes.List(); len(sandboxes) != 2 {
		t.Fatalf("sandboxes = %v, want the default and additional producer", sandboxes)
	}
	policies := got.TrafficPolicies.List()
	if len(policies) != 1 || policies[0].Name != "database-policy" {
		t.Fatalf("traffic policies = %v, want database-policy", policies)
	}
	if services := got.Services.List(); len(services) != 1 || services[0].Name != "default-service" {
		t.Fatalf("untouched services = %v, want the default collection", services)
	}
}

func TestSourceCollectionsRejectInvalidTransforms(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	defaults := testSourceCollections(stop)

	if _, err := applySourceCollectionTransforms(defaults, []SourceCollectionsTransform{nil}); err == nil ||
		!strings.Contains(err.Error(), "source collection transform 1 is nil") {
		t.Fatalf("nil transform error = %v", err)
	}
	want := errors.New("database unavailable")
	_, err := applySourceCollectionTransforms(defaults, []SourceCollectionsTransform{
		func(sources SourceCollections) (SourceCollections, error) { return sources, nil },
		func(SourceCollections) (SourceCollections, error) { return SourceCollections{}, want },
	})
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "source collection transform 2") {
		t.Fatalf("transform error = %v, want wrapped transform 2 error", err)
	}
}

func TestSourceCollectionsRejectMissingCollection(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	defaults := testSourceCollections(stop)

	_, err := applySourceCollectionTransforms(defaults, []SourceCollectionsTransform{
		func(sources SourceCollections) (SourceCollections, error) {
			sources.AgentioConfig = nil
			return sources, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "agentio config source collection is required") {
		t.Fatalf("missing collection error = %v", err)
	}
}

func TestSourceCollectionsRejectMissingTelemetrySources(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	for name, transform := range map[string]SourceCollectionsTransform{
		"policies": func(sources SourceCollections) (SourceCollections, error) {
			sources.Telemetry = nil
			return sources, nil
		},
		"providers": func(sources SourceCollections) (SourceCollections, error) {
			sources.TelemetryProviderOverrides = nil
			return sources, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := applySourceCollectionTransforms(
				testSourceCollections(stop),
				[]SourceCollectionsTransform{transform},
			); err == nil ||
				!strings.Contains(err.Error(), "Telemetry") {
				t.Fatalf("missing Telemetry source error = %v", err)
			}
		})
	}
}

func testSourceCollections(stop <-chan struct{}) SourceCollections {
	options := []krt.CollectionOption{krt.WithStop(stop)}
	return SourceCollections{
		Sandboxes: registry.NewSource(krt.NewStaticCollection[model.Sandbox](
			nil,
			[]model.Sandbox{
				{UID: "sandbox-1", Attester: &model.Attester{WorkloadUID: "cluster//Pod/default/pod-1"}},
			},
			options...)),
		Workloads: krt.NewStaticCollection[model.Workload](nil,
			[]model.Workload{{
				UID:       "cluster//Pod/default/pod-1",
				Namespace: "default",
				Principal: model.MustServiceAccountPrincipal("default", "default"),
			}}, options...),
		Services: krt.NewStaticCollection[model.Service](nil,
			[]model.Service{{Name: "default-service", Namespace: "default"}}, options...),
		Endpoints:                  krt.NewStaticCollection[model.Endpoint](nil, nil, options...),
		Gateways:                   krt.NewStaticCollection[model.Gateway](nil, nil, options...),
		TrafficPolicies:            krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...),
		SecurityProfiles:           krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...),
		GatewayPatches:             krt.NewStaticCollection[model.GatewayPatch](nil, nil, options...),
		Telemetry:                  krt.NewStaticCollection[model.Telemetry](nil, nil, options...),
		TelemetryProviderOverrides: krt.NewStatic[model.TelemetryProviderOverrides](nil, true, options...),
		AgentioConfig:              krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...),
	}
}

func TestWithScopeFuncRegistersAndRequiresKubernetes(t *testing.T) {
	fakeAttestation := model.Attestation("fake")
	fakeScope := model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"}
	kubernetesFunc := func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) {
		return model.ClientScope{}, nil
	}
	fakeFunc := func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) {
		return fakeScope, nil
	}

	// An additional attestation merges over the Kubernetes default.
	composition := applyOptions([]Option{WithScopeFunc(fakeAttestation, fakeFunc)})
	merged, err := mergeScopeFuncs(xds.ScopeFuncs{model.AttestationKubernetes: kubernetesFunc}, composition.scopeFuncs)
	if err != nil {
		t.Fatalf("mergeScopeFuncs() returned error: %v", err)
	}
	scope, err := merged.ResolveScope(t.Context(), nil, model.PeerIdentity{AttestedBy: fakeAttestation})
	if err != nil || scope != fakeScope {
		t.Fatalf("registered scope function not effective: scope=%#v err=%v", scope, err)
	}

	// Overriding Kubernetes with nil removes the mandatory entry and must fail
	// construction rather than fail open at runtime.
	overridden := applyOptions([]Option{WithScopeFunc(model.AttestationKubernetes, nil)})
	if _, err := mergeScopeFuncs(
		xds.ScopeFuncs{model.AttestationKubernetes: kubernetesFunc},
		overridden.scopeFuncs,
	); err == nil {
		t.Fatal("missing kubernetes scope function passed construction")
	}

	// Any nil registration is a construction error, never a runtime fail-open.
	nilEntry := applyOptions([]Option{WithScopeFunc(fakeAttestation, nil)})
	if _, err := mergeScopeFuncs(
		xds.ScopeFuncs{model.AttestationKubernetes: kubernetesFunc},
		nilEntry.scopeFuncs,
	); err == nil {
		t.Fatal("nil scope function registration passed construction")
	}
}

const attestationFirecracker model.Attestation = "firecracker"

func TestMergeAuthenticatorsRunsRegisteredBeforeDefaults(t *testing.T) {
	registered := &countingAuthenticator{peer: model.PeerIdentity{AttestedBy: attestationFirecracker}}
	defaultAuthenticator := &countingAuthenticator{err: errors.New("default authenticator must not run")}
	defaults := attestation.AuthenticatorChain{defaultAuthenticator}
	additions := []attestation.Authenticator{registered}

	chain := mergeAuthenticators(defaults, additions)
	peer, err := chain.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() returned error: %v", err)
	}
	if peer.AttestedBy != attestationFirecracker {
		t.Fatalf("authenticated by %q, want %q", peer.AttestedBy, attestationFirecracker)
	}
	if registered.calls != 1 || defaultAuthenticator.calls != 0 {
		t.Fatalf("registered/default calls = %d/%d, want 1/0", registered.calls, defaultAuthenticator.calls)
	}
	if len(defaults) != 1 || len(additions) != 1 {
		t.Fatalf("merge mutated inputs: defaults=%d additions=%d", len(defaults), len(additions))
	}
}

func TestWithDomainSignerReplacesDefaultSigner(t *testing.T) {
	signer := fakeDomainSigner{}
	state := krt.NewStatic(&mitm.SignerState{Revision: "custom"}, true)
	composition := applyOptions([]Option{WithDomainSigner(mitm.DomainSignerSource{Signer: signer, State: state})})

	if composition.domainSigner == nil || composition.domainSigner.Signer != signer {
		t.Fatal("WithDomainSigner did not install the custom signing behavior")
	}
	if got := composition.domainSigner.State.Get(); got == nil || got.Revision != "custom" {
		t.Fatalf("WithDomainSigner installed state %#v, want custom revision", got)
	}
}

func TestWithAuthenticatorAppendsToChain(t *testing.T) {
	called := false
	chain := attestation.AuthenticatorChain{
		unsupportedAuthenticator{},
		appendedAuthenticator{called: &called},
	}
	peer, err := chain.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() returned error: %v", err)
	}
	if !called {
		t.Fatal("appended authenticator was not consulted")
	}
	if peer.AttestedBy != attestationFirecracker {
		t.Fatalf("Authenticate() attested by %q, want %q", peer.AttestedBy, attestationFirecracker)
	}
}

type fakeDomainSigner struct{}

func (fakeDomainSigner) SignDNS(context.Context, string, time.Duration) (mitm.SignedCertificate, error) {
	return mitm.SignedCertificate{}, nil
}

type unsupportedAuthenticator struct{}

func (unsupportedAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	return model.PeerIdentity{}, attestation.ErrUnsupportedCredentials
}

type appendedAuthenticator struct {
	called *bool
}

type countingAuthenticator struct {
	peer  model.PeerIdentity
	err   error
	calls int
}

func (a *countingAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	a.calls++
	return a.peer, a.err
}

func (a appendedAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	*a.called = true
	return model.PeerIdentity{AttestedBy: attestationFirecracker}, nil
}

func TestSourceReplacementCarriesObservedState(t *testing.T) {
	defaults := testSourceCollections(t.Context().Done())
	old := model.Sandbox{
		UID:            "old",
		Namespace:      "demo",
		SourceIdentity: model.SourceIdentity{UID: "old"},
	}
	defaults.Sandboxes = registry.NewSource(
		krt.NewStaticCollection(nil, []model.Sandbox{old}, krt.WithStop(t.Context().Done())),
	)
	replacement := model.Sandbox{
		UID:            "new",
		Namespace:      "demo",
		SourceIdentity: model.SourceIdentity{UID: "new"},
	}
	objects := krt.NewMutableCollection(nil, []model.Sandbox{replacement}, krt.WithStop(t.Context().Done()))
	options := applyOptions([]Option{WithSourceCollections(func(sources SourceCollections) (SourceCollections, error) {
		sources.Sandboxes = registry.NewSource(objects.AsCollection())
		return sources, nil
	})})
	resolved, err := applySourceCollectionTransforms(defaults, options.sourceCollectionTransforms)
	if err != nil {
		t.Fatal(err)
	}
	sources := resolved.Sandboxes.Registry
	if got, found := sources.Lookup(replacement.SourceKey()); !found || got != replacement.SourceIdentity {
		t.Fatalf("replacement source missing: %v, %v", got, found)
	}
	if _, found := sources.Lookup(old.SourceKey()); found {
		t.Fatal("replaced source remained in lookup")
	}
	objects.DeleteObject(replacement.ResourceName())
	if _, found := sources.Lookup(replacement.SourceKey()); found {
		t.Fatal("replacement deletion not visible")
	}
}
