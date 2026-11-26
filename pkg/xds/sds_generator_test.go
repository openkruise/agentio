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
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

type fakeCertificateProvider struct {
	certificate mitm.SignedCertificate
	signCalls   int
	err         error
	revision    string
	authErr     error
}

func (f *fakeCertificateProvider) Get(context.Context, model.ClientScope, string) (mitm.SignedCertificate, error) {
	f.signCalls++
	return f.certificate, f.err
}
func (f *fakeCertificateProvider) Authorize(model.ClientScope) error { return f.authErr }
func (f *fakeCertificateProvider) SignerRevision() string {
	if f.revision != "" {
		return f.revision
	}
	return f.certificate.SignerRevision
}

func TestNewSDSGeneratorRejectsNilProvider(t *testing.T) {
	if _, err := NewSDSGenerator(nil); err == nil {
		t.Fatal("NewSDSGenerator accepted a nil certificate provider")
	}
}

func newTestSDSGenerator(t testing.TB, provider DomainCertificateProvider) *SDSGenerator {
	t.Helper()
	generator, err := NewSDSGenerator(provider)
	if err != nil {
		t.Fatalf("NewSDSGenerator: %v", err)
	}
	return generator
}

func TestSDSGeneratorBuildsEnvoySecret(t *testing.T) {
	certificate := mitm.SignedCertificate{
		CertificateChain: []byte("certificate-chain"),
		PrivateKey:       []byte("private-key"),
		UsableUntil:      time.Now().Add(59 * time.Minute),
		NotAfter:         time.Now().Add(time.Hour),
		SignedAt:         time.Now(),
		SignerRevision:   "one",
	}
	watch := &watchState{started: true, names: sets.New("api.example.com"), sent: map[string]string{}}
	generated, err := newTestSDSGenerator(t, &fakeCertificateProvider{certificate: certificate}).Generate(
		context.Background(),
		GenerationRequest{
			Scope:           gatewayScope(),
			TypeURL:         model.SecretType,
			Subscription:    newSubscriptionView(watch),
			Full:            true,
			SubscribedNames: []string{"api.example.com"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Resources) != 1 {
		t.Fatalf("resources = %d, want 1", len(generated.Resources))
	}
	secret := &tlsv3.Secret{}
	if err := generated.Resources[0].Value.UnmarshalTo(secret); err != nil {
		t.Fatal(err)
	}
	if got := secret.GetName(); got != "api.example.com" {
		t.Fatalf("secret name = %q, want api.example.com", got)
	}
	if got := secret.GetTlsCertificate().GetCertificateChain().GetInlineBytes(); string(got) != "certificate-chain" {
		t.Fatalf("certificate chain = %q, want certificate-chain", got)
	}
	if got := secret.GetTlsCertificate().GetPrivateKey().GetInlineBytes(); string(got) != "private-key" {
		t.Fatalf("private key = %q, want private-key", got)
	}
}

func TestSDSGeneratorPreservesExactSubscribedName(t *testing.T) {
	rawName := "API.Example.COM."
	watch := &watchState{started: true, names: sets.New(rawName), sent: map[string]string{}}
	generated, err := newTestSDSGenerator(t, &fakeCertificateProvider{certificate: testSDSCertificate()}).Generate(
		context.Background(),
		GenerationRequest{
			Scope:           gatewayScope(),
			TypeURL:         model.SecretType,
			Subscription:    newSubscriptionView(watch),
			Full:            true,
			SubscribedNames: []string{rawName},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Resources) != 1 {
		t.Fatalf("resources = %d, want 1", len(generated.Resources))
	}
	if got := generated.Resources[0].XDSName; got != rawName {
		t.Fatalf("xDS resource name = %q, want exact subscription %q", got, rawName)
	}
	secret := &tlsv3.Secret{}
	if err := generated.Resources[0].Value.UnmarshalTo(secret); err != nil {
		t.Fatal(err)
	}
	if got := secret.GetName(); got != rawName {
		t.Fatalf("secret name = %q, want exact subscription %q", got, rawName)
	}
}

func testSDSCertificate() mitm.SignedCertificate {
	now := time.Now()
	return mitm.SignedCertificate{
		CertificateChain: []byte("certificate-chain"),
		PrivateKey:       []byte("private-key"),
		UsableUntil:      now.Add(59 * time.Minute),
		NotAfter:         now.Add(time.Hour),
		SignedAt:         now,
		SignerRevision:   "one",
	}
}

// Use the real issuer to verify cache eviction has no wire effect.
type countingSDSSigner struct{ calls atomic.Int32 }

func (s *countingSDSSigner) SignDNS(context.Context, string, time.Duration) (mitm.SignedCertificate, error) {
	s.calls.Add(1)
	return testSDSCertificate(), nil
}
func (*countingSDSSigner) Authorize(model.ClientScope) error { return nil }

func TestSDSLocalEvictionDoesNotInvalidateSentCertificates(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	signer := &countingSDSSigner{}
	state := krt.NewStatic(&mitm.SignerState{Revision: "one"}, true, krt.WithStop(ctx.Done()))
	issuer, err := mitm.NewOnDemandIssuer(
		ctx,
		mitm.DomainSignerSource{Signer: signer, State: state},
		signer,
		mitm.OnDemandOptions{
			LeafLifetime:    time.Hour,
			RenewBefore:     time.Minute,
			CacheMaxAge:     time.Hour,
			CacheMaxEntries: 1,
			SignConcurrency: 1,
		},
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); <-issuer.Done() })
	generator := newTestSDSGenerator(t, issuer)
	names := []string{"a.example.com", "b.example.com", "c.example.com"}
	sent := map[string]string{}
	request := GenerationRequest{
		Scope:           gatewayScope(),
		TypeURL:         model.SecretType,
		Snapshot:        selectionSnapshot(t, nil),
		Full:            true,
		Subscription:    SubscriptionView{names: names, sent: sent},
		SubscribedNames: names,
	}
	generate := func() GeneratedDelta {
		t.Helper()
		delta, err := generator.Generate(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range delta.Removed {
			delete(sent, name)
		}
		for _, resource := range delta.Resources {
			sent[resource.XDSName] = delta.versions[resource.XDSName]
		}
		return delta
	}
	initial := generate()
	if len(initial.Resources) != 3 || signer.calls.Load() != 3 {
		t.Fatal("initial explicit subscriptions were not signed")
	}
	generation := issuer.Changes().Get().Generation
	request.SubscribedNames = nil
	for pass := range 3 {
		delta := generate()
		if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
			t.Fatalf("passive pass %d = resources:%v removed:%v", pass, selectedNames(delta.Resources), delta.Removed)
		}
		if signer.calls.Load() != 3 || issuer.Changes().Get().Generation != generation {
			t.Fatal("passive eviction refresh signed or generated another notification")
		}
	}
	if _, err := issuer.Get(ctx, gatewayScope(), "other.example.com"); err != nil {
		t.Fatal(err)
	}
	request.SubscribedNames = []string{"a.example.com"}
	restored := generate()
	if !slices.Equal(selectedNames(restored.Resources), []string{"a.example.com"}) || signer.calls.Load() != 5 {
		t.Fatal("explicit resubscription did not restore A exactly once")
	}
	generation = issuer.Changes().Get().Generation
	request.SubscribedNames = nil
	generate()
	if signer.calls.Load() != 5 || issuer.Changes().Get().Generation != generation {
		t.Fatal("passive refresh after restoration restarted signing")
	}
}

func TestSDSCertificateRemainingTTL(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Hour, 30 * time.Second} {
		t.Run(lifetime.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const name = "API.example.com"
				certificate := testSDSCertificate()
				certificate.NotAfter = time.Now().Add(lifetime + time.Minute)
				certificate.UsableUntil = certificate.NotAfter.Add(-time.Minute)
				provider := &fakeCertificateProvider{certificate: certificate}
				generator := newTestSDSGenerator(t, provider)
				watch := &watchState{started: true, names: sets.New(name), sent: map[string]string{}}
				request := GenerationRequest{
					Scope:           gatewayScope(),
					TypeURL:         model.SecretType,
					Full:            true,
					Subscription:    newSubscriptionView(watch),
					SubscribedNames: []string{name},
				}
				delta, err := generator.Generate(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				wire, removed, err := validateGeneratedDelta(model.SecretType, delta)
				if err != nil || len(wire) != 1 || len(removed) != 0 {
					t.Fatalf("initial response: resources=%v removed=%v error=%v", wire, removed, err)
				}
				if got := wire[0].GetTtl().AsDuration(); got != lifetime {
					t.Fatalf("initial TTL = %v, want %v", got, lifetime)
				}
				version := wire[0].Version
				watch.sent[name] = version
				time.Sleep(lifetime / 2)
				request.Subscription = newSubscriptionView(watch)
				request.SubscribedNames = nil
				passive, err := generator.Generate(t.Context(), request)
				if err != nil || len(passive.Resources) != 0 || provider.signCalls != 1 {
					t.Fatalf("passive refresh: delta=%v signs=%d error=%v", passive, provider.signCalls, err)
				}
				request.SubscribedNames = []string{name}
				delta, err = generator.Generate(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				wire, removed, err = validateGeneratedDelta(model.SecretType, delta)
				if err != nil || len(wire) != 1 || len(removed) != 0 {
					t.Fatalf("resubscribe: resources=%v removed=%v error=%v", wire, removed, err)
				}
				if wire[0].Version != version || wire[0].GetTtl().AsDuration() != lifetime/2 {
					t.Fatalf("resubscribe changed version or extended lifetime: %v", wire[0])
				}
				// A generated result may wait in a queue before it is serialized.
				time.Sleep(lifetime / 2)
				wire, removed, err = validateGeneratedDelta(model.SecretType, delta)
				if err != nil || len(wire) != 0 || !slices.Equal(removed, []string{name}) {
					t.Fatalf("expired response: resources=%v removed=%v error=%v", wire, removed, err)
				}
			})
		})
	}
}

func TestSDSPassiveValidationUsesSigningGeneration(t *testing.T) {
	for _, tc := range []struct {
		name        string
		version     string
		revision    string
		authErr     error
		wantRemoved bool
	}{
		{name: "same generation", version: sdsResourceVersion("one", time.Now().Add(time.Hour), "hash"), revision: "one"},
		{name: "rotated CA", version: sdsResourceVersion("one", time.Now().Add(time.Hour), "hash"), revision: "two", wantRemoved: true},
		{name: "signer unavailable", version: sdsResourceVersion("one", time.Now().Add(time.Hour), "hash"), wantRemoved: true},
		{name: "expired", version: sdsResourceVersion("one", time.Now().Add(-time.Second), "hash"), revision: "one", wantRemoved: true},
		{name: "legacy version", version: "old-content-hash", revision: "one", wantRemoved: true},
		{name: "gateway revoked", version: sdsResourceVersion("one", time.Now().Add(time.Hour), "hash"), revision: "one", authErr: errors.New("gateway revoked"), wantRemoved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &fakeCertificateProvider{revision: tc.revision, authErr: tc.authErr}
			generator := newTestSDSGenerator(t, provider)
			watch := &watchState{names: sets.New[string](), sent: make(map[string]string)}
			initial := request(model.SecretType)
			initial.InitialResourceVersions = map[string]string{"api.example.com": tc.version}
			applySubscription(watch, initial)
			delta, err := generator.Generate(t.Context(), GenerationRequest{
				Scope:        gatewayScope(),
				TypeURL:      model.SecretType,
				Subscription: newSubscriptionView(watch),
				Full:         true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(delta.Resources) != 0 || provider.signCalls != 0 {
				t.Fatal("initial versions alone caused issuance")
			}
			if tc.wantRemoved != slices.Equal(delta.Removed, []string{"api.example.com"}) {
				t.Fatalf("removed = %v", delta.Removed)
			}
		})
	}
}

func TestSDSExplicitDemandDoesNotResignOtherNames(t *testing.T) {
	provider := &fakeCertificateProvider{certificate: testSDSCertificate()}
	generator := newTestSDSGenerator(t, provider)
	names := []string{"a.example.com", "b.example.com", "c.example.com"}
	sent := map[string]string{}
	for _, name := range names {
		sent[name] = sdsResourceVersion("one", time.Now().Add(time.Hour), "cached")
	}
	delta, err := generator.Generate(t.Context(), GenerationRequest{
		Scope:           gatewayScope(),
		TypeURL:         model.SecretType,
		Subscription:    SubscriptionView{names: names, sent: sent},
		Full:            true,
		SubscribedNames: []string{"b.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.signCalls != 1 || len(delta.Removed) != 0 ||
		!slices.Equal(selectedNames(delta.Resources), []string{"b.example.com"}) {
		t.Fatalf("explicit demand affected unrelated names: %v", delta)
	}
}

func (*fakeCertificateProvider) SignerGeneration() uint64 { return 0 }
