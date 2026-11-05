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
	"errors"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

type fakeAuthenticator struct {
	peer  model.PeerIdentity
	err   error
	calls int
}

type fakeDelegatedIdentityAuthorizer struct {
	calls     int
	requested CertificateTarget
}

func (f *fakeDelegatedIdentityAuthorizer) Authorize(
	_ context.Context,
	_ model.PeerIdentity,
	requested CertificateTarget,
) (WorkloadIdentity, error) {
	f.calls++
	f.requested = requested
	return WorkloadIdentity{}, nil
}

func kubernetesAttestedCaller() model.PeerIdentity {
	return model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{Namespace: "agentio-system", ServiceAccount: "ztunnel"},
	}
}

const attestationFirecracker model.Attestation = "firecracker"

func (f *fakeAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	f.calls++
	return f.peer, f.err
}

func TestAuthenticatorChainSkipsUnsupportedCredentials(t *testing.T) {
	kubernetes := &fakeAuthenticator{err: ErrUnsupportedCredentials}
	vm := &fakeAuthenticator{peer: model.PeerIdentity{AttestedBy: attestationFirecracker}}
	chain := AuthenticatorChain{kubernetes, vm}

	peer, err := chain.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("chain rejected supported credentials: %v", err)
	}
	if peer != vm.peer {
		t.Fatalf("peer = %#v, want %#v", peer, vm.peer)
	}
	if kubernetes.calls != 1 || vm.calls != 1 {
		t.Fatalf("calls = %d/%d, want 1/1", kubernetes.calls, vm.calls)
	}
}

func TestAuthenticatorChainStopsOnRecognizedRejection(t *testing.T) {
	rejected := errors.New("token review failed")
	first := &fakeAuthenticator{err: rejected}
	second := &fakeAuthenticator{}
	chain := AuthenticatorChain{first, second}

	if _, err := chain.Authenticate(context.Background()); !errors.Is(err, rejected) {
		t.Fatalf("chain error = %v, want %v", err, rejected)
	}
	if second.calls != 0 {
		t.Fatal("rejection fell through to the next authenticator")
	}
}

func TestAuthenticatorChainFailsClosedWhenNothingMatches(t *testing.T) {
	chain := AuthenticatorChain{&fakeAuthenticator{err: ErrUnsupportedCredentials}}
	if _, err := chain.Authenticate(context.Background()); err == nil {
		t.Fatal("chain accepted unrecognized credentials")
	}
	if _, err := (AuthenticatorChain{}).Authenticate(context.Background()); err == nil {
		t.Fatal("empty chain accepted credentials")
	}
}

func TestRegisteredAttestationAuthenticatorAllowsRegisteredIdentity(t *testing.T) {
	want := model.PeerIdentity{AttestedBy: attestationFirecracker}
	authenticator, err := NewRegisteredAttestationAuthenticator(
		&fakeAuthenticator{peer: want}, []model.Attestation{attestationFirecracker})
	if err != nil {
		t.Fatal(err)
	}

	got, err := authenticator.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() returned error: %v", err)
	}
	if got != want {
		t.Fatalf("Authenticate() = %#v, want %#v", got, want)
	}
}

func TestRegisteredAttestationAuthenticatorRejectsUnregisteredIdentity(t *testing.T) {
	authenticator, err := NewRegisteredAttestationAuthenticator(&fakeAuthenticator{peer: model.PeerIdentity{
		AttestedBy: model.Attestation("typo-virtual-machine"),
	}}, []model.Attestation{attestationFirecracker})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := authenticator.Authenticate(context.Background()); err == nil {
		t.Fatal("Authenticate() accepted an unregistered attestation")
	}
}

func TestRegisteredAttestationAuthenticatorPreservesDelegateError(t *testing.T) {
	want := errors.New("credential rejected")
	authenticator, err := NewRegisteredAttestationAuthenticator(
		&fakeAuthenticator{err: want}, []model.Attestation{attestationFirecracker})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := authenticator.Authenticate(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Authenticate() error = %v, want %v", err, want)
	}
}

func TestRegisteredAttestationAuthenticatorRejectsInvalidConstruction(t *testing.T) {
	if _, err := NewRegisteredAttestationAuthenticator(nil, []model.Attestation{model.AttestationKubernetes}); err == nil {
		t.Fatal("NewRegisteredAttestationAuthenticator() accepted a nil delegate")
	}
	var typedNil *fakeAuthenticator
	if _, err := NewRegisteredAttestationAuthenticator(typedNil, []model.Attestation{model.AttestationKubernetes}); err == nil {
		t.Fatal("NewRegisteredAttestationAuthenticator() accepted a typed nil delegate")
	}
	if _, err := NewRegisteredAttestationAuthenticator(
		AuthenticatorChain{typedNil}, []model.Attestation{model.AttestationKubernetes}); err == nil {
		t.Fatal("NewRegisteredAttestationAuthenticator() accepted a chain with a typed nil authenticator")
	}
	if _, err := NewRegisteredAttestationAuthenticator(&fakeAuthenticator{}, nil); err == nil {
		t.Fatal("NewRegisteredAttestationAuthenticator() accepted no registered attestations")
	}
	if _, err := NewRegisteredAttestationAuthenticator(
		&fakeAuthenticator{}, []model.Attestation{model.AttestationKubernetes, ""}); err == nil {
		t.Fatal("NewRegisteredAttestationAuthenticator() accepted an empty attestation")
	}
}

func TestDelegatedIdentityAuthorizersDispatchByCallerAttestation(t *testing.T) {
	kubernetes := &fakeDelegatedIdentityAuthorizer{}
	authorizers := DelegatedIdentityAuthorizers{model.AttestationKubernetes: kubernetes}
	caller := kubernetesAttestedCaller()
	requested := CertificateTarget{
		Principal: model.MustPrincipal("cluster.local", "ns/demo/sa/app"),
		Workload:  &WorkloadReference{Namespace: "demo", Name: "pod-a"},
	}

	if _, err := authorizers.Authorize(context.Background(), caller, requested); err != nil {
		t.Fatalf("service account delegation rejected: %v", err)
	}
	if kubernetes.calls != 1 || kubernetes.requested != requested {
		t.Fatalf("kubernetes authorizer calls = %d requested = %#v", kubernetes.calls, kubernetes.requested)
	}

	caller.AttestedBy = attestationFirecracker
	if _, err := authorizers.Authorize(context.Background(), caller, requested); err == nil {
		t.Fatal("unregistered caller attestation authorized")
	}
	if kubernetes.calls != 1 {
		t.Fatal("unregistered caller attestation leaked to the Kubernetes authorizer")
	}
}

func TestDelegatedIdentityAuthorizersFailClosedOnNilEntry(t *testing.T) {
	authorizers := DelegatedIdentityAuthorizers{model.AttestationKubernetes: nil}
	requested := CertificateTarget{Principal: model.MustPrincipal("cluster.local", "ns/demo/sa/app")}
	if _, err := authorizers.Authorize(context.Background(), kubernetesAttestedCaller(), requested); err == nil {
		t.Fatal("nil authorizer entry authorized a delegation")
	}
}

func TestDelegatedIdentityAuthorizersFailClosedOnTypedNilEntry(t *testing.T) {
	var authorizer *fakeDelegatedIdentityAuthorizer
	authorizers := DelegatedIdentityAuthorizers{model.AttestationKubernetes: authorizer}
	requested := CertificateTarget{Principal: model.MustPrincipal("cluster.local", "ns/demo/sa/app")}
	if _, err := authorizers.Authorize(context.Background(), kubernetesAttestedCaller(), requested); err == nil {
		t.Fatal("typed nil authorizer entry authorized a delegation")
	}
}
