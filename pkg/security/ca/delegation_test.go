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

package ca

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	securityapi "istio.io/api/security/v1alpha1"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

type fakeDelegatedIdentityAuthorizer struct {
	calls     int
	caller    model.PeerIdentity
	requested model.Principal
	source    model.SourceRef
	workload  *attestation.WorkloadReference
	resolved  model.SourceRef
	role      string
	err       error
	authorize func(context.Context, model.PeerIdentity, model.Principal) error
}

func (f *fakeDelegatedIdentityAuthorizer) Authorize(
	ctx context.Context,
	caller model.PeerIdentity,
	target attestation.CertificateTarget,
) (attestation.WorkloadIdentity, error) {
	f.calls++
	f.caller = caller
	f.requested = target.Principal
	f.workload = target.Workload
	f.source = f.resolved
	if target.Workload != nil && f.source == (model.SourceRef{}) {
		f.source = model.SourceRef{Registry: "kubernetes/test", Key: caller.Kubernetes.WorkloadUID}
	}
	if f.authorize != nil {
		return attestation.WorkloadIdentity{
				Registry: f.source.Registry,
				UID:      f.source.Key,
				Role:     f.role,
			}, f.authorize(
				ctx,
				caller,
				target.Principal,
			)
	}
	return attestation.WorkloadIdentity{Registry: f.source.Registry, UID: f.source.Key, Role: f.role}, f.err
}

func sharedZTunnelCaller() model.PeerIdentity {
	return model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName:   "ztunnel-abc",
			WorkloadUID:    "agentio-system/ztunnel-abc",
			Namespace:      "agentio-system",
			ServiceAccount: "ztunnel",
		},
	}
}

func certificateIdentityForTest(
	t *testing.T,
	authority *Authority,
	ctx context.Context,
	caller model.PeerIdentity,
	request *securityapi.IstioCertificateRequest,
) (model.Principal, error) {
	t.Helper()
	csr, err := parseCertificateRequest(request)
	if err != nil {
		t.Fatalf("parse test certificate request: %v", err)
	}
	target, err := authority.certificateTarget(ctx, caller, request, csr)
	return target.Principal, err
}

func TestSelfIdentityUsesAuthorizer(t *testing.T) {
	authorizer := &fakeDelegatedIdentityAuthorizer{}
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.UseDelegatedIdentityAuthorizer(authorizer)
	caller := model.PeerIdentity{Kubernetes: model.KubernetesPeer{Namespace: "demo", ServiceAccount: "app"}}

	target := model.MustPrincipal("cluster.local", "workload/app")
	request := requestWithCSR(t, target.String())
	setRequestMetadata(t, request, target.String())
	got, err := certificateIdentityForTest(t, authority, context.Background(), caller, request)
	if err != nil {
		t.Fatalf("own identity refused: %v", err)
	}
	if got != target {
		t.Fatalf("identity = %#v, want %#v", got, target)
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorizer calls for own identity = %d, want 1", authorizer.calls)
	}
}

// Delegation must go through the authorizer; no Pod source is available here.
func TestDelegatedIdentityUsesAuthorizer(t *testing.T) {
	denied := errors.New("delegation denied")
	authorizer := &fakeDelegatedIdentityAuthorizer{err: denied}
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.UseDelegatedIdentityAuthorizer(authorizer)
	caller := sharedZTunnelCaller()
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/workload/app")

	_, err := certificateIdentityForTest(t, authority, context.Background(), caller, request)
	if !errors.Is(err, denied) {
		t.Fatalf("delegated authorization error = %v, want %v", err, denied)
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizer.calls)
	}
	if authorizer.caller != caller {
		t.Fatalf("authorizer caller = %#v, want %#v", authorizer.caller, caller)
	}
	want := model.MustPrincipal("cluster.local", "workload/app")
	if authorizer.requested != want {
		t.Fatalf("authorizer requested principal = %#v, want %#v", authorizer.requested, want)
	}
}

func TestDelegatedIdentityRequiresConfiguredAuthorizer(t *testing.T) {
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/workload/app")
	if _, err := certificateIdentityForTest(
		t,
		authority,
		context.Background(),
		sharedZTunnelCaller(),
		request,
	); err == nil {
		t.Fatal("delegated identity was allowed without an authorizer")
	}
}

func TestUnregisteredProfileStillRequiresAuthorization(t *testing.T) {
	denied := errors.New("identity is not registered")
	kubernetes := &fakeDelegatedIdentityAuthorizer{err: denied}
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.UseDelegatedIdentityAuthorizer(
		attestation.DelegatedIdentityAuthorizers{model.AttestationKubernetes: kubernetes},
	)
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/sandbox/v1/vm-1")

	if _, err := certificateIdentityForTest(
		t,
		authority,
		context.Background(),
		sharedZTunnelCaller(),
		request,
	); !errors.Is(
		err,
		denied,
	) {
		t.Fatalf("unregistered URI bypassed authorization: %v", err)
	}
	if kubernetes.calls != 1 {
		t.Fatalf("unregistered URI reached the Kubernetes authorizer %d times", kubernetes.calls)
	}
}

func TestDelegatedIdentityPassesCancellationToAuthorizer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	authorizer := &fakeDelegatedIdentityAuthorizer{
		authorize: func(ctx context.Context, _ model.PeerIdentity, _ model.Principal) error {
			return ctx.Err()
		},
	}
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.UseDelegatedIdentityAuthorizer(authorizer)
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/workload/app")

	_, err := certificateIdentityForTest(t, authority, ctx, sharedZTunnelCaller(), request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("delegated authorization error = %v, want context canceled", err)
	}
	if authorizer.calls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizer.calls)
	}
}

func TestParseSPIFFERejectsMalformedIdentities(t *testing.T) {
	for _, raw := range []string{
		"https://cluster.local/ns/demo/sa/app",
		"spiffe://other.local/ns/demo/sa/app",
		"spiffe://cluster.local/ns//sa/app",
		"spiffe://cluster.local/ns/demo/sa/",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := model.ParsePrincipalURL(parsed, "cluster.local"); err == nil {
			t.Fatalf("malformed identity accepted: %s", raw)
		}
	}
}
