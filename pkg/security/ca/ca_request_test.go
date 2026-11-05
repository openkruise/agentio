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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	securityapi "istio.io/api/security/v1alpha1"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

type staticAuthenticator struct {
	caller model.PeerIdentity
	err    error
}

func (a staticAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	return a.caller, a.err
}

func peerIdentity(namespace, serviceAccount string) model.PeerIdentity {
	return model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{Namespace: namespace, ServiceAccount: serviceAccount},
	}
}

func requestWithCSR(t *testing.T, identities ...string) *securityapi.IstioCertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uris []*url.URL
	for _, identity := range identities {
		parsed, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, parsed)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{},
		URIs:    uris,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &securityapi.IstioCertificateRequest{Csr: string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}))}
}

func setRequestMetadata(t *testing.T, request *securityapi.IstioCertificateRequest, value any) {
	t.Helper()
	metadata, err := structpb.NewStruct(map[string]any{impersonatedIdentityMetadata: value})
	if err != nil {
		t.Fatal(err)
	}
	request.Metadata = metadata
}

func certificateAuthority(t *testing.T, caller model.PeerIdentity, authorizer attestation.DelegatedIdentityAuthorizer) *Authority {
	t.Helper()
	authority := newTestAuthority(t, 24*time.Hour, 8*time.Hour)
	authority.authenticator = staticAuthenticator{caller: caller}
	authority.UseDelegatedIdentityAuthorizer(authorizer)
	return authority
}

func withASCIIWhitespace(value []byte) []byte {
	result := append([]byte(" \t\r\n\v\f"), value...)
	return append(result, []byte(" \t\r\n\v\f")...)
}

func responseIdentity(t *testing.T, response *securityapi.IstioCertificateResponse) string {
	t.Helper()
	if response == nil || len(response.CertChain) == 0 {
		t.Fatal("certificate response has no leaf")
	}
	block, _ := pem.Decode([]byte(response.CertChain[0]))
	if block == nil {
		t.Fatal("certificate response leaf is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.URIs) != 1 {
		t.Fatalf("certificate URI SANs = %d, want 1", len(certificate.URIs))
	}
	return certificate.URIs[0].String()
}

func TestCertificateIdentityUsesExplicitTargetWhenAuthorized(t *testing.T) {
	caller := peerIdentity("demo", "app")
	target := model.MustPrincipal("cluster.local", "workload/app")
	request := requestWithCSR(t, target.String())
	setRequestMetadata(t, request, target.String())
	response, err := certificateAuthority(
		t,
		caller,
		&fakeDelegatedIdentityAuthorizer{},
	).CreateCertificate(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	if got := responseIdentity(t, response); got != target.String() {
		t.Fatalf("certificate identity = %q, want %q", got, target.String())
	}
}

func TestCertificateIdentityUsesAuthorizedImpersonation(t *testing.T) {
	caller := sharedZTunnelCaller()
	target := model.MustPrincipal("cluster.local", "workload/target")
	authorizer := &fakeDelegatedIdentityAuthorizer{}
	request := requestWithCSR(t)
	setRequestMetadata(t, request, target.String())

	response, err := certificateAuthority(t, caller, authorizer).CreateCertificate(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	if got := responseIdentity(t, response); got != target.String() {
		t.Fatalf("certificate identity = %q, want %q", got, target.String())
	}
	if authorizer.calls != 1 || authorizer.caller != caller || authorizer.requested != target {
		t.Fatalf("authorizer call = (%d, %#v, %#v), want (1, %#v, %#v)",
			authorizer.calls, authorizer.caller, authorizer.requested, caller, target)
	}
}

func TestCertificateIdentityRejectsDeniedDelegation(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "untrusted caller", err: errors.New("caller is not a trusted node")},
		{name: "cross-node identity", err: errors.New("target workload is on another node")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := &fakeDelegatedIdentityAuthorizer{err: tc.err}
			request := requestWithCSR(t)
			setRequestMetadata(t, request, "spiffe://cluster.local/workload/target")

			_, err := certificateAuthority(
				t,
				sharedZTunnelCaller(),
				authorizer,
			).CreateCertificate(context.Background(), request)
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("CreateCertificate() code = %s, want %s: %v", status.Code(err), codes.Unauthenticated, err)
			}
			if strings.Contains(err.Error(), tc.err.Error()) || strings.Contains(err.Error(), "spiffe://") {
				t.Fatalf("CreateCertificate() error leaked authorization detail: %v", err)
			}
			if authorizer.calls != 1 {
				t.Fatalf("authorizer calls = %d, want 1", authorizer.calls)
			}
		})
	}
}

func TestCertificateIdentityRejectsCSRConflict(t *testing.T) {
	caller := peerIdentity("demo", "app")
	authorizer := &fakeDelegatedIdentityAuthorizer{}
	request := requestWithCSR(t, "spiffe://cluster.local/ns/demo/sa/other")

	_, err := certificateAuthority(t, caller, authorizer).CreateCertificate(context.Background(), request)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("CreateCertificate() code = %s, want %s: %v", status.Code(err), codes.Unauthenticated, err)
	}
	if authorizer.calls != 0 {
		t.Fatalf("authorizer calls = %d, want 0 for a CSR-only identity", authorizer.calls)
	}
}

func TestCallerPrincipalRequiresKubernetesEvidence(t *testing.T) {
	for _, caller := range []model.PeerIdentity{peerIdentity("", "app"), peerIdentity("demo", "")} {
		authorizer := &fakeDelegatedIdentityAuthorizer{}
		_, err := certificateAuthority(t, caller, authorizer).CreateCertificate(context.Background(), requestWithCSR(t))
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("CreateCertificate() code = %s, want %s: %v", status.Code(err), codes.Unauthenticated, err)
		}
		if authorizer.calls != 0 {
			t.Fatalf("authorizer calls = %d, want 0 for missing Kubernetes evidence", authorizer.calls)
		}
	}
}

func TestCertificateIdentityRejectsMalformedRequest(t *testing.T) {
	caller := peerIdentity("demo", "app")
	callerIdentity := model.MustServiceAccountPrincipal(caller.Kubernetes.Namespace, caller.Kubernetes.ServiceAccount).String()
	tests := []struct {
		name   string
		build  func(*testing.T) *securityapi.IstioCertificateRequest
		status codes.Code
	}{
		{
			name: "multiple URI SANs",
			build: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return requestWithCSR(t, callerIdentity, "spiffe://cluster.local/ns/demo/sa/other")
			},
			status: codes.Unauthenticated,
		},
		{
			name: "invalid SPIFFE metadata",
			build: func(t *testing.T) *securityapi.IstioCertificateRequest {
				request := requestWithCSR(t, callerIdentity)
				setRequestMetadata(t, request, "not-a-spiffe-identity")
				return request
			},
			status: codes.Unauthenticated,
		},
		{
			name: "malformed metadata",
			build: func(t *testing.T) *securityapi.IstioCertificateRequest {
				request := requestWithCSR(t, callerIdentity)
				setRequestMetadata(t, request, 7)
				return request
			},
			status: codes.Unauthenticated,
		},
		{
			name: "multiple metadata identities",
			build: func(t *testing.T) *securityapi.IstioCertificateRequest {
				request := requestWithCSR(t, callerIdentity)
				setRequestMetadata(t, request, []any{callerIdentity, "spiffe://cluster.local/ns/demo/sa/other"})
				return request
			},
			status: codes.Unauthenticated,
		},
		{
			name: "invalid CSR signature",
			build: func(t *testing.T) *securityapi.IstioCertificateRequest {
				request := requestWithCSR(t)
				block, _ := pem.Decode([]byte(request.Csr))
				block.Bytes[len(block.Bytes)-1] ^= 1
				request.Csr = string(pem.EncodeToMemory(block))
				return request
			},
			status: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := certificateAuthority(t, caller, &fakeDelegatedIdentityAuthorizer{}).
				CreateCertificate(context.Background(), tc.build(t))
			if status.Code(err) != tc.status {
				t.Fatalf("CreateCertificate() code = %s, want %s: %v", status.Code(err), tc.status, err)
			}
		})
	}
}

func TestCertificateRequestRequiresOneStrictPEMBlock(t *testing.T) {
	caller := peerIdentity("demo", "app")
	for _, tc := range []struct {
		name     string
		csr      func(string) string
		wantCode codes.Code
	}{
		{name: "prefixed data", csr: func(csr string) string { return "garbage\n" + csr }, wantCode: codes.InvalidArgument},
		{name: "trailing data", csr: func(csr string) string { return csr + "garbage" }, wantCode: codes.InvalidArgument},
		{name: "extra PEM block", csr: func(csr string) string { return csr + csr }, wantCode: codes.InvalidArgument},
		{
			name: "surrounding ASCII whitespace",
			csr: func(csr string) string {
				return string(withASCIIWhitespace([]byte(csr)))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := requestWithCSR(t)
			setRequestMetadata(t, request, "spiffe://cluster.local/workload/app")
			request.Csr = tc.csr(request.Csr)
			_, err := certificateAuthority(
				t,
				caller,
				&fakeDelegatedIdentityAuthorizer{},
			).CreateCertificate(context.Background(), request)
			if got := status.Code(err); got != tc.wantCode {
				t.Fatalf("CreateCertificate() code = %s, want %s: %v", got, tc.wantCode, err)
			}
		})
	}
}

func TestExplicitCertificateSANRequiresAuthorization(t *testing.T) {
	caller := peerIdentity("demo", "shared")
	target := model.MustPrincipal("cluster.local", "workload/shared")
	for _, allow := range []bool{false, true} {
		authorizer := &fakeDelegatedIdentityAuthorizer{}
		if !allow {
			authorizer.err = errors.New("not bound to caller")
		}
		request := requestWithCSR(t, target.String())
		setRequestMetadata(t, request, target.String())
		response, err := certificateAuthority(t, caller, authorizer).CreateCertificate(t.Context(), request)
		if allow {
			if err != nil {
				t.Fatal(err)
			}
			if got := responseIdentity(t, response); got != target.String() {
				t.Fatal(got)
			}
		} else if err == nil {
			t.Fatal("signed unauthorized explicit identity")
		}
	}
	request := requestWithCSR(t, target.String())
	if _, err := certificateAuthority(t, caller, nil).CreateCertificate(t.Context(), request); err == nil {
		t.Fatal("CSR alone selected explicit identity")
	}
}

func TestExplicitCertificateRequiresConfiguredAuthorizer(t *testing.T) {
	caller := peerIdentity("demo", "app")
	request := requestWithCSR(t)
	setRequestMetadata(t, request, "spiffe://cluster.local/workload/app")
	if _, err := certificateAuthority(t, caller, nil).CreateCertificate(t.Context(), request); err == nil {
		t.Fatal("explicit issuance bypassed a missing authorizer")
	}
}
