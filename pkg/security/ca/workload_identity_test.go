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

// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

// Keep the wire OID explicit to catch accidental protocol changes.
var testWorkloadIdentityOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57874, 5, 1}

func TestCertificateSignsAuthorizedSourceOnly(t *testing.T) {
	principal := model.MustServiceAccountPrincipal("demo", "shared")
	request := requestWithCSR(t, principal.String())
	csr, err := parseCertificateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	// Even a signed CSR cannot supply the extension's claims or criticality.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr.ExtraExtensions = []pkix.Extension{{Id: testWorkloadIdentityOID, Critical: true, Value: []byte("forged")}}
	der, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		t.Fatal(err)
	}
	request.Csr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	for _, tc := range []struct {
		name   string
		podUID string
		role   string
	}{
		{"instance a", "pod-a", ""},
		{"instance b with same URI", "pod-b", ""},
		{"principal-only request", "", ""},
		{"gateway", "gateway-uid", attestation.RoleEgressGateway},
		{"attester", "attester-uid", attestation.RoleSandboxAttester},
		{"reserved ext-proc role", "ext-proc-uid", attestation.RoleExtProc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := &fakeDelegatedIdentityAuthorizer{role: tc.role}
			authority := certificateAuthority(t, sharedZTunnelCaller(), authorizer)
			metadata := map[string]any{impersonatedIdentityMetadata: principal.String()}
			var source model.SourceRef
			if tc.podUID != "" {
				source = model.SourceRef{Registry: "kubernetes/test", Key: tc.podUID}
				metadata[targetWorkloadMetadata] = map[string]any{
					"namespace": "demo",
					"name":      "app",
					"role":      "forged-role",
				}
				authorizer.resolved = source
			}
			request.Metadata, err = structpb.NewStruct(metadata)
			if err != nil {
				t.Fatal(err)
			}
			response, err := authority.CreateCertificate(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if got := responseIdentity(t, response); got != principal.String() {
				t.Fatalf("URI SAN = %s, want %s", got, principal.String())
			}
			if authorizer.calls != 1 || authorizer.requested != principal || authorizer.source != source {
				t.Fatalf("authorization received principal=%v source=%v", authorizer.requested, authorizer.source)
			}
			if tc.podUID != "" &&
				(authorizer.workload == nil || authorizer.workload.Namespace != "demo" || authorizer.workload.Name != "app") {
				t.Fatalf("authorization received wrong lookup key: %+v", authorizer.workload)
			}
			block, _ := pem.Decode([]byte(response.CertChain[0]))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, extension := range cert.Extensions {
				if !extension.Id.Equal(testWorkloadIdentityOID) {
					continue
				}
				found = true
				var got attestation.WorkloadIdentity
				err := json.Unmarshal(extension.Value, &got)
				if err != nil || extension.Critical || got.Registry != source.Registry ||
					got.UID != source.Key || got.Role != tc.role {
					t.Fatalf("unexpected source extension: %+v payload=%+v err=%v", extension, got, err)
				}
			}
			if found != (tc.podUID != "") {
				t.Fatalf("source extension present=%v, requested source=%+v", found, source)
			}
		})
	}
}

func TestCertificateTargetWorkloadFailsWithoutDowngrade(t *testing.T) {
	valid := map[string]any{"namespace": "demo", "name": "app"}
	for _, tc := range []struct {
		name        string
		value       any
		denied      bool
		code        codes.Code
		authorizers int
	}{
		{"null", nil, false, codes.Unauthenticated, 0},
		{"string", "pod-a", false, codes.Unauthenticated, 0},
		{"empty object", map[string]any{}, false, codes.Unauthenticated, 0},
		{"source is not a selector", map[string]any{"registry": "kubernetes/test", "key": "pod-a"}, false, codes.Unauthenticated, 0},
		{"missing namespace", map[string]any{"name": "app"}, false, codes.Unauthenticated, 0},
		{"non-string name", map[string]any{"namespace": "demo", "name": 1}, false, codes.Unauthenticated, 0},
		{"empty name", map[string]any{"namespace": "demo", "name": ""}, false, codes.Unauthenticated, 0},
		{"authorization denied", valid, true, codes.Unauthenticated, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := &fakeDelegatedIdentityAuthorizer{
				resolved: model.SourceRef{Registry: "kubernetes/test", Key: "server-pod-uid"},
			}
			if tc.denied {
				authorizer.err = errors.New("source is not owned by caller")
			}
			authority := certificateAuthority(t, peerIdentity("demo", "shared"), authorizer)
			request := requestWithCSR(t)
			metadata, err := structpb.NewStruct(map[string]any{targetWorkloadMetadata: tc.value})
			if err != nil {
				t.Fatal(err)
			}
			request.Metadata = metadata
			response, err := authority.CreateCertificate(t.Context(), request)
			if response != nil || status.Code(err) != tc.code || authorizer.calls != tc.authorizers {
				t.Fatalf("response=%v err=%v authorizer calls=%d", response, err, authorizer.calls)
			}
		})
	}
}

func TestCertificateSourceRequiresAuthorizer(t *testing.T) {
	authority := certificateAuthority(t, peerIdentity("demo", "shared"), nil)
	request := requestWithCSR(t)
	metadata, err := structpb.NewStruct(map[string]any{
		targetWorkloadMetadata: map[string]any{"namespace": "demo", "name": "app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request.Metadata = metadata
	if response, err := authority.CreateCertificate(t.Context(), request); response != nil ||
		status.Code(err) != codes.Unauthenticated {
		t.Fatalf("instance request without authorizer: response=%v err=%v", response, err)
	}
}

func TestSelfRequestSourceBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bound  bool
		denied bool
	}{
		{"bound self", true, false},
		{"unbound self", false, false},
		{"source authorization denied", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := peerIdentity("demo", "app")
			if tc.bound {
				caller.Kubernetes.WorkloadName = "app-pod"
				caller.Kubernetes.WorkloadUID = "pod-a"
			}
			authorizer := &fakeDelegatedIdentityAuthorizer{
				resolved: model.SourceRef{Registry: "kubernetes/test", Key: "pod-a"},
			}
			if tc.denied {
				authorizer.err = errors.New("Pod binding no longer valid")
			}
			authority := certificateAuthority(t, caller, authorizer)
			principal := model.MustServiceAccountPrincipal("demo", "app")
			response, err := authority.CreateCertificate(t.Context(), requestWithCSR(t, principal.String()))
			wantSource := tc.bound
			wantCalls := 0
			if wantSource {
				wantCalls = 1
			}
			if authorizer.calls != wantCalls {
				t.Fatalf("authorization calls=%d, want %d", authorizer.calls, wantCalls)
			}
			if wantSource && authorizer.source != (model.SourceRef{Registry: "kubernetes/test", Key: "pod-a"}) {
				t.Fatalf("authorized source=%+v", authorizer.source)
			}
			if tc.denied {
				if response != nil || status.Code(err) != codes.Unauthenticated {
					t.Fatalf("response=%v err=%v", response, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := responseIdentity(t, response); got != principal.String() {
				t.Fatalf("identity=%s", got)
			}
			block, _ := pem.Decode([]byte(response.CertChain[0]))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, extension := range cert.Extensions {
				if !extension.Id.Equal(testWorkloadIdentityOID) {
					continue
				}
				found = true
				var source attestation.WorkloadIdentity
				err := json.Unmarshal(extension.Value, &source)
				if err != nil || extension.Critical || source.Registry != "kubernetes/test" ||
					source.UID != "pod-a" {
					t.Fatalf("source=%+v critical=%v err=%v", source, extension.Critical, err)
				}
			}
			if found != wantSource {
				t.Fatalf("extension present=%v, want %v", found, wantSource)
			}
		})
	}
}

func TestWorkloadIdentityJSON(t *testing.T) {
	for _, tc := range []struct {
		role string
		want []byte
	}{
		{"", []byte(`{"registry":"r","uid":"u"}`)},
		{"ext-proc", []byte(`{"registry":"r","uid":"u","role":"ext-proc"}`)},
	} {
		ext, err := workloadIdentityExtension(attestation.WorkloadIdentity{Registry: "r", UID: "u", Role: tc.role})
		if err != nil || ext.Critical || !ext.Id.Equal(testWorkloadIdentityOID) || !bytes.Equal(ext.Value, tc.want) {
			t.Fatalf("extension=%+v err=%v", ext, err)
		}
	}
}
