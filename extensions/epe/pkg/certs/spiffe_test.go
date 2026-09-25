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
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"testing"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs/certstest"
	"github.com/openkruise/agentio/pkg/model"
)

// chainsFor builds the [][]*x509.Certificate shape crypto/tls hands to
// VerifyPeerCertificate for a leaf issued by the test CA.
func chainsFor(t *testing.T, ca *certstest.CA, spec certstest.LeafSpec) [][]*x509.Certificate {
	t.Helper()
	_, leaf := ca.Issue(t, spec)
	return [][]*x509.Certificate{{leaf, ca.Cert}}
}

func TestSPIFFEAllowListValidation(t *testing.T) {
	tests := []struct {
		name        string
		ids         []string
		expectError string
	}{
		{
			name: "valid single ID is accepted",
			ids:  []string{"spiffe://cluster.local/ns/default/sa/envoy"},
		},
		{
			name: "valid IDs with surrounding whitespace are accepted",
			ids:  []string{"  spiffe://cluster.local/ns/default/sa/envoy  "},
		},
		{
			name: "empty list is accepted (fail-closed at verification time)",
			ids:  nil,
		},
		{
			name:        "empty string is rejected",
			ids:         []string{""},
			expectError: "invalid SPIFFE ID",
		},
		{
			name:        "whitespace-only string is rejected",
			ids:         []string{"   "},
			expectError: "invalid SPIFFE ID",
		},
		{
			name:        "non-spiffe scheme is rejected",
			ids:         []string{"https://cluster.local/ns/default/sa/envoy"},
			expectError: "invalid SPIFFE ID",
		},
		{
			name:        "missing trust domain is rejected",
			ids:         []string{"spiffe:///ns/default/sa/envoy"},
			expectError: "invalid SPIFFE ID",
		},
		{
			name:        "garbage is rejected",
			ids:         []string{"not a uri at all"},
			expectError: "invalid SPIFFE ID",
		},
		{
			name:        "one invalid ID rejects the whole set",
			ids:         []string{"spiffe://cluster.local/ns/default/sa/envoy", "bogus"},
			expectError: "invalid SPIFFE ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSPIFFEAllowList(tt.ids...)
			if tt.expectError != "" {
				mustErrorContains(t, err, tt.expectError)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSPIFFEValidationAcrossTLSRoles(t *testing.T) {
	for _, tt := range []struct {
		id    string
		valid bool
	}{
		{id: "spiffe://cluster.local/ns/system/sa/epe", valid: true},
		{id: "spiffe://external.example/services/credential-provider", valid: true},
		{id: "https://cluster.local/service"},
		{id: "spiffe:///service"},
		{id: "spiffe://cluster.local"},
		{id: "spiffe://user@cluster.local/service"},
		{id: "spiffe://cluster.local:443/service"},
		{id: "spiffe://cluster.local:/service"},
		{id: "spiffe://cluster.local/service?name=epe"},
		{id: "spiffe://cluster.local/service?"},
		{id: "spiffe://cluster.local/service#epe"},
		{id: "spiffe://cluster.local/service#"},
	} {
		t.Run(tt.id, func(t *testing.T) {
			_, epeErr := NewSPIFFEAllowList(tt.id)
			gatewayErr := model.ValidateExtProcTLS(&configv1.ExtProcTLSSettings{
				Mode:          configv1.ExtProcTLSSettings_MUTUAL,
				PeerSpiffeIds: []string{tt.id},
			})
			if (epeErr == nil) != tt.valid || (gatewayErr == nil) != tt.valid {
				t.Fatalf("valid=%v: EPE error=%v, gateway error=%v", tt.valid, epeErr, gatewayErr)
			}
		})
	}
}

func TestSPIFFEAllowListVerifyPeer(t *testing.T) {
	ca := certstest.New(t)
	const envoyID = "spiffe://cluster.local/ns/default/sa/envoy"
	const otherID = "spiffe://cluster.local/ns/other/sa/other"

	tests := []struct {
		name        string
		allowed     []string
		chains      [][]*x509.Certificate
		expectError string
	}{
		{
			name:    "matching SPIFFE ID is accepted",
			allowed: []string{envoyID},
			chains:  chainsFor(t, ca, certstest.LeafSpec{Serial: 300, URIs: []string{envoyID}}),
		},
		{
			name:    "match against multi-entry allow-list is accepted",
			allowed: []string{otherID, envoyID},
			chains:  chainsFor(t, ca, certstest.LeafSpec{Serial: 301, URIs: []string{envoyID}}),
		},
		{
			name:    "match on second URI SAN is accepted",
			allowed: []string{envoyID},
			chains:  chainsFor(t, ca, certstest.LeafSpec{Serial: 302, URIs: []string{otherID, envoyID}}),
		},
		{
			// An upper-case scheme in the configuration must still match the
			// peer's canonical uri.String() form.
			name:    "upper-case scheme is normalized and accepted",
			allowed: []string{"SPIFFE://cluster.local/ns/default/sa/envoy"},
			chains:  chainsFor(t, ca, certstest.LeafSpec{Serial: 340, URIs: []string{envoyID}}),
		},
		{
			name:        "non-matching SPIFFE ID is rejected",
			allowed:     []string{envoyID},
			chains:      chainsFor(t, ca, certstest.LeafSpec{Serial: 303, URIs: []string{otherID}}),
			expectError: "not in allow-list",
		},
		{
			name:        "leaf without URI SANs is rejected",
			allowed:     []string{envoyID},
			chains:      chainsFor(t, ca, certstest.LeafSpec{Serial: 304, DNSNames: []string{"envoy.local"}}),
			expectError: "no URI SANs",
		},
		{
			name:        "empty allow-list rejects every peer",
			allowed:     nil,
			chains:      chainsFor(t, ca, certstest.LeafSpec{Serial: 305, URIs: []string{envoyID}}),
			expectError: "not in allow-list",
		},
		{
			name:        "empty chains fail closed",
			allowed:     []string{envoyID},
			chains:      nil,
			expectError: "no verified chains",
		},
		{
			name:        "chain with empty first entry fails closed",
			allowed:     []string{envoyID},
			chains:      [][]*x509.Certificate{{}},
			expectError: "no verified chains",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := NewSPIFFEAllowList(tt.allowed...)
			if err != nil {
				t.Fatalf("NewSPIFFEAllowList: %v", err)
			}
			err = list.VerifyPeer(tt.chains)
			if tt.expectError != "" {
				mustErrorContains(t, err, tt.expectError)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSPIFFEAllowListSet(t *testing.T) {
	ca := certstest.New(t)
	const oldID = "spiffe://cluster.local/ns/default/sa/old"
	const newID = "spiffe://cluster.local/ns/default/sa/new"
	oldChains := chainsFor(t, ca, certstest.LeafSpec{Serial: 310, URIs: []string{oldID}})
	newChains := chainsFor(t, ca, certstest.LeafSpec{Serial: 311, URIs: []string{newID}})

	list, err := NewSPIFFEAllowList(oldID)
	if err != nil {
		t.Fatalf("NewSPIFFEAllowList: %v", err)
	}
	if err := list.VerifyPeer(oldChains); err != nil {
		t.Fatalf("old identity must verify before Set: %v", err)
	}
	if err := list.VerifyPeer(newChains); err == nil {
		t.Fatal("new identity must not verify before Set")
	}

	// The dynamic-reload contract: after Set, the old identity is rejected
	// and the new one accepted, with no tls.Config rebuild.
	if err := list.Set(newID); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := list.VerifyPeer(oldChains); err == nil {
		t.Error("old identity must be rejected after Set")
	}
	if err := list.VerifyPeer(newChains); err != nil {
		t.Errorf("new identity must verify after Set: %v", err)
	}

	// A failed Set must keep the previous contents untouched.
	if err := list.Set("bogus"); err == nil {
		t.Fatal("Set with an invalid ID must fail")
	}
	if err := list.VerifyPeer(newChains); err != nil {
		t.Errorf("new identity must still verify after a failed Set: %v", err)
	}
}

func TestSPIFFEAllowListConcurrency(t *testing.T) {
	ca := certstest.New(t)
	const id = "spiffe://cluster.local/ns/default/sa/envoy"
	chains := chainsFor(t, ca, certstest.LeafSpec{Serial: 320, URIs: []string{id}})

	list, err := NewSPIFFEAllowList(id)
	if err != nil {
		t.Fatalf("NewSPIFFEAllowList: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				// t.Errorf (not Fatalf): t.FailNow must not be called from
				// non-test goroutines.
				if err := list.Set(id); err != nil {
					t.Errorf("Set: %v", err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				// The set always contains id, so verification must succeed
				// regardless of interleaving.
				if err := list.VerifyPeer(chains); err != nil {
					t.Errorf("VerifyPeer: %v", err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestSPIFFEAllowListZeroValueFailsClosed(t *testing.T) {
	ca := certstest.New(t)
	const id = "spiffe://cluster.local/ns/default/sa/envoy"
	chains := chainsFor(t, ca, certstest.LeafSpec{Serial: 341, URIs: []string{id}})

	var list SPIFFEAllowList
	err := list.VerifyPeer(chains)
	if err == nil {
		t.Fatal("zero-value allow-list must reject every peer")
	}
	if !strings.Contains(err.Error(), "not in allow-list") {
		t.Errorf("error %q does not contain %q", err.Error(), "not in allow-list")
	}
}

func TestSPIFFEHandshake(t *testing.T) {
	// End-to-end inbound mTLS pipeline with an Istio-shaped client
	// certificate: URI SAN only, no DNS SAN.
	const envoyID = "spiffe://cluster.local/ns/default/sa/envoy"
	const strangerID = "spiffe://cluster.local/ns/default/sa/stranger"

	tests := []struct {
		name        string
		clientID    string
		expectError string
	}{
		{
			name:     "client with allow-listed SPIFFE ID succeeds",
			clientID: envoyID,
		},
		{
			name:        "client with unlisted SPIFFE ID is rejected",
			clientID:    strangerID,
			expectError: "not in allow-list",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := certstest.New(t)
			serverCert, serverLeaf := ca.Issue(t, certstest.LeafSpec{Serial: 330})
			clientCert, _ := ca.Issue(t, certstest.LeafSpec{
				Serial:      331,
				URIs:        []string{tt.clientID},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})

			list, err := NewSPIFFEAllowList(envoyID)
			if err != nil {
				t.Fatalf("NewSPIFFEAllowList: %v", err)
			}
			serverCfg, err := ServerTLSConfig(
				&staticProvider{cert: &serverCert, roots: ca.Pool},
				WithClientAuth(tls.RequireAndVerifyClientCert),
				WithPeerVerifier(list.VerifyPeer),
			)
			if err != nil {
				t.Fatalf("ServerTLSConfig: %v", err)
			}
			clientCfg, err := ClientTLSConfig(
				&staticProvider{cert: &clientCert, roots: ca.Pool},
				WithPeerVerifier(pinLeaf(serverLeaf)),
			)
			if err != nil {
				t.Fatalf("ClientTLSConfig: %v", err)
			}

			_, err = doHandshake(t, serverCfg, clientCfg)
			if tt.expectError != "" {
				mustErrorContains(t, err, tt.expectError)
				return
			}
			if err != nil {
				t.Fatalf("unexpected handshake error: %v", err)
			}
		})
	}
}
