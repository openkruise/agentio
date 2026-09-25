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
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/openkruise/agentio/pkg/model"
)

// SPIFFEAllowList is an exact-match allow-list of SPIFFE IDs whose contents
// can be swapped atomically at runtime without rebuilding the tls.Config:
// VerifyPeer reads the current set on every handshake. VerifyPeer matches
// the WithPeerVerifier signature, so a method value wires it directly:
// WithPeerVerifier(list.VerifyPeer).
//
// An empty allow-list fails closed: every peer is rejected. A control plane
// pushing an empty set must degrade to a detectable availability loss, not a
// silent authorization bypass for any certificate the trust anchors accept.
type SPIFFEAllowList struct {
	// allowed always holds a map[string]struct{}; Set replaces the whole map
	// (copy-on-write) so readers never observe partial state.
	allowed atomic.Value
}

// NewSPIFFEAllowList builds an allow-list from the given SPIFFE IDs. Each ID
// must be a valid spiffe:// URI; leading/trailing whitespace is trimmed.
func NewSPIFFEAllowList(ids ...string) (*SPIFFEAllowList, error) {
	l := &SPIFFEAllowList{}
	if err := l.Set(ids...); err != nil {
		return nil, err
	}
	return l, nil
}

// Set atomically replaces the allow-list contents. On validation error the
// previous contents are kept untouched.
func (l *SPIFFEAllowList) Set(ids ...string) error {
	allowed := make(map[string]struct{}, len(ids))
	for _, raw := range ids {
		id, err := normalizeSPIFFEID(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		allowed[id] = struct{}{}
	}
	l.allowed.Store(allowed)
	return nil
}

// normalizeSPIFFEID checks that id is a well-formed spiffe:// URI and returns
// its canonical form, so configured IDs compare equal to the peer
// certificate's uri.String() regardless of scheme case or encoding variants.
func normalizeSPIFFEID(id string) (string, error) {
	u, err := model.ParseSPIFFEID(id)
	if err != nil {
		return "", fmt.Errorf("certs: %w", err)
	}
	return u.String(), nil
}

// VerifyPeer asserts that the peer's leaf certificate carries a SPIFFE URI
// SAN present in the allow-list. It expects CA-verified chains, which
// ServerTLSConfig guarantees by requiring tls.VerifyClientCertIfGiven or
// stronger alongside WithPeerVerifier; the emptiness guard below is kept
// because the method is exported and callable outside that pipeline.
func (l *SPIFFEAllowList) VerifyPeer(chains [][]*x509.Certificate) error {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return errors.New("certs: no verified chains for peer identity verification")
	}
	// crypto/tls guarantees every verified chain starts with the same leaf.
	leaf := chains[0][0]
	if len(leaf.URIs) == 0 {
		return errors.New("certs: peer certificate has no URI SANs")
	}
	// A zero-value list never went through Set; the nil map fails closed
	// below instead of panicking inside the handshake callback.
	allowed, _ := l.allowed.Load().(map[string]struct{})
	presented := make([]string, 0, len(leaf.URIs))
	for _, uri := range leaf.URIs {
		id := uri.String()
		if _, ok := allowed[id]; ok {
			return nil
		}
		presented = append(presented, id)
	}
	// Report only the peer's own identities, never the allow-list contents.
	return fmt.Errorf("certs: peer SPIFFE ID %v not in allow-list", presented)
}
