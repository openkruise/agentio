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

package mitm

import (
	"context"
	"time"

	"github.com/openkruise/agentio/pkg/krt"
)

type SignedCertificate struct {
	CertificateChain []byte
	PrivateKey       []byte
	NotAfter         time.Time
	SignedAt         time.Time
	SignerRevision   string
}

type DomainCertificateSigner interface {
	SignDNS(context.Context, string, time.Duration) (SignedCertificate, error)
}

// SignerState is the committed signing generation. A nil singleton value means
// signing is unavailable; Revision identifies every certificate produced by
// the active generation.
type SignerState struct {
	Revision string
}

func (SignerState) ResourceName() string {
	return "domain-certificate-signer"
}

func (s SignerState) Equals(other SignerState) bool {
	return s.Revision == other.Revision
}

// DomainSignerSource keeps signing behavior and its observable state together
// at the composition seam while exposing the KRT singleton directly. State
// must be published only after the matching signing generation is ready; a nil
// state means SignDNS is unavailable, and every returned certificate must carry
// the revision of the signing generation that produced it.
type DomainSignerSource struct {
	Signer DomainCertificateSigner
	State  krt.Singleton[SignerState]
	// TrustBundle explicitly exposes public CA material for client trust distribution.
	// Optional for signers whose trust is provided via configured CA sources instead.
	TrustBundle krt.Singleton[TrustBundle]
}

// TrustBundle is public CA material for an accepted MITM signing generation.
// It never contains signing keys; nil means this source is currently unavailable.
type TrustBundle struct {
	PEM      string
	Revision string
}

// ResourceName identifies the public MITM trust singleton.
func (TrustBundle) ResourceName() string { return "mitm-trust-bundle" }

// Equals compares public material and its signing revision.
func (b TrustBundle) Equals(other TrustBundle) bool { return b == other }

// CertificateGeneration changes whenever cached SDS certificate visibility
// changes and consumers need to regenerate Secret resources.
type CertificateGeneration struct {
	Generation uint64
}

func (CertificateGeneration) ResourceName() string {
	return "on-demand-certificates"
}

func (g CertificateGeneration) Equals(other CertificateGeneration) bool {
	return g.Generation == other.Generation
}

type OnDemandOptions struct {
	LeafLifetime time.Duration
	RenewBefore  time.Duration
	CacheMaxAge  time.Duration
	// CacheMaxEntries bounds cache size; when full the entry closest to eviction is replaced. Non-positive selects the default.
	CacheMaxEntries int
	// SignConcurrency bounds concurrent SignDNS calls; non-positive selects the default.
	SignConcurrency int
	KrtOptions      krt.OptionsBuilder
}
