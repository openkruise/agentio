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

package features

import (
	"fmt"
	"time"

	"istio.io/istio/pkg/env"
)

var (
	MITMCRLOrigin = env.Register(
		"AGENTIO_MITM_CRL_ORIGIN",
		"",
		"HTTP origin advertised in newly issued MITM certificates. Empty disables CRL publication.",
	).Get()
	MITMCASecretName = env.Register(
		"AGENTIO_MITM_CA_SECRET_NAME",
		"agentio-mitm-ca",
		"Secret holding the CA that signs on-demand domain certificates. SECRET mode reads it; SELF_SIGN mode owns it.",
	).Get()
	MITMCASecretNamespace = env.Register(
		"AGENTIO_MITM_CA_SECRET_NAMESPACE",
		"",
		"Namespace of the MITM CA Secret. Empty uses the control-plane root namespace.",
	).Get()
	MITMSignMode = env.Register(
		"AGENTIO_MITM_SIGN_MODE",
		"SELF_SIGN",
		"MITM CA ownership mode: SECRET reads an externally managed Secret; SELF_SIGN persists a control-plane-managed self-signed CA.",
	).Get()
	MITMRootLifetime = env.Register(
		"AGENTIO_MITM_ROOT_LIFETIME",
		10*365*24*time.Hour,
		"Validity of the control-plane-managed root CA in MITM SELF_SIGN mode.",
	).Get()
	MITMRootRenewBefore = env.Register(
		"AGENTIO_MITM_ROOT_RENEW_BEFORE",
		365*24*time.Hour,
		"How long before expiry the control-plane-managed MITM root CA is renewed in SELF_SIGN mode.",
	).Get()
	MITMRotationCheckInterval = env.Register(
		"AGENTIO_MITM_ROTATION_CHECK_INTERVAL",
		time.Hour,
		"How often each replica checks whether the control-plane-managed MITM root CA needs CAS renewal.",
	).Get()
	MITMLeafLifetime = env.Register(
		"AGENTIO_MITM_LEAF_LIFETIME",
		15*time.Minute,
		"Validity of on-demand domain certificates.",
	).Get()
	MITMResourceTTL = env.Register(
		"AGENTIO_MITM_RESOURCE_TTL",
		15*time.Minute,
		"Maximum SDS residency from certificate signing time; replay never extends this deadline.",
	).Get()
	MITMRenewBefore = env.Register(
		"AGENTIO_MITM_RENEW_BEFORE",
		time.Minute,
		"How long before expiry SDS TTL removes an on-demand certificate; new demand re-issues it.",
	).Get()
	MITMCacheMaxAge = env.Register(
		"AGENTIO_MITM_CACHE_MAX_AGE",
		7*24*time.Hour,
		"Maximum local issuer cache age; eviction does not remove certificates from gateways.",
	).Get()
	MITMCacheMaxEntries = env.Register(
		"AGENTIO_MITM_CACHE_MAX_ENTRIES",
		10000,
		"Maximum number of on-demand certificates the cache may hold; the entry closest to eviction makes room when full.",
	).Get()
	MITMSignConcurrency = env.Register(
		"AGENTIO_MITM_SIGN_CONCURRENCY",
		8,
		"Maximum number of on-demand certificates signed concurrently.",
	).Get()
)

func validateMITM() error {
	switch MITMSignMode {
	case "SECRET":
	case "SELF_SIGN":
		if MITMRootLifetime <= 0 || MITMRootRenewBefore <= 0 || MITMRootRenewBefore >= MITMRootLifetime ||
			MITMRotationCheckInterval <= 0 {
			return fmt.Errorf("invalid self-signed MITM CA rotation durations")
		}
		if MITMRootRenewBefore <= MITMLeafLifetime {
			return fmt.Errorf("MITM root renew-before must exceed the MITM leaf certificate lifetime")
		}
	default:
		return fmt.Errorf("unsupported MITM sign mode %q", MITMSignMode)
	}
	if MITMResourceTTL <= 0 || MITMLeafLifetime <= 0 || MITMRenewBefore <= 0 || MITMRenewBefore >= MITMLeafLifetime ||
		MITMCacheMaxAge <= 0 {
		return fmt.Errorf("invalid MITM certificate durations")
	}
	if MITMCacheMaxEntries <= 0 || MITMSignConcurrency <= 0 {
		return fmt.Errorf("MITM cache entry limit and signing concurrency must be positive")
	}
	return nil
}
