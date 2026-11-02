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

package model

import (
	"fmt"

	configsecurity "istio.io/istio/pkg/config/security"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// ValidateUpstreamTLS checks the common TLS configuration accepted by both
// AgentioConfig and Gateway API parameters, without changing caller-owned data.
func ValidateUpstreamTLS(settings *configv1.UpstreamTlsSettings) error {
	const field = "tls.origination"
	minVersion, maxVersion := settings.GetMinProtocolVersion(), settings.GetMaxProtocolVersion()
	if minVersion < configv1.UpstreamTlsSettings_DEFAULT || minVersion > configv1.UpstreamTlsSettings_TLSV1_3 {
		return fmt.Errorf("%s.minProtocolVersion must be DEFAULT, TLSV1_2, or TLSV1_3", field)
	}
	if maxVersion < configv1.UpstreamTlsSettings_DEFAULT || maxVersion > configv1.UpstreamTlsSettings_TLSV1_3 {
		return fmt.Errorf("%s.maxProtocolVersion must be DEFAULT, TLSV1_2, or TLSV1_3", field)
	}
	if minVersion == configv1.UpstreamTlsSettings_DEFAULT {
		minVersion = configv1.UpstreamTlsSettings_TLSV1_2
	}
	if maxVersion == configv1.UpstreamTlsSettings_DEFAULT {
		maxVersion = configv1.UpstreamTlsSettings_TLSV1_3
	}
	if minVersion > maxVersion {
		return fmt.Errorf("%s.minProtocolVersion must not exceed maxProtocolVersion", field)
	}
	seen := make(map[string]bool)
	for j, cipher := range settings.GetCipherSuites() {
		if !configsecurity.ValidCipherSuites.Contains(cipher) {
			return fmt.Errorf("%s.cipherSuites[%d]: unsupported cipher name %q", field, j, cipher)
		}
		if seen[cipher] {
			return fmt.Errorf("%s.cipherSuites[%d]: duplicate cipher %q", field, j, cipher)
		}
		seen[cipher] = true
	}
	return nil
}
