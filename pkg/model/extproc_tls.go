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

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// ValidateExtProcTLS checks the processor's transport and exact peer identities.
func ValidateExtProcTLS(settings *configv1.ExtProcTLSSettings) error {
	if settings == nil {
		return nil
	}
	switch settings.GetMode() {
	case configv1.ExtProcTLSSettings_DISABLE:
		if len(settings.GetPeerSpiffeIds()) != 0 {
			return fmt.Errorf("extProc.tls.peerSpiffeIDs requires MUTUAL mode")
		}
	case configv1.ExtProcTLSSettings_MUTUAL:
		if len(settings.GetPeerSpiffeIds()) == 0 {
			return fmt.Errorf("extProc.tls.peerSpiffeIDs must not be empty in MUTUAL mode")
		}
		for i, id := range settings.GetPeerSpiffeIds() {
			uri, err := ParseSPIFFEID(id)
			if err != nil {
				return fmt.Errorf("extProc.tls.peerSpiffeIDs[%d]: %w", i, err)
			}
			if uri.String() != id {
				return fmt.Errorf(
					"extProc.tls.peerSpiffeIDs[%d]: SPIFFE ID %q must use canonical form %q",
					i,
					id,
					uri.String(),
				)
			}
		}
	default:
		return fmt.Errorf("extProc.tls.mode must be DISABLE or MUTUAL")
	}
	return nil
}
