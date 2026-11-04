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

package kubernetes

import (
	"fmt"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	"github.com/openkruise/agentio/pkg/model"
)

// normalizeEgressServiceEntries validates data at the Kubernetes source
// boundary so invalid updates retain the last-known-good value.
func normalizeEgressServiceEntries(gateways []*configv1.EgressGateway) error {
	for gatewayIndex, gateway := range gateways {
		if gateway == nil {
			continue
		}
		normalized, err := model.NormalizeEgressGatewayServiceEntries(gateway)
		if err != nil {
			return fmt.Errorf("egressGateways[%d]: %w", gatewayIndex, err)
		}
		gateways[gatewayIndex] = normalized
	}
	return nil
}
