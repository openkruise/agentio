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

package constants

import "strings"

// AgentioUDPOutput is the outbound UDP capture chain managed by the init container.
const AgentioUDPOutput = "AGENTIO_UDP_OUTPUT"

// IsManagedChain identifies chains owned by this rule builder and its cleanup.
// Match the Agentio chain exactly to leave other components' chains untouched.
func IsManagedChain(chain string) bool {
	return strings.HasPrefix(chain, "ISTIO_") || chain == AgentioUDPOutput
}
