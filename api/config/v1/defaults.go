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

package configv1

// MandatoryEgressDeniedCIDRs returns the destination restrictions shared by EPE
// and the gateway's dynamic forward proxy. Private service networks remain
// operator-owned. Each caller receives its own slice.
func MandatoryEgressDeniedCIDRs() []string {
	return []string{
		"127.0.0.0/8", "::1/128", // Loopback.
		"0.0.0.0/32", "::/128", // Unspecified.
		"169.254.0.0/16", "fe80::/10", // Link-local.
	}
}
