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

package agentio

import (
	"testing"
)

// When ENABLE_SECURITY_PROFILE_STATUS is off, initSecurityProfileStatus never
// runs, so the collections container stays nil. Leader election still toggles
// this method on every lock transition, so it must tolerate that.
func TestSetSecurityProfileStatusWriteWithFeatureDisabled(t *testing.T) {
	c := &Controller{} // spStatusCollections is nil

	// Any order, any number of times: no panic.
	c.SetSecurityProfileStatusWrite(false)
	c.SetSecurityProfileStatusWrite(true)
	c.SetSecurityProfileStatusWrite(true)
	c.SetSecurityProfileStatusWrite(false)
}
