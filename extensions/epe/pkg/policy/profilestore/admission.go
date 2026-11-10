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

package profilestore

import "github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"

// ObserveAdmission records a rejected candidate without replacing the accepted
// source. Collection updates own inputs status and effective policy publication.
func (s *XDSStore) ObserveAdmission(meta securityprofile.Meta, retained bool, err error) {
	key := keyFor(meta)
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.degraded.publish()
	if err != nil {
		profileCompileFailuresTotal.WithLabelValues(key.scope()).Inc()
		s.degraded.rejected(key, retained)
		if s.rejections == nil {
			s.rejections = make(map[profileKey]bool)
		}
		s.rejections[key] = true
	} else {
		delete(s.rejections, key)
		s.degraded.clearRejection(key)
	}
}
