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

import (
	"errors"
	"strconv"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
)

func BenchmarkProfileAdmission(b *testing.B) {
	for _, count := range []int{1, 1000, 50_000} {
		for _, action := range []string{"reject", "recover"} {
			b.Run(strconv.Itoa(count)+"/"+action, func(b *testing.B) {
				s := NewXDSStore()
				for i := range count {
					s.degraded.rejected(
						profileKey{match: securityprofile.MatchSandbox, namespace: "ns", name: strconv.Itoa(i)},
						true,
					)
				}
				meta := securityprofile.Meta{Match: securityprofile.MatchSandbox, Namespace: "ns", Name: "target"}
				failure := errors.New("invalid profile")
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if action == "recover" {
						s.degraded.rejected(keyFor(meta), true)
						s.ObserveAdmission(meta, true, nil)
					} else {
						s.ObserveAdmission(meta, true, failure)
					}
				}
			})
		}
	}
}
