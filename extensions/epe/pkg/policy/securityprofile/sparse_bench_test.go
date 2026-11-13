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

package securityprofile

import (
	"strconv"
	"testing"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

func BenchmarkResolverSparse(b *testing.B) {
	regs := claimAll(b, nil)
	for _, count := range []int{1, 4, 16} {
		b.Run("profiles="+strconv.Itoa(count), func(b *testing.B) {
			profiles := benchMissProfiles(b, regs, count, 8)
			rules := make([]agents.SecurityRule, 8)
			rules[0] = matchAllRule("hit")
			for i := 1; i < len(rules); i++ {
				rules[i] = matchHostRule("miss"+strconv.Itoa(i), "other.example")
			}
			profiles[0] = compile(b, regs, "p0", "ns", "1", rules)
			resolve := NewResolver(benchStore{profiles: profiles}, regs, nil, nil)
			req := testRequest("api.example.com")
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				res, err := resolve(b.Context(), subject.Subject{}, req)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = res
			}
		})
	}
}
