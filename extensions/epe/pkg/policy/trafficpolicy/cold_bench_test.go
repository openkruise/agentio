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

package trafficpolicy

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/model"
)

// Fetch publishes immediately: measures local dependency sequencing, not ADS RTT.
func BenchmarkColdDependencySequence(b *testing.B) {
	for _, n := range []int{1, 3, 10} {
		b.Run(fmt.Sprintf("Policies%d", n), func(b *testing.B) {
			names := make([]string, n)
			for i := range n {
				names[i] = fmt.Sprintf("p%d", i)
			}
			ref, err := anypb.New(&ext.PolicyReference{TypeUrl: model.TrafficPolicyType, ResourceNames: names})
			if err != nil {
				b.Fatal(err)
			}
			w := &workload.Workload{
				Name:       "pod",
				Namespace:  "ns",
				Extensions: []*workload.Extension{{Name: "traffic-policy-reference", Config: ref}},
			}
			b.ReportAllocs()
			for b.Loop() {
				f := &fakeStore{
					types:     []store.Type{store.Workload, store.TrafficPolicy},
					resources: map[store.Key]store.Resource{},
					ready:     true,
				}
				calls := 0
				f.fetch = func(k store.Key) {
					calls++
					if k.Type == store.Workload {
						f.put(k.Type, k.Name, w)
					} else {
						f.put(k.Type, k.Name, &sec.TrafficPolicy{})
					}
				}
				a := testAggregate(f)
				if _, err := lookup(
					context.Background(),
					a,
					subject.Subject{Workload: subject.Workload{Name: "pod", Namespace: "ns"}},
				); err != nil {
					b.Fatal(err)
				}
				if calls != n+1 {
					b.Fatalf("fetches=%d want=%d", calls, n+1)
				}
			}
		})
	}
}
