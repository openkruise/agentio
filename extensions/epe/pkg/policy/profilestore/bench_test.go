// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package profilestore

import (
	"strconv"
	"testing"
)

// benchSink defeats dead-code elimination.
var benchSink any

// benchPodLabels is the label set every request is matched against.
var benchPodLabels = map[string]string{
	"app":                          "agent",
	"tier":                         "web",
	"version":                      "v2",
	"app.kubernetes.io/managed-by": "kruise",
}

// BenchmarkMatches measures the per-request profile lookup: every profile in
// the pod's namespace, plus every cluster-scoped one, has its selector
// evaluated on every request.
//
// The arms vary what the selectors do rather than only how many there are:
//   - select=hit: every profile matches, so the result slice grows to full
//     length and the caller gets maximum downstream work.
//   - select=miss: no profile matches, which is the common case for a pod
//     governed by one profile out of many in a busy namespace.
func BenchmarkMatches(b *testing.B) {
	for _, n := range []int{1, 10, 50} {
		for _, hit := range []bool{true, false} {
			outcome := "hit"
			if !hit {
				outcome = "miss"
			}
			b.Run("profiles="+strconv.Itoa(n)+"/select="+outcome, func(b *testing.B) {
				store := MakeFakeStore()
				for i := 0; i < n; i++ {
					sel := map[string]string{"app": "agent"}
					if !hit {
						// A key the pod does not carry, so Matches walks the
						// whole selector before rejecting.
						sel = map[string]string{"app": "other-" + strconv.Itoa(i)}
					}
					store.ProfileSet(newTestProfile("p"+strconv.Itoa(i), "default", sel))
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = store.Matches("", "default", benchPodLabels)
				}
			})
		}
	}
}

// BenchmarkMatches_GlobalAndNamespaced covers the path where both the
// cluster- and namespace-scoped runs contribute matches, which is the only
// case that pays the merge re-sort.
func BenchmarkMatches_GlobalAndNamespaced(b *testing.B) {
	for _, n := range []int{2, 10} {
		b.Run("each="+strconv.Itoa(n), func(b *testing.B) {
			store := MakeFakeStore()
			for i := 0; i < n; i++ {
				store.ProfileSet(newTestProfile("ns"+strconv.Itoa(i), "default",
					map[string]string{"app": "agent"}))
				store.GlobalProfileSet(newTestGlobalProfile("g"+strconv.Itoa(i),
					map[string]string{"tier": "web"}))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSink = store.Matches("", "default", benchPodLabels)
			}
		})
	}
}
