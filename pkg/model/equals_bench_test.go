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

import "testing"

func BenchmarkModelEquals(b *testing.B) {
	b.Run("Workload", func(b *testing.B) {
		benchmarkEquals(
			b,
			func() Workload {
				return Workload{
					UID:       "pod-uid",
					Namespace: "default",
					Name:      "pod",
					Source:    SourceRef{Registry: "kubernetes/test", Key: "pod-uid"},
					Addresses: []string{"10.0.0.1", "2001:db8::1"},
					Labels:    map[string]string{"app": "worker", "version": "v1", "team": "platform"},
					Ready:     true,
				}
			},
			Workload.Equals,
		)
	})
	b.Run("Sandbox", func(b *testing.B) {
		benchmarkEquals(
			b,
			func() Sandbox {
				return Sandbox{UID: "sandbox-uid", Namespace: "default", Attester: &Attester{WorkloadUID: "pod-uid"}}
			},
			Sandbox.Equals,
		)
	})
	b.Run("Service", func(b *testing.B) {
		benchmarkEquals(
			b,
			func() Service {
				return Service{
					Namespace: "default",
					Name:      "api",
					Hostname:  "api.default.svc.cluster.local",
					Addresses: []string{"10.0.0.2", "2001:db8::2"},
					Ports:     []ServicePort{{Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP"}},
					Canonical: true,
				}
			},
			Service.Equals,
		)
	})
}

// Independent allocations model an informer update with unchanged contents,
// avoiding DeepEqual's shortcut for maps and slices sharing the same storage.
func benchmarkEquals[T any](b *testing.B, fixture func() T, equal func(T, T) bool) {
	left, right := fixture(), fixture()
	if !equal(left, right) {
		b.Fatal("fixture must compare equal")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if !equal(left, right) {
			b.Fatal("equality changed")
		}
	}
}
