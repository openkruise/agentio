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

package compiler

import (
	"fmt"
	"runtime"
	"testing"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func BenchmarkBuildWDSAddress(b *testing.B) {
	for _, count := range []int{0, 40, 160, 640} {
		b.Run(fmt.Sprintf("rules=%d", count), func(b *testing.B) {
			input := benchmarkWDSProjection(count)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := buildWDSAddress(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkWDSResourceLifecycle(b *testing.B) {
	for _, rules := range []int{0, 40, 160, 640} {
		input := benchmarkWDSProjection(rules)
		for _, clients := range []int{1, 10, 100} {
			b.Run(fmt.Sprintf("rules=%d/clients=%d", rules, clients), func(b *testing.B) {
				scopes := make([]model.ClientScope, clients)
				for index := range scopes {
					scopes[index] = model.ClientScope{Class: model.ClientAgentioEgress, WorkloadUID: fmt.Sprint(index)}
				}
				b.ReportAllocs()
				for b.Loop() {
					resource, err := buildWDSAddress(input)
					if err != nil {
						b.Fatal(err)
					}
					for _, scope := range scopes {
						if _, err := resource.Encode(scope, model.WorkloadType); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func BenchmarkWDSResourceRetention(b *testing.B) {
	for _, rules := range []int{0, 40, 160, 640} {
		input := benchmarkWDSProjection(rules)
		for _, formats := range []int{0, 1, 2} {
			b.Run(fmt.Sprintf("rules=%d/formats=%d", rules, formats), func(b *testing.B) {
				const count = 2000
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				resources := make([]model.Resource, count)
				for b.Loop() {
					for index := range resources {
						resource, err := buildWDSAddress(input)
						if err != nil {
							b.Fatal(err)
						}
						for format := range formats {
							scope := model.ClientScope{Class: model.ClientAgentioEgress}
							if format == 1 {
								scope.Class = model.ClientEgressGateway
							}
							if _, err := resource.Encode(scope, model.WorkloadType); err != nil {
								b.Fatal(err)
							}
						}
						resources[index] = *resource
					}
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				runtime.KeepAlive(resources)
				runtime.KeepAlive(input)
				b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/count, "retained-B/resource")
			})
		}
	}
}

func benchmarkWDSProjection(rules int) wdsProjection {
	input := wdsProjection{Workload: projectionTestWorkload()}
	if rules > 0 {
		input.SNIPolicy = &extensionsv1.SniTrafficPolicy{}
		for index := range rules {
			input.SNIPolicy.Rules = append(input.SNIPolicy.Rules, &extensionsv1.SniRule{
				Match:  &extensionsv1.SniMatch{Sni: []string{fmt.Sprintf("api-%03d.example.com", index)}},
				Action: extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH,
			})
		}
	}
	return input
}
