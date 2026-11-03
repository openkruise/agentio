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
package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// BenchmarkEvalRequestCycle includes both phases so moving work between them
// does not look like a performance improvement or regression by itself.
func BenchmarkEvalRequestCycle(b *testing.B) {
	for _, shape := range []benchShape{shapePassthrough, shapeMutated, shapeNeedBody} {
		for _, axis := range benchAxes {
			b.Run(fmt.Sprintf("%s/units=%d/filters=%d", shape, axis.units, axis.filters), func(b *testing.B) {
				regs := benchChain(b, shape, axis.filters)
				units := benchUnits(axis.units, len(regs))
				e := NewEngine(regs, 0)
				ctx := context.Background()
				body := filter.Body{Bytes: []byte(`{"jsonrpc":"2.0","method":"tools/call"}`), Complete: true}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					st := &filter.Stream{StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()}}
					res, err := e.EvalRequestHeaders(ctx, st, units)
					if err != nil {
						b.Fatal(err)
					}
					if res.NeedsBody() {
						result, err := e.EvalRequestBody(ctx, st, res, body)
						if err != nil {
							b.Fatal(err)
						}
						benchSink = result
					} else {
						benchSink = res
					}
				}
			})
		}
	}
}
