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

package krt

import (
	"fmt"
	"testing"
)

func BenchmarkJoinIndexLookup(b *testing.B) {
	for _, tc := range []struct {
		name        string
		collections int
		size        int
		matches     string
		filtered    bool
	}{
		{"single-128", 1, 128, "all", false},
		{"first-128", 2, 128, "first", false},
		{"last-128", 2, 128, "last", false},
		{"all-128", 2, 128, "all", false},
		{"all-10000", 2, 10000, "all", false},
		{"filtered-10000", 2, 10000, "all", true},
		{"four-all-128", 4, 128, "all", false},
		{"four-sparse-10000", 4, 10000, "sparse", false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for _, unchecked := range []bool{false, true} {
				b.Run(fmt.Sprintf("unchecked=%v", unchecked), func(b *testing.B) {
					opts := []CollectionOption{WithStop(b.Context().Done())}
					if unchecked {
						opts = append(opts, WithJoinUnchecked())
					}
					var sources []Collection[allocationItem]
					for source := range tc.collections {
						values := make([]allocationItem, tc.size)
						for i := range values {
							values[i] = allocationItem{Name: fmt.Sprintf("%d/%d", source, i), Value: i}
						}
						sources = append(sources, NewStaticCollection(nil, values, opts...))
					}
					joined := JoinCollection(sources, opts...)
					if !joined.WaitUntilSynced(b.Context().Done()) {
						b.Fatal("join did not sync")
					}
					index := NewIndex(joined, "selected", func(o allocationItem) []string {
						switch tc.matches {
						case "first":
							if o.Name[0] != '0' {
								return nil
							}
						case "last":
							if o.Name[0] != byte('0'+tc.collections-1) {
								return nil
							}
						case "sparse":
							if o.Value != 0 {
								return nil
							}
						}
						return []string{"selected"}
					})
					var filter func(allocationItem) bool
					want := tc.collections * tc.size
					if tc.matches == "first" || tc.matches == "last" {
						want = tc.size
					}
					if tc.filtered {
						filter = func(o allocationItem) bool { return o.Value == 0 }
					}
					if tc.filtered || tc.matches == "sparse" {
						want = tc.collections
					}
					if got := len(index.LookupFiltered("selected", filter)); got != want {
						b.Fatalf("got %d results, want %d", got, want)
					}
					b.ReportAllocs()
					for b.Loop() {
						index.LookupFiltered("selected", filter)
					}
				})
			}
		})
	}
}

func BenchmarkJoinIndexUpdate(b *testing.B) {
	for _, indexed := range []bool{false, true} {
		b.Run(fmt.Sprintf("indexed=%v", indexed), func(b *testing.B) {
			opts := []CollectionOption{WithStop(b.Context().Done())}
			values := make([]allocationItem, 128)
			for i := range values {
				values[i] = allocationItem{Name: fmt.Sprintf("first/%d", i)}
			}
			first := NewMutableCollection(nil, values, opts...)
			for i := range values {
				values[i].Name = fmt.Sprintf("second/%d", i)
			}
			second := NewStaticCollection(nil, values, opts...)
			joined := JoinCollection([]Collection[allocationItem]{first.AsCollection(), second}, opts...)
			if !joined.WaitUntilSynced(b.Context().Done()) {
				b.Fatal("join did not sync")
			}
			if indexed {
				NewIndex(joined, "value", func(o allocationItem) []string {
					if o.Value%2 == 0 {
						return []string{"even"}
					}
					return []string{"odd"}
				})
			}
			processed := make(chan struct{}, 1)
			registration := joined.RegisterBatch(func([]Event[allocationItem]) { processed <- struct{}{} }, false)
			defer registration.UnregisterHandler()
			value := 0
			b.ReportAllocs()
			for b.Loop() {
				value++
				first.UpdateObject(allocationItem{Name: "first/0", Value: value})
				<-processed
			}
		})
	}
}
