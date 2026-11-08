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

package store

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

func BenchmarkStoreSnapshotDuringBulkApply(b *testing.B) {
	const count = 100_000
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("workload-%d", i)
	}
	initial := newSnapshot(b, names...)
	store := New(initial)
	changes := [2][]model.ResourceChange{make([]model.ResourceChange, count), make([]model.ResourceChange, count)}
	for i, old := range initial.List(model.AddressType) {
		updated, err := model.NewResource(old.Key, "", &anypb.Any{TypeUrl: model.AddressType, Value: []byte("updated")}, nil, old.Facts)
		if err != nil {
			b.Fatal(err)
		}
		changes[0][i] = model.ResourceChange{Key: old.Key, New: &old}
		changes[1][i] = model.ResourceChange{Key: old.Key, New: &updated}
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var maximum time.Duration
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				started := time.Now()
				store.Snapshot()
				maximum = max(maximum, time.Since(started))
			}
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if _, err := store.Apply(changes[(i+1)%2]); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	close(stop)
	<-done
	b.ReportMetric(float64(maximum.Nanoseconds()), "snapshot_max_ns")
}
