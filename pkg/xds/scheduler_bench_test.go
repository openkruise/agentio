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

package xds

import (
	"context"
	"fmt"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func BenchmarkPushScheduler(b *testing.B) {
	oldResource := addressResource(b, "workload-a", "old")
	newResource := addressResource(b, "workload-a", "new")
	update := updateFromChanges(b, []model.ResourceChange{{Key: oldResource.Key, Old: &oldResource, New: &newResource}})

	for _, clientCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("connections=%d", clientCount), func(b *testing.B) {
			scheduler := NewPushScheduler(clientCount)
			defer scheduler.Close()
			connections := make([]*pushConnection, clientCount)
			for client := range connections {
				connections[client] = newPushConnection(context.Background())
			}
			b.ReportAllocs()
			b.ReportMetric(float64(clientCount), "connections/op")
			b.ResetTimer()
			for range b.N {
				for _, connection := range connections {
					scheduler.Enqueue(connection, update)
				}
				for range connections {
					push := scheduler.Next(context.Background())
					if push == nil {
						b.Fatal("scheduler closed before delivering all clients")
					}
					scheduler.Done(push)
				}
			}
		})
	}
}

// Each producer owns a connection with pending work. Repeated publications
// exercise merge contention without depending on generator or network speed.
func BenchmarkPushSchedulerConcurrentMerge(b *testing.B) {
	for _, size := range []int{1, 512} {
		b.Run(fmt.Sprintf("changes=%d", size), func(b *testing.B) {
			changes := make([]model.ResourceChange, size)
			for i := range changes {
				name := fmt.Sprintf("workload-%d", i)
				older := addressResource(b, name, "old")
				newer := addressResource(b, name, "new")
				changes[i] = model.ResourceChange{Key: newer.Key, Old: &older, New: &newer}
			}
			update := updateFromChanges(b, changes)
			scheduler := NewPushScheduler(1)
			defer scheduler.Close()
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				connection := newPushConnection(context.Background())
				scheduler.Enqueue(connection, update)
				for pb.Next() {
					scheduler.Enqueue(connection, update)
				}
			})
		})
	}
}
