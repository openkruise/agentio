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
	"fmt"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/openkruise/agentio/pkg/model"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// Measure generic gateway delivery and ACK processing over precompiled snapshots.
func BenchmarkGatewayDeltaACK(b *testing.B) {
	for _, size := range []int{10, 1000} {
		for _, changed := range []int{1, size} {
			b.Run(fmt.Sprintf("resources=%d/changed=%d", size, changed), func(b *testing.B) {
				benchmarkGatewayDeltaACK(b, size, changed, 1, false)
			})
		}
	}
}

func BenchmarkGatewayDelayedACK(b *testing.B) {
	for _, changed := range []int{1, 1000} {
		for _, ackEvery := range []int{8, 64} {
			b.Run(fmt.Sprintf("resources=1000/changed=%d/ack_every=%d", changed, ackEvery), func(b *testing.B) {
				benchmarkGatewayDeltaACK(b, 1000, changed, ackEvery, false)
			})
		}
	}
}

func BenchmarkGatewayDelayedDistinctACK(b *testing.B) {
	for _, ackEvery := range []int{8, 64} {
		b.Run(fmt.Sprintf("resources=1000/ack_every=%d", ackEvery), func(b *testing.B) {
			benchmarkGatewayDeltaACK(b, 1000, 1, ackEvery, true)
		})
	}
}

func benchmarkGatewayDeltaACK(b *testing.B, size, changed, ackEvery int, distinct bool) {
	original := make([]model.Resource, size)
	next := make([]model.Resource, size)
	names := make([]string, size)
	for i := range size {
		names[i] = fmt.Sprintf("route-%04d", i)
		original[i] = gatewayResourceOfType(b, model.RouteType, "demo/egress", names[i], "before")
		next[i] = original[i]
		if i < changed {
			next[i] = gatewayResourceOfType(b, model.RouteType, "demo/egress", names[i], "after")
		}
	}
	before, err := model.NewResourceSet(original)
	if err != nil {
		b.Fatal(err)
	}
	after, err := model.NewResourceSet(next)
	if err != nil {
		b.Fatal(err)
	}
	snapshots := []model.ResourceSet{after, before}
	updates := []xdsstore.Update{
		updateBetween(before, after, before.Diff(after)),
		updateBetween(after, before, after.Diff(before)),
	}
	if distinct {
		snapshots, updates = nil, nil
		current := before
		for i := range 2 * ackEvery {
			resource := original[i%ackEvery]
			old, _ := current.Get(resource.Key)
			if i < ackEvery {
				resource = gatewayResourceOfType(b, model.RouteType, "demo/egress", resource.XDSName, "after")
			}
			change := model.ResourceChange{Key: resource.Key, Old: &old, New: &resource}
			nextSnapshot, _, err := current.Apply([]model.ResourceChange{change})
			if err != nil {
				b.Fatal(err)
			}
			snapshots = append(snapshots, nextSnapshot)
			updates = append(updates, updateBetween(current, nextSnapshot, []model.ResourceChange{change}))
			current = nextSnapshot
		}
	}
	server := newTestServer(b, gatewayScope(), original, nil)
	stream := &countingDeltaStream{ctx: b.Context()}
	subscription := server.resources.Subscribe(b.Context(), server.scope)
	watches := map[string]*watchState{}
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		watches,
		subscription,
		nodeRequest(model.RouteType, names...),
	); err != nil {
		b.Fatal(err)
	}
	watch := watches[model.RouteType]
	ack := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.RouteType, ResponseNonce: watch.nonceSent}
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		watches,
		subscription,
		ack,
	); err != nil {
		b.Fatal(err)
	}
	nonces := make([]string, ackEvery)
	b.ReportAllocs()
	b.ResetTimer()
	iteration := 0
	for b.Loop() {
		for i := range ackEvery {
			server.resources.mu.Lock()
			server.resources.snapshot = snapshots[iteration%len(snapshots)]
			server.resources.mu.Unlock()
			if err := server.server.pushUpdate(
				stream,
				server.scope,
				log,
				watches,
				updates[iteration%len(updates)],
			); err != nil {
				b.Fatal(err)
			}
			nonces[i] = watch.nonceSent
			iteration++
		}
		for _, nonce := range nonces {
			ack.ResponseNonce = nonce
			if err := server.server.handleRequest(stream, server.scope, log, watches, subscription, ack); err != nil {
				b.Fatal(err)
			}
		}
	}
	if stream.resources != size+b.N*ackEvery*changed || stream.responses != b.N*ackEvery+1 {
		b.Fatalf(
			"delivery changed: resources=%d responses=%d iterations=%d",
			stream.resources,
			stream.responses,
			b.N,
		)
	}
}
