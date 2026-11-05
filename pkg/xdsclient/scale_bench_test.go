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

package xdsclient

import (
	"fmt"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func benchmarkClient(b *testing.B, wildcard bool) *Client {
	b.Helper()
	conn, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := conn.Close(); err != nil {
			b.Error(err)
		}
	})
	c, err := New(
		conn,
		Config{Node: &core.Node{Id: "benchmark"}, Watches: []Watch{{TypeURL: testType, Wildcard: wildcard}}},
	)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

func BenchmarkDeltaApplyWith50000Resources(b *testing.B) {
	c := benchmarkClient(b, true)
	value, err := anypb.New(wrapperspb.String("value"))
	if err != nil {
		b.Fatal(err)
	}
	resources := make([]*discovery.Resource, 50000)
	for i := range resources {
		resources[i] = &discovery.Resource{
			Name:     fmt.Sprintf("workload-%d", i),
			Aliases:  []string{fmt.Sprintf("instance-%d", i)},
			Resource: value,
		}
	}
	if err := c.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType, Resources: resources}); err != nil {
		b.Fatal(err)
	}
	delta := &discovery.DeltaDiscoveryResponse{TypeUrl: testType, Resources: resources[:1]}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := c.apply(delta); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSubscriptionChangeWith50000Names(b *testing.B) {
	c := benchmarkClient(b, false)
	for i := range 50000 {
		if _, err := c.Acquire(testType, fmt.Sprintf("instance-%d", i)); err != nil {
			b.Fatal(err)
		}
	}
	sent := map[string]map[string]*subscription{}
	c.initialRequests(sent)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		lease, err := c.Acquire(testType, "new-instance")
		if err != nil {
			b.Fatal(err)
		}
		if len(c.pendingRequests(sent)) != 1 {
			b.Fatal("missing subscribe")
		}
		lease.Release()
		if len(c.pendingRequests(sent)) != 1 {
			b.Fatal("missing unsubscribe")
		}
	}
}
