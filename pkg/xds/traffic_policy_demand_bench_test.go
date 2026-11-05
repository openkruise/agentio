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
	"io"
	"log/slog"
	"testing"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func BenchmarkTrafficPolicyDemand(b *testing.B) {
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	b.Cleanup(func() { slog.SetDefault(previous) })
	policy := sharedTrafficResource(b, "p", securityv1.TrafficPolicy_ALLOW)
	w := workloadWithTrafficRefs(b, addressResource(b, "w", "w"), "p")
	server := newTestServer(b, gatewayScope(), []model.Resource{policy, w}, nil)
	stream := discardDeltaStream{ctx: b.Context()}
	sub := server.resources.Subscribe(b.Context(), model.ClientScope{})
	watches := map[string]*watchState{}
	if err := server.server.handleRequest(
		stream,
		server.scope,
		log,
		watches,
		sub,
		nodeRequest(model.WorkloadType, "w"),
	); err != nil {
		b.Fatal(err)
	}
	request := nodeRequest(model.TrafficPolicyType, "p")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := server.server.handleRequest(stream, server.scope, log, watches, sub, request); err != nil {
			b.Fatal(err)
		}
	}
}
