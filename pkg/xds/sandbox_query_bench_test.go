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
	"time"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// The full unary path: admission, authentication, scope, snapshot lookup,
// encode, and unmarshal. Run with GOMAXPROCS=2 to match the bench README.
func BenchmarkGetSandbox(b *testing.B) {
	for _, keys := range []int{1, 1000} {
		b.Run(fmt.Sprintf("Keys%d", keys), func(b *testing.B) {
			resources := make([]model.Resource, keys)
			requests := make([]*sandboxv1.GetSandboxRequest, keys)
			for i := range resources {
				name := fmt.Sprintf("uid:%06d", i)
				resources[i] = sandboxResourceWithAttester(b, name, "host")
				requests[i] = &sandboxv1.GetSandboxRequest{Name: name}
			}
			server := newTestServer(b, gatewayScope(), resources, nil)
			q := server.server.SandboxQuery(nil, nil, 10*time.Second)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					if _, err := q.GetSandbox(b.Context(), requests[i%keys]); err != nil {
						b.Fatal(err)
					}
					i++
				}
			})
		})
	}
}

func BenchmarkAdmitUnary(b *testing.B) {
	f := newFlowController(defaultFlowControlConfig(16, 0))
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			release, err := f.admitUnary(b.Context())
			if err != nil {
				b.Fatal(err)
			}
			release()
		}
	})
}