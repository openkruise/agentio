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
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// BenchmarkCompilerDNSUpdate times the propagation wave after one egress hostname's DNS result changes.
func BenchmarkCompilerDNSUpdate(b *testing.B) {
	count := 10_000
	if override := os.Getenv("DNS_FLIP_WORKLOADS"); override != "" {
		parsed, err := strconv.Atoi(override)
		if err != nil || parsed <= 0 {
			b.Fatalf("invalid DNS_FLIP_WORKLOADS=%q", override)
		}
		count = parsed
	}
	b.Run(fmt.Sprintf("workloads=%d", count), func(b *testing.B) {
		stop := make(chan struct{})
		b.Cleanup(func() { close(stop) })
		options := []krt.CollectionOption{krt.WithStop(stop)}

		dnsResults := krt.NewMutableCollection[dnsBenchmarkResult](nil,
			[]dnsBenchmarkResult{{host: "api.example.com", address: netip.MustParseAddr("10.1.0.1")}}, options...)
		compiler := dnsScaleCompiler(b, count, dnsResults.AsCollection(), stop, options, nil)
		waitSynced(b, compiler)

		var addressUpdates atomic.Uint64
		registration := compiler.Resources().RegisterBatch(func(events []krt.Event[model.Resource]) {
			for _, event := range events {
				if event.Latest().Key.TypeURL == model.AddressType {
					addressUpdates.Add(1)
				}
			}
		}, false)
		b.Cleanup(registration.UnregisterHandler)
		b.ReportAllocs()
		b.ResetTimer()
		var waveTotal time.Duration
		for iteration := range b.N {
			// The address must differ from the initial 10.1.0.1 and from every
			// previous iteration, or the update is suppressed as a no-op and the
			// wave never starts.
			address := netip.AddrFrom4([4]byte{10, 1, 1, byte(iteration % 256)})
			started := time.Now()
			dnsResults.ConditionalUpdateObject(dnsBenchmarkResult{host: "api.example.com", address: address})
			target := uint64(iteration+1) * uint64(count)
			waitForAddressUpdates(b, &addressUpdates, target)
			waveTotal += time.Since(started)
		}
		b.ReportMetric(float64(waveTotal.Microseconds())/float64(b.N), "wave_us/op")
	})
}
