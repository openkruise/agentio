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

package policy

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	agentlog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
)

func BenchmarkBindingCompare(b *testing.B) {
	agentlog.ConfigureOutputLevel(slog.LevelError)
	count := 2000
	if raw := os.Getenv("BINDING_BENCH_SIZE"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 2 || n > 30000 {
			b.Fatal("invalid count")
		}
		count = n
	}
	scopes := []string{"namespace", "global"}
	if scope := os.Getenv("BINDING_BENCH_SCOPE"); scope != "" {
		scopes = []string{scope}
	}
	for _, scope := range scopes {
		b.Run(scope, func(b *testing.B) {
			stop := make(chan struct{})
			defer close(stop)
			opts := []krt.CollectionOption{krt.WithStop(stop)}
			ws := make([]model.Workload, count)
			ps := make([]PolicyAttachment, count)
			for i := range count {
				uid := fmt.Sprintf("w-%d", i)
				ws[i] = model.Workload{UID: uid, Namespace: "demo", Labels: map[string]string{"app": uid}}
				target := AttachmentTarget{
					Global:   scope == "global",
					Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": uid}},
				}
				if !target.Global {
					target.Namespaces = []string{"demo"}
				}
				var err error
				ps[i], err = NewPolicyAttachment(
					PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: uid, Target: target},
				)
				if err != nil {
					b.Fatal(err)
				}
			}
			policies := krt.NewMutableCollection(nil, ps, opts...)
			workloads := krt.NewMutableCollection(nil, ws, opts...)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			bindings := NewWorkloadPolicyBindingsCollection(
				workloads.AsCollection(),
				policies.AsCollection(),
				krt.NewOptionsBuilder(stop, "bench", nil),
			)
			if !bindings.WaitUntilSynced(stop) {
				b.Fatal("sync failed")
			}
			cold := time.Since(start)
			runtime.GC()
			runtime.ReadMemStats(&after)
			fmt.Printf(
				"FIXTURE scope=%s workloads=%d policies=%d cold_ns=%d retained_heap_delta=%d\n",
				scope,
				count,
				count,
				cold.Nanoseconds(),
				int64(after.HeapAlloc)-int64(before.HeapAlloc),
			)
			events := make(chan krt.Event[Bindings], count*2)
			reg := bindings.RegisterBatch(func(es []krt.Event[Bindings]) {
				for _, e := range es {
					events <- e
				}
			}, false)
			defer reg.UnregisterHandler()
			wait := func(n int) {
				for range n {
					if count <= 2000 {
						awaitBindingEvent(b, events)
					} else {
						select {
						case <-events:
						case <-time.After(10 * time.Minute):
							b.Fatal("binding update timeout")
						}
					}
				}
			}
			for _, global := range []bool{true, false} {
				name := "namespace_wide"
				target := AttachmentTarget{Namespaces: []string{"demo"}}
				if global {
					name = "global_wide"
					target = AttachmentTarget{Global: true}
				}
				p, err := NewPolicyAttachment(
					PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: "wide", Target: target},
				)
				if err != nil {
					b.Fatal(err)
				}
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						policies.ConditionalUpdateObject(p)
						wait(count)
						policies.DeleteObject(p.ResourceName())
						wait(count)
					}
					b.StopTimer()
				})
			}
			b.Run("selector_move", func(b *testing.B) {
				p := ps[0]
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					p.Target.Selector.MatchLabels = map[string]string{"app": "w-1"}
					p.selector = nil
					var err error
					p, err = NewPolicyAttachment(p)
					if err != nil {
						b.Fatal(err)
					}
					policies.ConditionalUpdateObject(p)
					wait(2)
					policies.ConditionalUpdateObject(ps[0])
					wait(2)
				}
				b.StopTimer()
			})
			b.Run("workload_label", func(b *testing.B) {
				w := ws[0]
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					w.Labels = map[string]string{"app": "none"}
					workloads.ConditionalUpdateObject(w)
					wait(1)
					workloads.ConditionalUpdateObject(ws[0])
					wait(1)
				}
				b.StopTimer()
			})
			p, err := NewPolicyAttachment(
				PolicyAttachment{
					Kind:     PolicyKindTrafficPolicy,
					Name:     "priority",
					Priority: 1,
					Target:   AttachmentTarget{Global: true},
				},
			)
			if err != nil {
				b.Fatal(err)
			}
			policies.ConditionalUpdateObject(p)
			wait(count)
			b.Run("priority", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					p.Priority = -1
					policies.ConditionalUpdateObject(p)
					wait(count)
					p.Priority = 1
					policies.ConditionalUpdateObject(p)
					wait(count)
				}
				b.StopTimer()
			})
		})
	}
}
