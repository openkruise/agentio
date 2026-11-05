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

package securityprofile

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

// TestMain installs a logger so the request path's log.FromContext resolves
// to a real sink instead of controller-runtime's unfulfilled root, which
// prints a stack trace into the output once a run exceeds 30s. Production
// installs a zap logger at INFO; the arg-slice construction that dominates a
// disabled log line is the same either way.
func TestMain(m *testing.M) {
	ctrllog.SetLogger(logr.Discard())
	os.Exit(m.Run())
}

// The benchmarks here are the denominator for every micro-benchmark under
// pkg/engine and pkg/policy: one full ext_proc exchange through the
// production filter chain, the real resolver, and the real stream loggers.
// A saving that looks large in isolation is only worth taking if it is
// visible against these numbers.
//
// The gRPC transport is the one production cost left out — Process is driven
// against a scripted in-process stream.
//
// Two harness artifacts have to be kept off the clock or the numbers drift
// with -benchtime instead of converging:
//
//   - Setup must be followed by b.ResetTimer(). The framework resets the
//     alloc counters just before calling the benchmark function, so seeding
//     profiles (YAML parse, CRD validation, compilation) would otherwise be
//     charged to the loop and divided by b.N.
//   - RunMessages resets CaptureAccessLogger per call, so the audit log stays
//     one entry deep and its copy-out does not grow with b.N.

// benchSink defeats dead-code elimination.
var benchSink any

var benchLabels = map[string]string{"app": "sandbox"}

func benchBlockProfileYAML(name, path string, status int, body string) string {
	return fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: %s
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: block
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: %s
    actions:
      block:
        statusCode: %d
        body: %s
`, name, path, status, body)
}

func benchBypassProfileYAML(name, path string) string {
	return fmt.Sprintf(`
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: %s
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: bypass
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: %s
    actions:
      bypass: true
`, name, path)
}

// benchPassthroughProfileYAML matches the benchmark pod but scopes its rule
// to a path no benchmark request uses, so resolution runs in full and yields
// no unit. This is the shape of a pod governed by policy that does not
// happen to apply to the request in flight.
func benchPassthroughProfileYAML(name string) string {
	return benchBlockProfileYAML(name, "/never-requested", 451, "unreachable")
}

// benchRequest is a realistic request: pod identity, a handful of headers,
// and a query string, so header extraction and query parsing both do work.
func benchRequest(path string) *enginetest.RequestBuilder {
	return enginetest.NewRequest("POST", "server.example.com", path).
		Workload("test-ns", "sandbox-pod", benchLabels).
		Scheme("https").
		SourceAddress("10.244.1.37:43210").
		RequestID("3f2b8c1e-0d4a-4a7b-9c2f-1e5d8a6b4c30").
		Header("content-type", "application/json").
		Header("user-agent", "agent-sdk/1.4.2").
		Header("accept", "application/json")
}

// benchArm is one end-to-end outcome together with how to seed it.
type benchArm struct {
	name string
	// setup seeds the profile that decides this arm's outcome.
	setup func(h *Harness)
	path  string
	// outcome is the derived audit outcome, verified before timing. Asserting
	// on the wire verdict alone would not do: bypassed and passthrough share
	// the same wire shape, so a mis-seeded bypass profile would silently be
	// measured as a passthrough under the "bypassed" label.
	outcome string
}

var benchArms = []benchArm{
	{
		name:    "passthrough",
		setup:   func(*Harness) {},
		path:    "/v1/chat/completions?stream=true",
		outcome: "passthrough",
	},
	{
		name: "blocked",
		setup: func(h *Harness) {
			h.Fixture.ApplyYAML(benchBlockProfileYAML("block", "/blocked", 451, "blocked-by-bench"))
		},
		path:    "/blocked",
		outcome: "blocked",
	},
	{
		name: "bypassed",
		setup: func(h *Harness) {
			h.Fixture.ApplyYAML(benchBypassProfileYAML("bypass", "/bypassed"))
		},
		path:    "/bypassed",
		outcome: "bypassed",
	},
}

// benchHarness builds a harness seeded with nProfiles non-applying profiles
// plus the arm's own. The resolution probe is off so a test-only stream
// logger stays out of the measurement; verifyArm re-checks the outcome
// through a probe-enabled harness instead.
func benchHarness(b testing.TB, nProfiles int, arm benchArm) *Harness {
	b.Helper()
	h := New(b, Options{DisableResolutionProbe: true})
	for i := 0; i < nProfiles; i++ {
		h.Fixture.ApplyYAML(benchPassthroughProfileYAML("filler" + strconv.Itoa(i)))
	}
	arm.setup(h)
	return h
}

// verifyArm asserts the arm really reaches the outcome it claims, on a
// throwaway harness with the probe enabled. This runs outside the timed loop,
// so the probe's cost is not measured.
func verifyArm(b testing.TB, nProfiles int, arm benchArm) {
	b.Helper()
	h := New(b, Options{})
	for i := 0; i < nProfiles; i++ {
		h.Fixture.ApplyYAML(benchPassthroughProfileYAML("filler" + strconv.Itoa(i)))
	}
	arm.setup(h)
	v := h.Run(b, benchRequest(arm.path))
	if v.Err != nil {
		b.Fatalf("%s: Process returned error: %v", arm.name, v.Err)
	}
	if v.Info == nil {
		b.Fatalf("%s: no resolution captured, cannot verify outcome", arm.name)
	}
	if got := v.Info.Outcome.String(); got != arm.outcome {
		b.Fatalf("%s: outcome = %q, want %q", arm.name, got, arm.outcome)
	}
}

// BenchmarkRequest measures one complete ext_proc exchange. The profiles
// axis is the interesting one: it is the number of SecurityProfiles whose
// selectors and rules the resolver walks on every single request, and the
// only arm where a busy namespace differs from an idle one.
func BenchmarkRequest(b *testing.B) {
	for _, nProfiles := range []int{0, 1, 10} {
		for _, arm := range benchArms {
			b.Run("profiles="+strconv.Itoa(nProfiles)+"/"+arm.name, func(b *testing.B) {
				verifyArm(b, nProfiles, arm)
				h := benchHarness(b, nProfiles, arm)
				// Built once: RequestBuilder assembles protos, which is
				// adapter input rather than adapter cost.
				msgs := benchRequest(arm.path).Build()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSink = h.RunMessages(b, msgs)
				}
			})
		}
	}
}

// BenchmarkRequest_NoIdentity measures the fail-open path taken on every
// request when filter_state carries no pod identity — a misconfigured mesh
// pays this instead of the numbers above, so it is the adapter's floor.
func BenchmarkRequest_NoIdentity(b *testing.B) {
	h := benchHarness(b, 1, benchArms[1]) // the blocked arm, never reached
	// No Workload call, so the request carries no identity.
	msgs := enginetest.NewRequest("POST", "server.example.com", "/blocked").Build()
	if got := h.RunMessages(b, msgs).Kind; got != enginetest.VerdictPassthrough {
		b.Fatalf("verdict = %s, want passthrough for missing identity", got)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = h.RunMessages(b, msgs)
	}
}

// BenchmarkRequest_Headers isolates how the request's own header count moves
// the end-to-end number, since every header is lowercased and copied into a
// map that filters then read.
func BenchmarkRequest_Headers(b *testing.B) {
	arm := benchArms[0]
	for _, extra := range []int{0, 16, 48} {
		b.Run("extra="+strconv.Itoa(extra), func(b *testing.B) {
			h := benchHarness(b, 1, arm)
			rb := benchRequest(arm.path)
			for i := 0; i < extra; i++ {
				rb = rb.Header("x-bench-"+strconv.Itoa(i), "value-"+strconv.Itoa(i))
			}
			msgs := rb.Build()
			if got := h.RunMessages(b, msgs).Kind; got != enginetest.VerdictPassthrough {
				b.Fatalf("verdict = %s, want passthrough", got)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSink = h.RunMessages(b, msgs)
			}
		})
	}
}

// TestBenchArmsReachTheirOutcome guards the benchmark fixtures under
// plain `go test`: if a filler profile ever started matching the benchmark
// path, or an arm's profile stopped applying, the benchmarks would keep
// reporting numbers for the wrong path.
func TestBenchArmsReachTheirOutcome(t *testing.T) {
	for _, arm := range benchArms {
		t.Run(arm.name, func(t *testing.T) {
			verifyArm(t, 10, arm)
		})
	}
}
