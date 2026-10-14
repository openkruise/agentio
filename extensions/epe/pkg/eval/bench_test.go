// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package eval

import (
	"fmt"
	"testing"

	"github.com/google/cel-go/cel"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// benchSink defeats dead-code elimination.
var benchSink any

func benchRequest() inputs.Request {
	return inputs.RequestFrom(httpreq.HTTPRequest{
		Host:   "api.example.com",
		Port:   443,
		Path:   "/v1/chat/completions",
		Scheme: "https",
		Method: "POST",
	})
}

func benchActivation(extra map[string]any) cel.Activation {
	return inputs.NewScope(
		benchRequest(),
		inputs.Pod{Namespace: "test-ns", Name: "sandbox-pod", Labels: map[string]string{"app": "sleep"}},
		inputs.Profile{Name: "profile"},
		inputs.Rule{Name: "rule"},
		extra,
	).Activation()
}

// BenchmarkEvalBool measures one audit `when` evaluation against an already
// compiled program and an already built activation — the per-request cost a
// profile with audit conditions adds. The activation carries the audit shape:
// the memoised scope activation with the audit-only variables layered on top,
// exactly as audit.Scope.Activation builds it. Compilation happens once per
// profile (BenchmarkCompileBool) and the base activation construction is
// charged separately (BenchmarkActivation).
func BenchmarkEvalBool(b *testing.B) {
	tests := []struct {
		name string
		expr string
	}{
		// Empty expression: the "always fire" nil-program path.
		{"empty", ""},
		{"result-compare", `result == "blocked"`},
		{"labels-and-result", `pod.labels["app"] == "sleep" && result == "blocked"`},
		{"string-functions", `request.path.startsWith("/v1/") && request.host.endsWith(".example.com")`},
	}
	for _, tt := range tests {
		prog, err := CompileBool(tt.expr)
		if err != nil {
			b.Fatalf("%s: compile: %v", tt.name, err)
		}
		act := layerAuditOnly(b, benchActivation(nil), map[string]any{"result": "blocked"})
		// Guard the fixture: every arm must actually evaluate to true, or
		// the numbers would describe an error path instead.
		if ok, err := EvalBool(prog, act); err != nil || !ok {
			b.Fatalf("%s: fixture does not evaluate to true: (%v, %v)", tt.name, ok, err)
		}
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ok, err := EvalBool(prog, act)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = ok
			}
		})
	}
}

// BenchmarkEvalValue measures one credentialProvider parameter evaluation:
// the CEL expression yields an arbitrary value that is then converted to its
// native Go representation.
func BenchmarkEvalValue(b *testing.B) {
	routing := map[string]any{
		"routing": map[string]any{"api.example.com": "tenant-a"},
	}
	tests := []struct {
		name   string
		expr   string
		inputs map[string]any
	}{
		{"string-field", `pod.namespace`, nil},
		{"inputs-lookup", `inputs["routing"][request.host]`, routing},
		{"list-literal", `[request.host, request.path]`, nil},
		// A map result is the shape that pays for the JSON-native rebuild:
		// EvalValue cannot hand back the activation's own map.
		{"map-slot", `pod.labels`, nil},
	}
	for _, tt := range tests {
		prog, err := CompileValue(tt.expr)
		if err != nil {
			b.Fatalf("%s: compile: %v", tt.name, err)
		}
		act := benchActivation(tt.inputs)
		if v, err := EvalValue(prog, act); err != nil || v == nil {
			b.Fatalf("%s: fixture yields (%v, %v), want a value", tt.name, v, err)
		}
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				v, err := EvalValue(prog, act)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = v
			}
		})
	}
}

// BenchmarkActivation measures the per-unit projection. The first-call arm is
// what a request pays once; the memoised arm is what every later evaluation in
// that unit pays. The sizes are 2, 12 and 40 headers because the cost the
// pooled implementation paid was linear in header count.
func BenchmarkActivation(b *testing.B) {
	sizes := []struct {
		name    string
		h, q, l int
	}{
		{"h2_q0_l2", 2, 0, 2},
		{"h12_q2_l5", 12, 2, 5},
		{"h40_q8_l15", 40, 8, 15},
	}
	for _, sz := range sizes {
		req, pod := benchRequestSized(sz.h, sz.q), benchPodSized(sz.l)
		// Guard the fixture: the projection must actually carry the headers and
		// labels the size claims, or every arm would measure the same trivial
		// bag. Checked through CEL so the guard does not depend on the bag's
		// representation.
		guardProjectionSize(b, req, pod, sz.h, sz.l)
		b.Run("first/"+sz.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchSink = inputs.NewScope(req, pod, inputs.Profile{Name: "p"}, inputs.Rule{Name: "r"}, nil).
					Activation()
			}
		})
		b.Run("memoised/"+sz.name, func(b *testing.B) {
			s := inputs.NewScope(req, pod, inputs.Profile{Name: "p"}, inputs.Rule{Name: "r"}, nil)
			_ = s.Activation()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchSink = s.Activation()
			}
		})
	}
}

// guardProjectionSize fails the benchmark unless the projected bag really
// exposes nHeaders headers and nLabels labels, so a fixture that silently
// stopped varying with size cannot produce believable numbers.
func guardProjectionSize(b *testing.B, req inputs.Request, pod inputs.Pod, nHeaders, nLabels int) {
	b.Helper()
	prog, err := CompileBool(fmt.Sprintf(`size(request.headers) == %d && size(pod.labels) == %d`, nHeaders, nLabels))
	if err != nil {
		b.Fatalf("guard: compile: %v", err)
	}
	act := inputs.NewScope(req, pod, inputs.Profile{Name: "p"}, inputs.Rule{Name: "r"}, nil).Activation()
	if ok, err := EvalBool(prog, act); err != nil || !ok {
		b.Fatalf("guard: projection does not carry %d headers / %d labels: (%v, %v)", nHeaders, nLabels, ok, err)
	}
}

func benchRequestSized(nHeaders, nQuery int) inputs.Request {
	h := make(map[string]string, nHeaders)
	for i := 0; i < nHeaders; i++ {
		h[fmt.Sprintf("x-header-%02d", i)] = "some-reasonably-long-header-value"
	}
	q := make(map[string][]string, nQuery)
	for i := 0; i < nQuery; i++ {
		q[fmt.Sprintf("param%d", i)] = []string{"value"}
	}
	return inputs.RequestFrom(httpreq.HTTPRequest{
		Host:    "api.example.com",
		Port:    443,
		Path:    "/v1/chat/completions",
		Scheme:  "https",
		Method:  "POST",
		Headers: h,
		Query:   q,
	})
}

func benchPodSized(nLabels int) inputs.Pod {
	l := make(map[string]string, nLabels)
	for i := 0; i < nLabels; i++ {
		l[fmt.Sprintf("label-%d", i)] = "value"
	}
	return inputs.Pod{Name: "sandbox-pod", Namespace: "ns", IP: "10.0.0.1", Labels: l}
}

// BenchmarkCompileBool measures one full compile (parse, type-check,
// optimize). This runs per profile compilation, not per request; it exists to
// document why compiled programs are cached on the profile.
func BenchmarkCompileBool(b *testing.B) {
	const expr = `pod.labels["app"] == "sleep" && result == "blocked"`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		prog, err := CompileBool(expr)
		if err != nil {
			b.Fatal(err)
		}
		benchSink = prog
	}
}
