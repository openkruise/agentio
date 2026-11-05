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
package tokentransform

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"k8s.io/utils/ptr"

	"github.com/openkruise/agentio/extensions/epe/pkg/eval"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

func TestRenderParamsValueAndTemplate(t *testing.T) {
	tmpl, err := eval.CompileTemplate("test", "pod-{{ .Pod.Name }}")
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]ParamSource{
		"static":   {Value: ptr.To("v1")},
		"rendered": {Template: tmpl},
	}
	scope := inputs.NewScope(inputs.Request{}, inputs.Workload{Name: "pod-a"}, inputs.Profile{}, inputs.Rule{}, nil)
	got, err := renderParams(params, scope)
	if err != nil {
		t.Fatal(err)
	}
	if got["static"] != "v1" || got["rendered"] != "pod-pod-a" {
		t.Fatalf("renderParams = %v", got)
	}
}

// TestRenderParamsCel covers the CEL branch and the JSON normalization that
// turns a CEL list into a plain []any.
func TestRenderParamsCel(t *testing.T) {
	prog, err := eval.CompileValue(`[inputs["routing"][request.host], request.headers["x-scope"]]`)
	if err != nil {
		t.Fatal(err)
	}
	scope := inputs.NewScope(
		inputs.RequestFrom(
			httpreq.HTTPRequest{
				Host:    "example.com",
				Port:    443,
				Path:    "/v1/resources",
				Scheme:  "https",
				Method:  "GET",
				Query:   url.Values{},
				Headers: map[string]string{"x-scope": "readonly"},
			},
		),
		inputs.Workload{},
		inputs.Profile{},
		inputs.Rule{},
		map[string]any{"routing": map[string]string{"example.com": "kms-name"}},
	)
	got, err := renderParams(map[string]ParamSource{"computed": {Cel: prog}}, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["computed"], []any{"kms-name", "readonly"}) {
		t.Fatalf("renderParams = %#v, want normalized []any", got["computed"])
	}
}

// TestRenderParamsMapResult covers map-valued parameters end to end. cel-go
// converts a map result to map[any]any, a type encoding/json refuses, so
// without eval's JSON-native normalization every one of these fails the
// marshalling step with "result is not JSON-compatible".
func TestRenderParamsMapResult(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want any
	}{
		{"header map", `request.headers`, map[string]any{"x-scope": "readonly"}},
		{"pod labels", `pod.labels`, map[string]any{"tenant": "a"}},
		{"inputs entry", `inputs["routing"]`, map[string]any{"example.com": "kms-name"}},
		{"map literal", `{"tenant": pod.labels["tenant"]}`, map[string]any{"tenant": "a"}},
		{"map inside list", `[request.headers]`, []any{map[string]any{"x-scope": "readonly"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := eval.CompileValue(tc.expr)
			if err != nil {
				t.Fatal(err)
			}
			scope := inputs.NewScope(
				inputs.RequestFrom(
					httpreq.HTTPRequest{
						Host:    "example.com",
						Port:    443,
						Path:    "/v1/resources",
						Scheme:  "https",
						Method:  "GET",
						Query:   url.Values{},
						Headers: map[string]string{"x-scope": "readonly"},
					},
				),
				inputs.Workload{Labels: map[string]string{"tenant": "a"}},
				inputs.Profile{},
				inputs.Rule{},
				map[string]any{"routing": map[string]string{"example.com": "kms-name"}},
			)
			got, err := renderParams(map[string]ParamSource{"computed": {Cel: prog}}, scope)
			if err != nil {
				t.Fatalf("renderParams: %v", err)
			}
			if !reflect.DeepEqual(got["computed"], tc.want) {
				t.Fatalf("renderParams = %#v, want %#v", got["computed"], tc.want)
			}
		})
	}
}

// TestRenderParamsConcurrentIsolation is an end-to-end check that two requests
// rendering the same compiled parameter never see each other's values. Its
// original subject was contamination of a pooled activation, which no longer
// exists; it survives because it exercises the whole path — Scope projection,
// CEL evaluation, ownedNative and the JSON round-trip — under concurrency,
// which no unit test does.
func TestRenderParamsConcurrentIsolation(t *testing.T) {
	prog, err := eval.CompileValue(`{"headers": request.headers, "labels": pod.labels, "profile": profile}`)
	if err != nil {
		t.Fatal(err)
	}
	const goroutines, iterations = 16, 200
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(tenant string) {
			defer wg.Done()
			scope := inputs.NewScope(
				inputs.RequestFrom(httpreq.HTTPRequest{
					Host:    tenant + ".example.com",
					Port:    443,
					Path:    "/v1",
					Scheme:  "https",
					Method:  "GET",
					Query:   url.Values{},
					Headers: map[string]string{"x-tenant": tenant},
				}),
				inputs.Workload{Name: tenant, Namespace: tenant, Labels: map[string]string{"tenant": tenant}},
				inputs.Profile{Name: tenant, Namespace: tenant},
				inputs.Rule{}, nil,
			)
			want := map[string]any{
				"headers": map[string]any{"x-tenant": tenant},
				"labels":  map[string]any{"tenant": tenant},
				"profile": map[string]any{"name": tenant, "namespace": tenant},
			}
			for i := 0; i < iterations; i++ {
				got, err := renderParams(map[string]ParamSource{"computed": {Cel: prog}}, scope)
				if err != nil {
					errs <- fmt.Errorf("tenant %s: %w", tenant, err)
					return
				}
				if !reflect.DeepEqual(got["computed"], want) {
					errs <- fmt.Errorf("tenant %s saw %#v, want %#v", tenant, got["computed"], want)
					return
				}
			}
		}(fmt.Sprintf("tenant-%02d", g))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestRenderParamsNullResult keeps the all-or-nothing guard: a parameter that
// evaluates to null aborts the whole provider call.
func TestRenderParamsNullResult(t *testing.T) {
	prog, err := eval.CompileValue(`null`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = renderParams(
		map[string]ParamSource{"nothing": {Cel: prog}},
		inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil),
	)
	if err == nil || !strings.Contains(err.Error(), "result is null") {
		t.Fatalf("err = %v, want result-is-null error", err)
	}
}

func TestRenderParamsUnsetSource(t *testing.T) {
	_, err := renderParams(
		map[string]ParamSource{"empty": {}},
		inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{}, inputs.Rule{}, nil),
	)
	if err == nil || !strings.Contains(err.Error(), "exactly one of value, cel or template") {
		t.Fatalf("err = %v, want exactly-one-source error", err)
	}
}

func TestRenderParamsNilScope(t *testing.T) {
	if _, err := renderParams(map[string]ParamSource{"a": {Value: ptr.To("x")}}, nil); err == nil {
		t.Fatal("nil scope with parameters must error")
	}
	if got, err := renderParams(nil, nil); err != nil || got != nil {
		t.Fatalf("empty params = %v, %v; want nil, nil", got, err)
	}
}
