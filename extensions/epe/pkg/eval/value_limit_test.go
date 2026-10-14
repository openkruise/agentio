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
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
)

func boundedProgram(t *testing.T, expression string) cel.Program {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("body", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile(expression)
	if issues.Err() != nil {
		t.Fatal(issues.Err())
	}
	prog, err := env.Program(ast, cel.CostLimit(10000))
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

func TestValueBoundedExactJSONSize(t *testing.T) {
	for _, expression := range []string{
		`null`, `true`, `-123`, `1.5`, `42u`, `"你好<>&\n\""`, `[]`, `{}`,
		`b"abc"`, `b""`, `{1: ["x", null], "escaped\n": {"text": "<>&"}}`,
		`timestamp("2026-01-02T03:04:05Z")`, `duration("1s")`,
	} {
		t.Run(expression, func(t *testing.T) {
			prog := boundedProgram(t, expression)
			act, err := cel.NewActivation(map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			want, err := EvalValue(prog, act)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ValueBounded(prog, act, len(encoded))
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%v err=%v want=%v", got, err, want)
			}
			if got, err := ValueBounded(
				prog,
				act,
				len(encoded)-1,
			); !errors.Is(err, ErrResultTooLarge) ||
				got != nil {
				t.Fatalf("accepted over-budget result: %v (%v)", got, err)
			}
		})
	}
}

func TestValueBoundedAmplificationAndDepth(t *testing.T) {
	body := make([]any, 200)
	for i := range body {
		body[i] = map[string]any{"text": strings.Repeat("x", 200)}
	}
	var deep any = "x"
	for range 130 {
		deep = []any{deep}
	}
	for _, tt := range []struct {
		name       string
		expression string
		body       any
	}{
		{"amplification", `body.map(item, {'item': item, 'context': body})`, body},
		{"depth", `body`, deep},
		{"scalar", `body`, strings.Repeat("x", 65536)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			act, err := cel.NewActivation(map[string]any{"body": tt.body})
			if err != nil {
				t.Fatal(err)
			}
			got, err := ValueBounded(boundedProgram(t, tt.expression), act, 16384)
			if !errors.Is(err, ErrResultTooLarge) || got != nil {
				t.Fatalf("got=%v err=%v", got, err)
			}
		})
	}
}

func TestCheckValueSizeWithoutProgram(t *testing.T) {
	for _, value := range []any{nil, "hello", true, float64(42), []any{"x", nil}, map[string]any{"text": "<>&"}} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckValueSize(value, len(encoded)); err != nil {
			t.Fatalf("exact budget rejected: %s %v", encoded, err)
		}
		if err := CheckValueSize(value, len(encoded)-1); !errors.Is(err, ErrResultTooLarge) {
			t.Fatalf("oversized value accepted: %s %v", encoded, err)
		}
	}
	var value any = "x"
	for range 130 {
		value = []any{value}
	}
	if err := CheckValueSize(value, 16384); !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("deep value accepted: %v", err)
	}
	if err := CheckValueSize(nil, 0); !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("invalid budget accepted: %v", err)
	}
}

func TestValueRejectsCollidingJSONKeys(t *testing.T) {
	for _, expression := range []string{
		`{1: "number", "1": "string"}`,
		`{true: "boolean", "true": "string"}`,
		`{"nested": [{1u: null, "1": "string"}]}`,
	} {
		t.Run(expression, func(t *testing.T) {
			prog := boundedProgram(t, expression)
			act, err := cel.NewActivation(map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			for _, bounded := range []bool{false, true} {
				var got any
				if bounded {
					got, err = ValueBounded(prog, act, 1024)
				} else {
					got, err = EvalValue(prog, act)
				}
				if got != nil || err == nil || !strings.Contains(err.Error(), "duplicate JSON map key") {
					t.Fatalf("bounded=%v got=%v err=%v", bounded, got, err)
				}
			}
		})
	}
}
