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
	"bytes"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
)

func bodyActivation(t *testing.T, body []byte, value string) cel.Activation {
	t.Helper()
	act, err := cel.NewActivation(map[string]any{
		"request": map[string]any{"body": body},
		"value":   value,
		"pod":     map[string]any{},
		"profile": map[string]string{},
		"rule":    map[string]string{},
		"inputs":  map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return act
}

// Removing the merge implementation or making it left-biased would leave the
// caller's stale credential in place, which is the security bug this test
// catches.
func TestBodyMutationJSONMergeUsesRenderedValue(t *testing.T) {
	prog, err := CompileBodyMutation("json(request.body).merge({\"api_key\": value})")
	if err != nil {
		t.Fatal(err)
	}
	got, err := EvalBodyMutation(prog, bodyActivation(t, []byte("{\"api_key\":\"old\",\"keep\":1}"), "new"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("{\"api_key\":\"new\",\"keep\":1}")
	if !bytes.Equal(got, want) {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

func TestBodyMutationPreservesRawBytesAndStrings(t *testing.T) {
	for _, tc := range []struct {
		name string
		expr string
		want string
	}{
		{name: "bytes", expr: "request.body", want: "raw-body\n"},
		{name: "string", expr: "\"replacement\"", want: "replacement"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := CompileBodyMutation(tc.expr)
			if err != nil {
				t.Fatal(err)
			}
			got, err := EvalBodyMutation(prog, bodyActivation(t, []byte("raw-body\n"), "unused"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("body = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBodyMutationSerializesJSONValues(t *testing.T) {
	prog, err := CompileBodyMutation("{\"enabled\": true, \"items\": [1, 2]}")
	if err != nil {
		t.Fatal(err)
	}
	got, err := EvalBodyMutation(prog, bodyActivation(t, nil, "unused"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"enabled\":true,\"items\":[1,2]}"; string(got) != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

func TestBodyMutationRejectsInvalidJSONWithoutLeakingActivationValues(t *testing.T) {
	prog, err := CompileBodyMutation("json(request.body).merge({\"api_key\": value})")
	if err != nil {
		t.Fatal(err)
	}
	const body = "not-json-BODY-MUST-NOT-LEAK"
	const value = "TOKEN-MUST-NOT-LEAK"
	_, err = EvalBodyMutation(prog, bodyActivation(t, []byte(body), value))
	if err == nil {
		t.Fatal("EvalBodyMutation accepted malformed JSON")
	}
	if strings.Contains(err.Error(), body) || strings.Contains(err.Error(), value) {
		t.Fatalf("error leaked body or credential: %v", err)
	}
}

func TestCompileBodyMutationRejectsMalformedCEL(t *testing.T) {
	if _, err := CompileBodyMutation("json(request.body).merge("); err == nil {
		t.Fatal("CompileBodyMutation accepted malformed CEL")
	}
}

func TestCompileBodyMutationRejectsUnboundedListConstructor(t *testing.T) {
	if _, err := CompileBodyMutation("lists.range(int(json(request.body).n))"); err == nil || !strings.Contains(err.Error(), "lists.range") {
		t.Fatalf("CompileBodyMutation() error = %v, want lists.range rejection", err)
	}
}

func TestBodyMutationRuntimeCostIsBoundedAndErrorIsSanitized(t *testing.T) {
	prog, err := CompileBodyMutation("json(request.body).map(item, item)")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("[\"BODY-MUST-NOT-LEAK\"," + strings.Repeat("0,", 20_000) + "0]")
	const value = "TOKEN-MUST-NOT-LEAK"
	_, err = EvalBodyMutation(prog, bodyActivation(t, body, value))
	if err == nil {
		t.Fatal("EvalBodyMutation exceeded its cost budget without failing")
	}
	if strings.Contains(err.Error(), "BODY-MUST-NOT-LEAK") || strings.Contains(err.Error(), value) {
		t.Fatalf("error leaked body or credential: %v", err)
	}
}

func TestBodyMutationHelperErrorDoesNotLeakRuntimeValues(t *testing.T) {
	prog, err := CompileBodyMutation("[json(request.body), value].join(',')")
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"secret":"BODY-MUST-NOT-LEAK"}`
	const value = "TOKEN-MUST-NOT-LEAK"
	_, err = EvalBodyMutation(prog, bodyActivation(t, []byte(body), value))
	if err == nil {
		t.Fatal("EvalBodyMutation accepted a non-string join operand")
	}
	if strings.Contains(err.Error(), "BODY-MUST-NOT-LEAK") || strings.Contains(err.Error(), value) {
		t.Fatalf("error leaked body or credential: %v", err)
	}
}
