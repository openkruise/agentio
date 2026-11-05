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
	"strings"
	"testing"
)

func TestValueEval(t *testing.T) {
	tmpl, err := CompileTemplate("t", "Bearer {{ .Token }}")
	if err != nil {
		t.Fatalf("CompileTemplate: %v", err)
	}
	tests := []struct {
		name        string
		value       Value
		data        any
		want        string
		expectError string
	}{
		{name: "literal skips engines", value: Value{Literal: "application/json"}, data: nil, want: "application/json"},
		{name: "template renders", value: Value{Tmpl: tmpl}, data: struct{ Token string }{"tok"}, want: "Bearer tok"},
		{name: "empty value yields empty string", value: Value{}, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.value.Eval(tc.data)
			if tc.expectError != "" {
				if err == nil {
					t.Fatalf("Eval: want error containing %q, got nil", tc.expectError)
				}
				if !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf("Eval error: want substring %q, got %q", tc.expectError, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("Eval: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("Eval: want %q, got %q", tc.want, got)
			}
		})
	}
}
