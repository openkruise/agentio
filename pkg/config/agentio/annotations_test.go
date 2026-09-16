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
package agentio

import "testing"

func TestAnnotationPrecedence(t *testing.T) {
	for legacy, key := range annotationAliases {
		for _, tc := range []struct {
			name        string
			annotations map[string]string
			want        string
			found       bool
		}{
			{"absent", nil, "", false},
			{"legacy", map[string]string{legacy: "old"}, "old", true},
			{"agentio", map[string]string{key: "new"}, "new", true},
			{"both", map[string]string{legacy: "old", key: "new"}, "new", true},
			{"empty override", map[string]string{legacy: "old", key: ""}, "", true},
		} {
			t.Run(key+"/"+tc.name, func(t *testing.T) {
				original := tc.annotations[legacy]
				got, found := Annotation(tc.annotations, legacy)
				if got != tc.want || found != tc.found {
					t.Fatalf("got (%q, %v), want (%q, %v)", got, found, tc.want, tc.found)
				}
				normalized := NormalizeAnnotations(tc.annotations)
				if tc.found && (normalized[legacy] != tc.want || normalized[key] != tc.want) {
					t.Fatalf("normalized annotations = %v", normalized)
				}
				if tc.annotations[legacy] != original {
					t.Fatal("input annotations were modified")
				}
			})
		}
	}
}
