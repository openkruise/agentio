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

package subject

import "testing"

func TestHasIdentity(t *testing.T) {
	tests := []struct {
		name    string
		subject Subject
		want    bool
	}{
		{
			name:    "workload UID without Kubernetes metadata",
			subject: Subject{Workload: Workload{UID: "native:host"}},
			want:    true,
		},
		{
			name:    "Sandbox UID without workload",
			subject: Subject{Sandbox: &Sandbox{UID: "kruise:sbx"}},
			want:    true,
		},
		{
			name:    "network metadata is not identity",
			subject: Subject{Workload: Workload{IP: "192.0.2.1"}},
		},
		{
			name:    "namespace and name present",
			subject: Subject{Workload: Workload{Namespace: "ns", Name: "pod"}},
			want:    true,
		},
		{
			name:    "missing name",
			subject: Subject{Workload: Workload{Namespace: "ns"}},
			want:    false,
		},
		{
			name:    "missing namespace",
			subject: Subject{Workload: Workload{Name: "pod"}},
			want:    false,
		},
		{
			name:    "zero subject",
			subject: Subject{},
			want:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.subject.HasIdentity(); got != tc.want {
				t.Errorf("HasIdentity(): want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestWorkloadString(t *testing.T) {
	for _, tc := range []struct {
		workload Workload
		want     string
	}{
		{Workload{}, ""},
		{Workload{IP: "192.0.2.1"}, ""},
		{Workload{Namespace: "ns", Name: "host"}, "ns/host"},
		{Workload{UID: "native:host", Namespace: "ns", Name: "host"}, "native:host"},
	} {
		if got := tc.workload.String(); got != tc.want {
			t.Errorf("workload=%+v: String() = %q, want %q", tc.workload, got, tc.want)
		}
	}
}
