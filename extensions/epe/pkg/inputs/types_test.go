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
package inputs

import (
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

func TestWorkloadFromSubjectWithoutWorkload(t *testing.T) {
	for _, subject := range []subject.Subject{{}, {Sandbox: &subject.Sandbox{UID: "kruise:sbx"}}} {
		got := WorkloadFromSubject(subject)
		if got.Name != "" || got.Namespace != "" || got.IP != "" || got.Labels != nil {
			t.Fatalf("absent workload leaked into expression pod: %+v", got)
		}
	}
}

func TestWorkloadLabel(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		key    string
		want   string
	}{
		{"present", map[string]string{"app": "sleep"}, "app", "sleep"},
		{"absent", map[string]string{"app": "sleep"}, "missing", ""},
		{"nil map", nil, "app", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Workload{Labels: tc.labels}
			if got := p.Label(tc.key); got != tc.want {
				t.Errorf("Label(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestRequestHeaderAndQuery(t *testing.T) {
	r := RequestFrom(httpreq.HTTPRequest{Host: "h", Port: 80, Path: "/p", Scheme: "http", Method: "GET", Query: map[string][]string{"a": {"1", "2"}}, Headers: map[string]string{"x-k": "v"}})
	if got := r.Header("X-K"); got != "v" {
		t.Errorf("Header case-insensitive = %q, want v", got)
	}
	if got := r.Header("missing"); got != "" {
		t.Errorf("Header missing = %q, want empty", got)
	}
	if got := r.QueryParam("a"); got != "1" {
		t.Errorf("QueryParam(a) = %q, want 1", got)
	}
	if got := r.QueryParam("missing"); got != "" {
		t.Errorf("QueryParam missing = %q, want empty", got)
	}
}
