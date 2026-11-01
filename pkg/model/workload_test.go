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

package model

import "testing"

func TestWorkloadAlias(t *testing.T) {
	for _, tc := range []struct {
		source SourceRef
		want   string
	}{
		{SourceRef{Registry: "kubernetes/demo", Key: "pod-123"}, "workload-instance/kubernetes/demo/pod-123"},
		{SourceRef{Registry: "运行时", Key: "sandbox+42:/"}, "workload-instance/运行时/sandbox%2B42%3A%2F"},
		{SourceRef{Registry: "runtime", Key: "a/b% c-._~"}, "workload-instance/runtime/a%2Fb%25%20c-._~"},
	} {
		if got := tc.source.WorkloadAlias(); got != tc.want {
			t.Errorf("%+v alias = %q, want %q", tc.source, got, tc.want)
		}
	}
}

func TestTunnelProtocolValidateRejectsUnknownProtocol(t *testing.T) {
	for _, protocol := range []TunnelProtocol{"", TunnelProtocolNone, TunnelProtocolHBONE} {
		if err := protocol.Validate(); err != nil {
			t.Fatalf("valid tunnel protocol %q rejected: %v", protocol, err)
		}
	}
	if err := (TunnelProtocol("unknown")).Validate(); err == nil {
		t.Fatal("unknown tunnel protocol accepted")
	}
}
