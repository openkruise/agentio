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

package compiler

import (
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestWDSIdentityProjectionChecksNamespace(t *testing.T) {
	principal := model.MustPrincipal("cluster.local", "ns/demo/sa/app")
	for _, tc := range []struct {
		namespace string
		wantErr   bool
	}{
		{"demo", false}, {"other", true},
	} {
		input := wdsProjection{
			Workload: model.Workload{UID: "pod", Namespace: tc.namespace, Principal: principal},
		}
		domain, account, err := projectWorkloadIdentity(input)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%+v: %v", tc, err)
		}
		if err == nil && (domain != "cluster.local" || account != "app") {
			t.Fatalf("projection: %s/%s", domain, account)
		}
	}
}
