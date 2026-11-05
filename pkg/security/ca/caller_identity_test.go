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

package ca

import (
	"fmt"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

func TestSelfRequestWithoutSourceDoesNotRequireTargetAuthorization(t *testing.T) {
	caller := peerIdentity("demo", "app")
	caller.Kubernetes.WorkloadName, caller.Kubernetes.WorkloadUID = "", ""
	want := model.MustServiceAccountPrincipal("demo", "app")
	authorizer := &fakeDelegatedIdentityAuthorizer{err: fmt.Errorf("instance authorization must not run")}
	authority := certificateAuthority(t, caller, authorizer)
	response, err := authority.CreateCertificate(t.Context(), requestWithCSR(t, want.String()))
	if err != nil || authorizer.calls != 0 {
		t.Fatalf("self request: %v, calls=%d", err, authorizer.calls)
	}
	if responseIdentity(t, response) != want.String() {
		t.Fatal("wrong caller SAN")
	}
}
