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

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestInvalidSandboxDoesNotRemoveWorkload(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	failures := newFailureRecorder()
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{validationTestWorkload("worker", "")}, options...)
	inputs.Sandboxes = krt.NewStaticCollection(nil, []model.Sandbox{{UID: "sandbox", Attester: &model.Attester{}}}, options...)
	validated := validatedDomainInputs(inputs, failures, func(name string) []krt.CollectionOption {
		return []krt.CollectionOption{krt.WithStop(stop), krt.WithName(name)}
	})
	if !validated.Workloads.WaitUntilSynced(stop) || !validated.Sandboxes.WaitUntilSynced(stop) {
		t.Fatal("sync failed")
	}
	if len(validated.Workloads.List()) != 1 || len(validated.Sandboxes.List()) != 0 {
		t.Fatal("invalid Sandbox affected endpoint discovery")
	}
}

func TestValidateDiscoveredWorkload(t *testing.T) {
	valid := validationTestWorkload("workload-a", "sandbox-a")
	valid.Principal = model.Principal{}
	tests := []struct {
		name    string
		mutate  func(*model.Workload)
		wantErr bool
	}{
		{name: "absent principal"},
		{
			name: "empty UID",
			mutate: func(workload *model.Workload) {
				workload.UID = ""
			},
			wantErr: true,
		},
		{
			name: "invalid tunnel",
			mutate: func(workload *model.Workload) {
				workload.TunnelProtocol = "invalid"
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workload := valid
			if tc.mutate != nil {
				tc.mutate(&workload)
			}
			err := validateDiscoveredWorkload(workload)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateDiscoveredWorkload() error = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

func validationTestWorkload(uid, sandboxUID string) model.Workload {
	return model.Workload{
		UID:       uid,
		Namespace: "demo",
		Principal: model.MustServiceAccountPrincipal("demo", "client"),
	}
}
