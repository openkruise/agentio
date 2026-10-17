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

package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	workload "github.com/openkruise/agentio/api/workload/v1"
)

func TestObservedRevision(t *testing.T) {
	resource := workloadResource(23456, 7)
	value, err := observedWorkload(resource.Value)
	if err != nil {
		t.Fatal(err)
	}
	got := value.(observedResource)
	if got.Index != 23456 || got.Revision != 7 || time.Since(got.Received) > time.Second {
		t.Fatalf("wrong observation: %+v", got)
	}
	_, err = observedWorkload(
		anyOf(
			&workload.Address{Type: &workload.Address_Workload{Workload: &workload.Workload{Name: "workload-23456"}}},
		),
	)
	if err == nil {
		t.Fatal("missing revision must not be accepted")
	}
}

func TestObservationRearm(t *testing.T) {
	o := newObservations(100)
	old := o.wake
	request := httptest.NewRequest("GET", "/observe?count=5000&revision=4", nil)
	response := httptest.NewRecorder()
	o.arm(response, request)
	if response.Code != 200 || o.count != 5000 || o.revision != 4 || o.start.IsZero() {
		t.Fatalf("arm: %s", response.Body)
	}
	select {
	case <-old:
	default:
		t.Fatal("observers not notified")
	}
	o.times[0] = 1
	o.arm(httptest.NewRecorder(), httptest.NewRequest("GET", "/observe?count=50000&revision=4&fresh=true", nil))
	if o.times[0] != 0 || !o.fresh {
		t.Fatal("old convergence leaked into reconnect")
	}
}

func TestCanceledClientPhasePreservesResult(t *testing.T) {
	certs = certificates(1, 0)
	maxDuration = time.Second
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result := phase(ctx, nil, "workload", 10, 1, 1, 0, 0)
	if result.RunError != context.Canceled.Error() || result.Operations != 0 || result.ActiveTarget != 1 {
		t.Fatalf("lost canceled phase result: %+v", result)
	}
}
