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
	"flag"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	xdsstore "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/test"
)

func TestSecurityProfileSourceWatches(t *testing.T) {
	if flag.Lookup("security-profile-source").DefValue != "kubernetes" {
		t.Fatal("default must preserve informer policy discovery")
	}
	for _, sandboxMode := range []bool{false, true} {
		test.SetForTest(t, &features.SandboxMode, sandboxMode)
		for _, source := range []string{"kubernetes", "xds"} {
			profiles := xdsstore.NewProfileSource(profilestore.NewXDSStore().ObserveAdmission, t.Context().Done())
			watches := epeWatches(source, nil, profiles)
			found := map[string]bool{}
			for _, watch := range watches {
				if watch.Wildcard {
					t.Fatal("policy discovery must start with named-only watches")
				}
				found[watch.TypeURL] = true
			}
			if !found[model.WorkloadType] || !found[model.TrafficPolicyType] {
				t.Fatal("native workload discovery is required in both modes")
			}
			if found[model.SecurityProfileType] != (source == "xds") || found[model.SandboxType] != (source == "xds" && sandboxMode) {
				t.Fatalf("%s selected unexpected policy watches: %v", source, found)
			}
		}
	}
}
