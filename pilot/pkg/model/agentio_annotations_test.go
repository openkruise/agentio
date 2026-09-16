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
package model

import (
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestAgentioTrafficDistribution(t *testing.T) {
	annotations := map[string]string{
		"networking.istio.io/traffic-distribution":          "PreferSameNode",
		"networking.agentio.kruise.io/traffic-distribution": "PreferClose",
	}
	if got := GetTrafficDistribution(nil, annotations); got != TrafficDistributionPreferSameZone {
		t.Fatalf("distribution = %v", got)
	}
	annotations["networking.agentio.kruise.io/traffic-distribution"] = ""
	if got := GetTrafficDistribution(nil, annotations); got != TrafficDistributionAny {
		t.Fatalf("empty override = %v", got)
	}
	spec := corev1.ServiceTrafficDistributionPreferSameNode
	if got := GetTrafficDistribution(&spec, annotations); got != TrafficDistributionPreferSameNode {
		t.Fatalf("spec precedence = %v", got)
	}
}
