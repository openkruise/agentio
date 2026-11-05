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

import (
	"slices"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
)

func TestNewGatewayPatchNormalizesTargetsAndClonesTypedValues(t *testing.T) {
	policy, err := NewGatewayPatch(GatewayPatchMetadata{
		Namespace: "sandbox-traffic-system",
		Name:      "patches",
		Source:    "sandbox-traffic-system/source",
	}, 10, []string{
		"sandbox-traffic-system/egress-z",
		"sandbox-traffic-system/egress-a",
		"sandbox-traffic-system/egress-z",
	}, []EnvoyPatch{{
		Operation: PatchMerge,
		Target: ClusterPatch{
			Match: &ClusterMatch{Name: "tls_connect_originate"},
			Value: &clusterv3.Cluster{Name: "tls_connect_originate"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := policy.TargetGateways, []string{
		"sandbox-traffic-system/egress-a",
		"sandbox-traffic-system/egress-z",
	}; !slices.Equal(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}

	clone := policy.Clone()
	if !policy.Equals(clone) {
		t.Fatal("clone differs from original")
	}
	cluster := clone.Patches[0].Target.(ClusterPatch)
	cluster.Value.AltStatName = "changed"
	if policy.Equals(clone) {
		t.Fatal("nested protobuf mutation was ignored")
	}
	original := policy.Patches[0].Target.(ClusterPatch)
	if original.Value.GetAltStatName() != "" {
		t.Fatalf("clone mutated original: %+v", original.Value)
	}
	if got, want := policy.LogicalName(), "sandbox-traffic-system/patches"; got != want {
		t.Fatalf("logical name = %q, want %q", got, want)
	}
	if got, want := policy.ResourceName(), "sandbox-traffic-system/source|sandbox-traffic-system/patches"; got != want {
		t.Fatalf("resource name = %q, want %q", got, want)
	}
}

func TestNewGatewayPatchRejectsInvalidValues(t *testing.T) {
	validTarget := ClusterPatch{Value: &clusterv3.Cluster{Name: "cluster"}}
	tests := []struct {
		name     string
		metadata GatewayPatchMetadata
		targets  []string
		patch    EnvoyPatch
		wantErr  bool
	}{
		{
			name:     "empty identity",
			metadata: GatewayPatchMetadata{Source: "source"},
			targets:  []string{"demo/gateway"},
			patch:    EnvoyPatch{Operation: PatchAdd, Target: validTarget},
			wantErr:  true,
		},
		{
			name:     "empty target",
			metadata: GatewayPatchMetadata{Namespace: "demo", Name: "filter", Source: "source"},
			targets:  []string{""},
			patch:    EnvoyPatch{Operation: PatchAdd, Target: validTarget},
			wantErr:  true,
		},
		{
			name:     "no targets",
			metadata: GatewayPatchMetadata{Namespace: "demo", Name: "filter", Source: "source"},
			patch:    EnvoyPatch{Operation: PatchAdd, Target: validTarget},
			wantErr:  true,
		},
		{
			name:     "nil patch target",
			metadata: GatewayPatchMetadata{Namespace: "demo", Name: "filter", Source: "source"},
			targets:  []string{"demo/gateway"},
			patch:    EnvoyPatch{Operation: PatchAdd},
			wantErr:  true,
		},
		{
			name:     "invalid operation",
			metadata: GatewayPatchMetadata{Namespace: "demo", Name: "filter", Source: "source"},
			targets:  []string{"demo/gateway"},
			patch:    EnvoyPatch{Target: validTarget},
			wantErr:  true,
		},
		{
			name:     "nil merge value",
			metadata: GatewayPatchMetadata{Namespace: "demo", Name: "filter", Source: "source"},
			targets:  []string{"demo/gateway"},
			patch:    EnvoyPatch{Operation: PatchMerge, Target: ClusterPatch{}},
			wantErr:  true,
		},
		{
			name:     "unsupported cluster replace",
			metadata: GatewayPatchMetadata{Namespace: "demo", Name: "filter", Source: "source"},
			targets:  []string{"demo/gateway"},
			patch:    EnvoyPatch{Operation: PatchReplace, Target: validTarget},
			wantErr:  true,
		},
		{
			name:     "nil remove value",
			metadata: GatewayPatchMetadata{Namespace: "demo", Name: "filter", Source: "source"},
			targets:  []string{"demo/gateway"},
			patch:    EnvoyPatch{Operation: PatchRemove, Target: ClusterPatch{}},
			wantErr:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGatewayPatch(tc.metadata, 0, tc.targets, []EnvoyPatch{tc.patch})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewGatewayPatchRejectsEmptyPatchPlan(t *testing.T) {
	_, err := NewGatewayPatch(GatewayPatchMetadata{
		Namespace: "demo",
		Name:      "filter",
		Source:    "source",
	}, 0, []string{"demo/gateway"}, nil)
	if err == nil {
		t.Fatal("empty patch plan accepted")
	}
}
