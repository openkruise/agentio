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

package charts_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestAgentiodPolicyStatusRBAC(t *testing.T) {
	manifest := renderAgentio(t, "--show-only", "templates/agentiod/rbac.yaml")
	found := false
	for document := range strings.SplitSeq(manifest, "\n---") {
		var role rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(document), &role); err != nil {
			t.Fatal(err)
		}
		if role.Kind != "ClusterRole" {
			continue
		}
		for _, rule := range role.Rules {
			if slices.Contains(rule.Resources, "secrets") {
				t.Fatal("status reporting expanded Secret access")
			}
			if !slices.Contains(rule.Resources, "securityprofiles/status") {
				continue
			}
			want := rbacv1.PolicyRule{
				APIGroups: []string{"agents.kruise.io"},
				Resources: []string{
					"securityprofiles/status",
					"globalsecurityprofiles/status",
					"trafficpolicies/status",
					"globaltrafficpolicies/status",
				},
				Verbs: []string{"patch"},
			}
			if !reflect.DeepEqual(rule, want) {
				t.Fatalf("unexpected status rule: %+v", rule)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing policy status permissions")
	}
}
