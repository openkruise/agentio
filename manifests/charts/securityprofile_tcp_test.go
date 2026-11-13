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
	"os"
	"path/filepath"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func TestSecurityProfileCRDsPreserveTCPRules(t *testing.T) {
	for _, chart := range []string{"agentio", "agentio/integrations/openkruise/sandbox-manager/files/agentio"} {
		for _, name := range []string{"securityprofiles.yaml", "globalsecurityprofiles.yaml"} {
			path := filepath.Join(chart, "crds", name)
			t.Run(path, func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var crd apiextensionsv1.CustomResourceDefinition
				if err := yaml.Unmarshal(data, &crd); err != nil {
					t.Fatal(err)
				}
				for _, version := range crd.Spec.Versions {
					tcp := version.Schema.OpenAPIV3Schema.Properties["spec"].Properties["tcpRules"]
					if tcp.Type != "array" {
						t.Fatalf("%s schema does not preserve tcpRules", version.Name)
					}
					rule := tcp.Items.Schema
					if rule.Properties["action"].Type != "string" || rule.Properties["match"].Type != "array" {
						t.Fatalf("%s schema does not preserve TCP rule action and match", version.Name)
					}
					actions := rule.Properties["action"].Enum
					if len(actions) != 2 || string(actions[0].Raw) != `"Allow"` || string(actions[1].Raw) != `"Deny"` {
						t.Fatalf("%s TCP actions must be Allow and Deny: %v", version.Name, actions)
					}
					cidr := rule.Properties["match"].Items.Schema.Properties["cidrs"].Items.Schema
					if cidr.Type != "string" || cidr.Format != "" || len(cidr.XValidations) != 0 {
						t.Fatalf("%s TCP destinations must accept IP addresses and CIDRs: %+v", version.Name, cidr)
					}
				}
			})
		}
	}
}
