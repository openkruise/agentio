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

package kubernetes

import (
	"reflect"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

func TestPolicyModelsUseSelector(t *testing.T) {
	metadata := metav1.ObjectMeta{
		UID:         "policy-source",
		Name:        "policy",
		Namespace:   "demo",
		Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "kruise:annotation"},
	}
	for _, tc := range []struct {
		name     string
		selector metav1.LabelSelector
	}{
		{
			name: "matchLabels",
			selector: metav1.LabelSelector{
				MatchLabels: map[string]string{agentsv1alpha1.LabelSandboxID: "selected"},
			},
		},
		{
			name: "matchExpressions",
			selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      agentsv1alpha1.LabelSandboxID,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"selected"},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, global := range []bool{false, true} {
				traffic := trafficPolicyModel(
					metadata,
					&agentsv1alpha1.TrafficPolicySpec{Selector: tc.selector},
					global,
				)
				profile := securityProfileModel(metadata, &agentsv1alpha1.SecurityProfileSpec{
					Selector: tc.selector,
					Rules: []agentsv1alpha1.SecurityRule{
						{
							Match: []agentsv1alpha1.RuleMatch{
								{
									Domains: []string{"api.example"},
								},
							},
						},
					},
				}, global)

				if traffic.GetUID() != "policy-source" || profile.GetUID() != "policy-source" {
					t.Fatal("policy model lost the source object UID")
				}
				if !reflect.DeepEqual(traffic.Spec.Selector, tc.selector) ||
					!reflect.DeepEqual(profile.Spec.Selector, tc.selector) {
					t.Fatal("policy model changed the selector")
				}
				compiled, err := policy.CompileSecurityProfile(*profile)
				if err != nil {
					t.Fatal(err)
				}
				for _, subject := range []struct {
					name      string
					uid       string
					namespace string
					label     string
					want      bool
				}{
					{
						name:      "matching label",
						uid:       "kruise:selected",
						namespace: "demo",
						label:     "selected",
						want:      true,
					},
					{
						name:      "annotation does not select",
						uid:       "kruise:annotation",
						namespace: "demo",
						label:     "other",
					},
					{
						name:      "label does not imply runtime or UID",
						uid:       "workload:other",
						namespace: "demo",
						label:     "selected",
						want:      true,
					},
					{
						name:      "namespace scope is preserved",
						uid:       "kruise:selected",
						namespace: "other",
						label:     "selected",
						want:      global,
					},
				} {
					selected := compiled.Attachment.Selects(model.Workload{
						UID:       subject.uid,
						Namespace: subject.namespace,
						Labels:    map[string]string{agentsv1alpha1.LabelSandboxID: subject.label},
					})
					if selected != subject.want {
						t.Fatalf("global=%t, %s: selected=%t, want %t", global, subject.name, selected, subject.want)
					}
				}
			}
		})
	}
}
