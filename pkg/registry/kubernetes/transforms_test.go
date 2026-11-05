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
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestStripTrafficPolicy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		obj   any
		check func(t *testing.T, got any)
	}{
		{
			name:  "namespaced",
			obj:   &agentsv1alpha1.TrafficPolicy{ObjectMeta: policyObjectMeta(), Spec: trafficPolicySpec(), Status: agentsv1alpha1.TrafficPolicyStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}}}},
			check: func(t *testing.T, got any) { checkTrafficPolicy(t, got.(*agentsv1alpha1.TrafficPolicy)) },
		},
		{
			name:  "global",
			obj:   &agentsv1alpha1.GlobalTrafficPolicy{ObjectMeta: policyObjectMeta(), Spec: trafficPolicySpec(), Status: agentsv1alpha1.TrafficPolicyStatus{Conditions: []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue}}}},
			check: func(t *testing.T, got any) { checkTrafficPolicy(t, got.(*agentsv1alpha1.GlobalTrafficPolicy)) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stripTrafficPolicy(tc.obj)
			if err != nil {
				t.Fatalf("stripTrafficPolicy(): %v", err)
			}
			if got == tc.obj {
				t.Fatal("stripTrafficPolicy() returned the caller-owned object")
			}
			tc.check(t, got)
			if !hasPolicyMetadata(tc.obj) {
				t.Fatal("stripTrafficPolicy() mutated the caller-owned object")
			}
		})
	}
}

func TestStripSecurityProfile(t *testing.T) {
	priority := int32(23)
	for _, tc := range []struct {
		name  string
		obj   any
		check func(t *testing.T, got any)
	}{
		{
			name:  "namespaced",
			obj:   &agentsv1alpha1.SecurityProfile{ObjectMeta: policyObjectMeta(), Spec: securityProfileSpec(&priority), Status: agentsv1alpha1.SecurityProfileStatus{ObservedGeneration: 7}},
			check: func(t *testing.T, got any) { checkSecurityProfile(t, got.(*agentsv1alpha1.SecurityProfile)) },
		},
		{
			name:  "global",
			obj:   &agentsv1alpha1.GlobalSecurityProfile{ObjectMeta: policyObjectMeta(), Spec: securityProfileSpec(&priority), Status: agentsv1alpha1.SecurityProfileStatus{ObservedGeneration: 7}},
			check: func(t *testing.T, got any) { checkSecurityProfile(t, got.(*agentsv1alpha1.GlobalSecurityProfile)) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stripSecurityProfile(tc.obj)
			if err != nil {
				t.Fatalf("stripSecurityProfile(): %v", err)
			}
			if got == tc.obj {
				t.Fatal("stripSecurityProfile() returned the caller-owned object")
			}
			tc.check(t, got)
			if !hasPolicyMetadata(tc.obj) {
				t.Fatal("stripSecurityProfile() mutated the caller-owned object")
			}
		})
	}
}

func policyObjectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:              "policy",
		Namespace:         "sandbox",
		UID:               types.UID("uid"),
		ResourceVersion:   "42",
		Generation:        7,
		CreationTimestamp: metav1.NewTime(time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)),
		Labels:            map[string]string{"unused": "label"},
		Annotations: map[string]string{
			"istio.io/dry-run":                 "true",
			agentsv1alpha1.AnnotationSandboxID: "sandbox-a",
			"unused":                           "annotation",
		},
		Finalizers:      []string{"unused"},
		OwnerReferences: []metav1.OwnerReference{{Name: "unused"}},
		ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "test"}},
	}
}

func trafficPolicySpec() agentsv1alpha1.TrafficPolicySpec {
	return agentsv1alpha1.TrafficPolicySpec{
		Priority: 17,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
		Egress: &agentsv1alpha1.TrafficPolicyDirection{
			Rules: []agentsv1alpha1.TrafficPolicyRule{
				{
					Action: agentsv1alpha1.RuleActionAllow,
					To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "api.example.com"}},
				},
			},
		},
	}
}

func securityProfileSpec(priority *int32) agentsv1alpha1.SecurityProfileSpec {
	return agentsv1alpha1.SecurityProfileSpec{
		Priority: priority,
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
		Rules: []agentsv1alpha1.SecurityRule{
			{
				Name:    "block-api",
				Match:   []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
				Actions: agentsv1alpha1.SecurityRuleActions{Block: &agentsv1alpha1.BlockAction{StatusCode: 403}},
			},
		},
	}
}

func checkTrafficPolicy(t *testing.T, policy any) {
	t.Helper()
	meta := policy.(metav1.Object)
	checkStrippedPolicyMeta(t, meta, nil)
	switch traffic := policy.(type) {
	case *agentsv1alpha1.TrafficPolicy:
		if !reflect.DeepEqual(traffic.Spec, trafficPolicySpec()) || len(traffic.Status.Conditions) != 0 {
			t.Fatalf("traffic policy fields were not retained and stripped correctly: %+v", policy)
		}
	case *agentsv1alpha1.GlobalTrafficPolicy:
		if !reflect.DeepEqual(traffic.Spec, trafficPolicySpec()) || len(traffic.Status.Conditions) != 0 {
			t.Fatalf("global traffic policy fields were not retained and stripped correctly: %+v", policy)
		}
	default:
		t.Fatalf("traffic policy fields were not retained and stripped correctly: %+v", policy)
	}
}

func checkSecurityProfile(t *testing.T, profile any) {
	t.Helper()
	meta := profile.(metav1.Object)
	checkStrippedPolicyMeta(t, meta, nil)
	switch security := profile.(type) {
	case *agentsv1alpha1.SecurityProfile:
		if !reflect.DeepEqual(security.Spec, securityProfileSpec(int32Ptr(23))) ||
			!reflect.DeepEqual(security.Status, agentsv1alpha1.SecurityProfileStatus{}) {
			t.Fatalf("security profile fields were not retained and stripped correctly: %+v", profile)
		}
	case *agentsv1alpha1.GlobalSecurityProfile:
		if !reflect.DeepEqual(security.Spec, securityProfileSpec(int32Ptr(23))) ||
			!reflect.DeepEqual(security.Status, agentsv1alpha1.SecurityProfileStatus{}) {
			t.Fatalf("global security profile fields were not retained and stripped correctly: %+v", profile)
		}
	default:
		t.Fatalf("security profile fields were not retained and stripped correctly: %+v", profile)
	}
}

func int32Ptr(value int32) *int32 { return &value }

func checkStrippedPolicyMeta(t *testing.T, meta metav1.Object, annotations map[string]string) {
	t.Helper()
	creationTime := meta.GetCreationTimestamp()
	if meta.GetName() != "policy" || meta.GetNamespace() != "sandbox" || meta.GetUID() != "uid" ||
		meta.GetResourceVersion() != "42" ||
		meta.GetGeneration() != 7 ||
		!creationTime.Time.Equal(time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("required metadata changed: %+v", meta)
	}
	if !reflect.DeepEqual(meta.GetAnnotations(), annotations) || meta.GetLabels() != nil ||
		len(meta.GetFinalizers()) != 0 ||
		len(meta.GetOwnerReferences()) != 0 ||
		len(meta.GetManagedFields()) != 0 {
		t.Fatalf("unused metadata was not stripped: %+v", meta)
	}
}

func hasPolicyMetadata(obj any) bool {
	meta := obj.(metav1.Object)
	return meta.GetLabels()["unused"] == "label" && meta.GetAnnotations()["unused"] == "annotation" &&
		len(meta.GetManagedFields()) == 1
}
