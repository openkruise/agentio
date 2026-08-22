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

package spstatus

import (
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
)

func buildCollection(t *testing.T, inputs []any) (krt.Collection[ProfileStatus], *krttest.MockCollection) {
	t.Helper()
	stop := test.NewStop(t)
	mock := krttest.NewMock(t, inputs)
	profiles := krttest.GetMockCollection[*agentsv1alpha1.SecurityProfile](mock)
	secrets := krttest.GetMockCollection[*corev1.Secret](mock)
	opts := krt.NewOptionsBuilder(stop, "test", krt.GlobalDebugHandler)
	col := NewCollection(profiles, secrets, opts)
	col.WaitUntilSynced(stop)
	return col, mock
}

func statusOf(t *testing.T, col krt.Collection[ProfileStatus], key string) agentsv1alpha1.SecurityProfileStatus {
	t.Helper()
	got := col.GetKey(key)
	if got == nil {
		t.Fatalf("no entry for key %q; have %d entries", key, len(col.List()))
	}
	return got.Status
}

func TestCollectionCleanProfile(t *testing.T) {
	sp := profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKindSecret, "cred")
	sp.Generation = 5
	col, _ := buildCollection(t, []any{sp, secret("ns-a", "cred")})

	st := statusOf(t, col, "ns-a/sp")
	assert.Equal(t, st.ObservedGeneration, int64(5))
	assert.Equal(t, len(st.Conditions), 3)
	assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionAccepted).Status, metav1.ConditionTrue)
	assert.Equal(t, condOf(t, st, ConditionResolvedRefs).Status, metav1.ConditionTrue)
	assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionProgrammed).Status, metav1.ConditionTrue)
}

// The missing secret must surface on ResolvedRefs only.
func TestCollectionMissingSecret(t *testing.T) {
	sp := profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKindSecret, "cred")
	col, _ := buildCollection(t, []any{sp})

	st := statusOf(t, col, "ns-a/sp")
	assert.Equal(t, condOf(t, st, ConditionResolvedRefs).Status, metav1.ConditionFalse)
	assert.Equal(t, condOf(t, st, ConditionResolvedRefs).Reason, ReasonSecretNotFound)
	assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionAccepted).Status, metav1.ConditionTrue)
	assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionProgrammed).Status, metav1.ConditionTrue)
}

func TestCollectionInvalidSpec(t *testing.T) {
	sp := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "sp"},
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Rules: []agentsv1alpha1.SecurityRule{{
				Name: "r1",
				Match: []agentsv1alpha1.RuleMatch{{
					Domains: []string{"*"},
					Paths: []agentsv1alpha1.PathMatch{
						{Type: agentsv1alpha1.PathMatchTypeRegex, Value: "("},
					},
				}},
			}},
		},
	}
	col, _ := buildCollection(t, []any{sp})

	st := statusOf(t, col, "ns-a/sp")
	assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionAccepted).Status, metav1.ConditionFalse)
	assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionAccepted).Reason, ReasonInvalidRegex)
	assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionProgrammed).Status, metav1.ConditionFalse)
	assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionProgrammed).Reason, ReasonNotAccepted)
}

// Obj must carry the live object so the writer can compare live vs desired
// without re-reading the apiserver.
func TestCollectionCarriesLiveObject(t *testing.T) {
	sp := profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKindSecret, "cred")
	sp.Status = agentsv1alpha1.SecurityProfileStatus{ObservedGeneration: 99}
	col, _ := buildCollection(t, []any{sp, secret("ns-a", "cred")})

	got := col.GetKey("ns-a/sp")
	if got == nil {
		t.Fatal("no entry")
	}
	assert.Equal(t, got.Obj.Name, "sp")
	assert.Equal(t, got.Obj.Status.ObservedGeneration, int64(99))
	assert.Equal(t, got.ResourceName(), "ns-a/sp")
}

// Adding the referenced secret must recompute ResolvedRefs: this proves the
// Secrets collection is a tracked krt dependency, not a one-shot read.
func TestCollectionRecomputesWhenSecretAppears(t *testing.T) {
	stop := test.NewStop(t)
	sp := profileWithCredRef("ns-a", agentsv1alpha1.CredentialRefKindSecret, "cred")
	mock := krttest.NewMock(t, []any{sp})
	profiles := krttest.GetMockCollection[*agentsv1alpha1.SecurityProfile](mock)
	secrets := krt.NewStaticCollection[*corev1.Secret](nil, nil, krt.WithStop(stop))
	opts := krt.NewOptionsBuilder(stop, "test", krt.GlobalDebugHandler)
	col := NewCollection(profiles, secrets, opts)
	col.WaitUntilSynced(stop)

	assert.EventuallyEqual(t, func() metav1.ConditionStatus {
		return condOf(t, statusOf(t, col, "ns-a/sp"), ConditionResolvedRefs).Status
	}, metav1.ConditionFalse)

	secrets.UpdateObject(secret("ns-a", "cred"))

	assert.EventuallyEqual(t, func() metav1.ConditionStatus {
		return condOf(t, statusOf(t, col, "ns-a/sp"), ConditionResolvedRefs).Status
	}, metav1.ConditionTrue)
}
