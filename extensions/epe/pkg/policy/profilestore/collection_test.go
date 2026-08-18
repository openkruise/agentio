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
package profilestore

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsfake "github.com/openkruise/agents-api/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient/clienttest"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/retry"
)

func TestProfileCollection_ConfigMapInputDependency(t *testing.T) {
	profile := newTestProfile("with-inputs", "ns-a", map[string]string{"app": "test"})
	profile.Spec.Inputs = []v1alpha1.SecurityProfileInput{
		{Name: "inline", Inline: map[string]string{"region": "cn-hangzhou"}},
		{Name: "routing", ConfigMap: &v1alpha1.ConfigMapInputRef{Name: "routing"}},
	}
	agentsCS := agentsfake.NewSimpleClientset(profile)
	RegisterTypes(agentsCS)

	c := kube.NewFakeClient(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "routing", Namespace: "ns-a"},
		Data:       map[string]string{"tenant-a": "provider-a"},
	})
	clienttest.MakeCRD(t, c, securityProfileGVR)
	clienttest.MakeCRD(t, c, globalSecurityProfileGVR)
	stop := test.NewStop(t)

	store := NewStore()
	profiles := NewCollection(c, krt.GlobalDebugHandler, stop)
	reg := store.RegisterCollection(profiles)
	c.RunAndWait(stop)
	if !reg.WaitUntilSynced(stop) {
		t.Fatal("profile collection handler never synced")
	}

	assertInputs := func(want map[string]any) error {
		matched := store.Matches("", "ns-a", map[string]string{"app": "test"})
		if len(matched) != 1 {
			return fmt.Errorf("matched profiles = %d, want 1", len(matched))
		}
		if !reflect.DeepEqual(matched[0].Inputs, want) {
			return fmt.Errorf("inputs = %#v, want %#v", matched[0].Inputs, want)
		}
		return nil
	}

	retry.UntilSuccessOrFail(t, func() error {
		return assertInputs(map[string]any{
			"inline":  map[string]string{"region": "cn-hangzhou"},
			"routing": map[string]string{"tenant-a": "provider-a"},
		})
	}, retry.Timeout(5*time.Second))

	ctx := test.NewContext(t)
	cm, err := c.Kube().CoreV1().ConfigMaps("ns-a").Get(ctx, "routing", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data = map[string]string{"tenant-a": "provider-b"}
	if _, err := c.Kube().CoreV1().ConfigMaps("ns-a").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	retry.UntilSuccessOrFail(t, func() error {
		return assertInputs(map[string]any{
			"inline":  map[string]string{"region": "cn-hangzhou"},
			"routing": map[string]string{"tenant-a": "provider-b"},
		})
	}, retry.Timeout(5*time.Second))

	if err := c.Kube().CoreV1().ConfigMaps("ns-a").Delete(ctx, "routing", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		compiled := profiles.GetKey("ns-a/with-inputs")
		if compiled == nil || compiled.CompileError == "" {
			return fmt.Errorf("profile collection has not observed the missing ConfigMap")
		}
		return assertInputs(map[string]any{
			"inline":  map[string]string{"region": "cn-hangzhou"},
			"routing": map[string]string{"tenant-a": "provider-b"},
		})
	}, retry.Timeout(5*time.Second))
}

// TestProfileCollection_EndToEnd drives the krt-backed collection into the
// store against fake clients: initial state replay, live adds for both
// scopes, updates, invalid-update LKG retention, and deletes.
func TestProfileCollection_EndToEnd(t *testing.T) {
	existing := newTestProfile("existing", "ns-a", map[string]string{"app": "test"})
	agentsCS := agentsfake.NewSimpleClientset(existing)
	RegisterTypes(agentsCS)

	c := kube.NewFakeClient()
	clienttest.MakeCRD(t, c, securityProfileGVR)
	clienttest.MakeCRD(t, c, globalSecurityProfileGVR)
	stop := test.NewStop(t)
	c.RunAndWait(stop)

	store := NewStore()
	profiles := NewCollection(c, krt.GlobalDebugHandler, stop)
	reg := store.RegisterCollection(profiles)
	if !reg.WaitUntilSynced(stop) {
		t.Fatal("profile collection handler never synced")
	}

	ctx := test.NewContext(t)

	// Initial state replay delivers the pre-existing profile.
	retry.UntilSuccessOrFail(t, func() error {
		if n := len(store.Matches("", "ns-a", map[string]string{"app": "test"})); n != 1 {
			return fmt.Errorf("expected 1 match in ns-a, got %d", n)
		}
		return nil
	}, retry.Timeout(5*time.Second))

	// Live SecurityProfile add.
	live := newTestProfile("live", "ns-b", map[string]string{"app": "test"})
	if _, err := agentsCS.AgentsV1alpha1().SecurityProfiles("ns-b").Create(ctx, live, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		if n := len(store.Matches("", "ns-b", map[string]string{"app": "test"})); n != 1 {
			return fmt.Errorf("expected 1 match in ns-b, got %d", n)
		}
		return nil
	}, retry.Timeout(5*time.Second))

	// Live GlobalSecurityProfile add matches pods in every namespace.
	gsp := newTestGlobalProfile("global", map[string]string{"app": "test"})
	if _, err := agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Create(ctx, gsp, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		if n := len(store.Matches("", "ns-c", map[string]string{"app": "test"})); n != 1 {
			return fmt.Errorf("expected global profile to match ns-c, got %d", n)
		}
		return nil
	}, retry.Timeout(5*time.Second))

	// An update that turns the profile invalid remains visible in the compiled
	// collection, while the store continues serving the last-known-good profile.
	bad := live.DeepCopy()
	bad.Spec.Selector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "!", Operator: metav1.LabelSelectorOpExists,
	}}}
	if _, err := agentsCS.AgentsV1alpha1().SecurityProfiles("ns-b").Update(ctx, bad, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		compiled := profiles.GetKey("ns-b/live")
		if compiled == nil || compiled.CompileError == "" {
			return fmt.Errorf("compiled collection has not observed invalid update")
		}
		matched := store.Matches("", "ns-b", map[string]string{"app": "test"})
		if len(matched) != 2 {
			names := make([]string, 0, len(matched))
			for _, sp := range matched {
				names = append(names, sp.Meta.Name)
			}
			return fmt.Errorf("expected invalid update to retain live plus global profiles, got %v", names)
		}
		return nil
	}, retry.Timeout(5*time.Second))

	// Delete removes the cluster-scoped profile.
	if err := agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Delete(ctx, "global", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	retry.UntilSuccessOrFail(t, func() error {
		if n := len(store.Matches("", "ns-c", map[string]string{"app": "test"})); n != 0 {
			return fmt.Errorf("expected global profile removal, still %d matches", n)
		}
		return nil
	}, retry.Timeout(5*time.Second))
}

// The Sandbox CRD may be absent: the EPE chart does not install the
// agents.kruise.io CRDs, and the e2e clusters start without them. The joined
// collection must still sync so startup is not wedged behind
// WaitUntilSynced. The fake apiserver tolerates unknown GVRs, so this test
// cannot reproduce the real 404-retry hang of a non-delayed informer; it
// pins the delayed-informer wiring (CRD-absent sync plus an empty result
// set) so the intent documented here stays visible.
func TestProfileCollection_SyncsWithoutSandboxCRD(t *testing.T) {
	agentsCS := agentsfake.NewSimpleClientset()
	RegisterTypes(agentsCS)

	c := kube.NewFakeClient()
	clienttest.MakeCRD(t, c, securityProfileGVR)
	clienttest.MakeCRD(t, c, globalSecurityProfileGVR)
	// Deliberately no Sandbox CRD.
	stop := test.NewStop(t)

	store := NewStore()
	profiles := NewCollection(c, krt.GlobalDebugHandler, stop)
	reg := store.RegisterCollection(profiles)
	c.RunAndWait(stop)

	synced := make(chan struct{})
	go func() {
		if reg.WaitUntilSynced(stop) {
			close(synced)
		}
	}()
	select {
	case <-synced:
	case <-time.After(10 * time.Second):
		t.Fatal("collection did not sync while the Sandbox CRD is absent")
	}
	if got := store.Matches("sbx-1", "sandboxes", nil); len(got) != 0 {
		t.Fatalf("Matches = %+v, want no profiles without the CRD", got)
	}
}
