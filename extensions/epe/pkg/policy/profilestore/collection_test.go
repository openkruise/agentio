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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
)

type profileTestClient struct {
	kube.Client
}

func (c *profileTestClient) CrdWatcher() kube.CrdWatcher {
	return knownCRDWatcher{securityProfileGVR: {}, globalSecurityProfileGVR: {}}
}

type knownCRDWatcher map[schema.GroupVersionResource]struct{}

func (w knownCRDWatcher) HasSynced() bool { return true }

func (w knownCRDWatcher) KnownOrCallback(resource schema.GroupVersionResource, _ func(<-chan struct{})) bool {
	_, found := w[resource]
	return found
}

func (w knownCRDWatcher) WaitForCRD(resource schema.GroupVersionResource, _ <-chan struct{}) bool {
	_, found := w[resource]
	return found
}

func (knownCRDWatcher) Run(<-chan struct{}) {}

func newProfileTestClient(objects ...runtime.Object) kube.Client {
	return &profileTestClient{Client: kube.NewFakeClient(objects...)}
}

func TestProfileCollection_ConfigMapInputDependency(t *testing.T) {
	profile := newTestProfile("with-inputs", "ns-a", map[string]string{"app": "test"})
	profile.Spec.Inputs = []v1alpha1.SecurityProfileInput{
		{Name: "inline", Inline: map[string]string{"region": "cn-hangzhou"}},
		{Name: "routing", ConfigMap: &v1alpha1.ConfigMapInputRef{Name: "routing"}},
	}
	c := newProfileTestClient(profile, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "routing", Namespace: "ns-a"},
		Data:       map[string]string{"tenant-a": "provider-a"},
	})
	stop := t.Context().Done()

	store := NewStore()
	profiles := NewCollection(c, nil, krt.GlobalDebugHandler, stop)
	reg := store.RegisterCollection(profiles)
	c.Run(stop)
	if !reg.WaitUntilSynced(stop) {
		t.Fatal("profile collection handler never synced")
	}

	assertState := func(wantInputs map[string]any, wantUnavailable bool) error {
		matched := store.ProfilesFor(inputs.Pod{Namespace: "ns-a", Labels: map[string]string{"app": "test"}})
		if len(matched) != 1 {
			return fmt.Errorf("matched profiles = %d, want 1", len(matched))
		}
		if !reflect.DeepEqual(matched[0].Inputs, wantInputs) {
			return fmt.Errorf("inputs = %#v, want %#v", matched[0].Inputs, wantInputs)
		}
		if unavailable := matched[0].InputsError != ""; unavailable != wantUnavailable {
			return fmt.Errorf("InputsError = %q, want unavailable=%v", matched[0].InputsError, wantUnavailable)
		}
		return nil
	}

	testsupport.Eventually(t, 5*time.Second, func() error {
		return assertState(map[string]any{
			"inline":  map[string]string{"region": "cn-hangzhou"},
			"routing": map[string]string{"tenant-a": "provider-a"},
		}, false)
	})

	ctx := t.Context()
	cm, err := c.Kube().CoreV1().ConfigMaps("ns-a").Get(ctx, "routing", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data = map[string]string{"tenant-a": "provider-b"}
	if _, err := c.Kube().CoreV1().ConfigMaps("ns-a").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	testsupport.Eventually(t, 5*time.Second, func() error {
		return assertState(map[string]any{
			"inline":  map[string]string{"region": "cn-hangzhou"},
			"routing": map[string]string{"tenant-a": "provider-b"},
		}, false)
	})

	// Deleting the ConfigMap keeps the profile installed and enforcing, but
	// the inputs become unavailable rather than silently serving the stale
	// values; the compiled item is valid (no CompileError).
	if err := c.Kube().CoreV1().ConfigMaps("ns-a").Delete(ctx, "routing", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		compiled := profiles.GetKey("ns-a/with-inputs")
		if compiled == nil {
			return fmt.Errorf("profile disappeared from the compiled collection")
		}
		if compiled.CompileError != "" {
			return fmt.Errorf("missing ConfigMap must not reject the profile, got CompileError %q", compiled.CompileError)
		}
		return assertState(nil, true)
	})

	// Recreating the ConfigMap heals the inputs.
	if _, err := c.Kube().CoreV1().ConfigMaps("ns-a").Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "routing", Namespace: "ns-a"},
		Data:       map[string]string{"tenant-a": "provider-c"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		return assertState(map[string]any{
			"inline":  map[string]string{"region": "cn-hangzhou"},
			"routing": map[string]string{"tenant-a": "provider-c"},
		}, false)
	})
}

// TestProfileCollection_EndToEnd drives the krt-backed collection into the
// store against fake clients: initial state replay, live adds for both
// scopes, updates, invalid-update LKG retention, and deletes.
func TestProfileCollection_EndToEnd(t *testing.T) {
	existing := newTestProfile("existing", "ns-a", map[string]string{"app": "test"})
	c := newProfileTestClient(existing)
	agentsCS := c.AgentsAPI()
	stop := t.Context().Done()
	c.Run(stop)

	store := NewStore()
	profiles := NewCollection(c, nil, krt.GlobalDebugHandler, stop)
	reg := store.RegisterCollection(profiles)
	if !reg.WaitUntilSynced(stop) {
		t.Fatal("profile collection handler never synced")
	}

	ctx := t.Context()

	// Initial state replay delivers the pre-existing profile.
	testsupport.Eventually(t, 5*time.Second, func() error {
		if n := len(store.ProfilesFor(inputs.Pod{Namespace: "ns-a", Labels: map[string]string{"app": "test"}})); n != 1 {
			return fmt.Errorf("expected 1 match in ns-a, got %d", n)
		}
		return nil
	})

	// Live SecurityProfile add.
	live := newTestProfile("live", "ns-b", map[string]string{"app": "test"})
	if _, err := agentsCS.AgentsV1alpha1().SecurityProfiles("ns-b").Create(ctx, live, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		if n := len(store.ProfilesFor(inputs.Pod{Namespace: "ns-b", Labels: map[string]string{"app": "test"}})); n != 1 {
			return fmt.Errorf("expected 1 match in ns-b, got %d", n)
		}
		return nil
	})

	// Live GlobalSecurityProfile add matches pods in every namespace.
	gsp := newTestGlobalProfile("global", map[string]string{"app": "test"})
	if _, err := agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Create(ctx, gsp, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		if n := len(store.ProfilesFor(inputs.Pod{Namespace: "ns-c", Labels: map[string]string{"app": "test"}})); n != 1 {
			return fmt.Errorf("expected global profile to match ns-c, got %d", n)
		}
		return nil
	})

	// An update that turns the profile invalid remains visible in the compiled
	// collection, while the store continues serving the last-known-good profile.
	bad := live.DeepCopy()
	bad.Spec.Selector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key:      "!",
		Operator: metav1.LabelSelectorOpExists,
	}}}
	if _, err := agentsCS.AgentsV1alpha1().SecurityProfiles("ns-b").Update(ctx, bad, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		compiled := profiles.GetKey("ns-b/live")
		if compiled == nil || compiled.CompileError == "" {
			return fmt.Errorf("compiled collection has not observed invalid update")
		}
		matched := store.ProfilesFor(inputs.Pod{Namespace: "ns-b", Labels: map[string]string{"app": "test"}})
		if len(matched) != 2 {
			names := make([]string, 0, len(matched))
			for _, sp := range matched {
				names = append(names, sp.Meta.Name)
			}
			return fmt.Errorf("expected invalid update to retain live plus global profiles, got %v", names)
		}
		return nil
	})

	// Delete removes the cluster-scoped profile.
	if err := agentsCS.AgentsV1alpha1().GlobalSecurityProfiles().Delete(ctx, "global", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		if n := len(store.ProfilesFor(inputs.Pod{Namespace: "ns-c", Labels: map[string]string{"app": "test"}})); n != 0 {
			return fmt.Errorf("expected global profile removal, still %d matches", n)
		}
		return nil
	})
}

// The Sandbox CRD may be absent: the EPE chart does not install the
// agents.kruise.io CRDs, and the e2e clusters start without them. The joined
// collection must still sync so startup is not wedged behind
// WaitUntilSynced. The fake apiserver tolerates unknown GVRs, so this test
// cannot reproduce the real 404-retry hang of a non-delayed informer; it
// pins the delayed-informer wiring (CRD-absent sync plus an empty result
// set) so the intent documented here stays visible.
func TestCompileSandboxProfileDistinguishesPrewarmFromClaimedEmpty(t *testing.T) {
	sandbox := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Name: "sbx-1", Namespace: "sandboxes", ResourceVersion: "1",
	}}

	prewarm := compileSandboxProfile(sandbox, nil)
	if prewarm.SandboxState != securityprofile.SandboxPolicyUnknown {
		t.Fatalf("prewarm state = %v, want Unknown", prewarm.SandboxState)
	}

	claimed := sandbox.DeepCopy()
	claimed.ResourceVersion = "2"
	claimed.Labels = map[string]string{v1alpha1.LabelSandboxIsClaimed: v1alpha1.True}
	empty := compileSandboxProfile(claimed, nil)
	if empty.SandboxState != securityprofile.SandboxPolicyReadyEmpty {
		t.Fatalf("claimed empty state = %v, want ReadyEmpty", empty.SandboxState)
	}
}

func TestProfileCollection_SyncsWithoutSandboxCRD(t *testing.T) {
	c := newProfileTestClient()
	// Deliberately no Sandbox CRD.
	stop := t.Context().Done()

	store := NewStore()
	profiles := NewCollection(c, nil, krt.GlobalDebugHandler, stop)
	reg := store.RegisterCollection(profiles)
	c.Run(stop)

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
	if got := store.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"}); len(got) != 0 {
		t.Fatalf("Matches = %+v, want no profiles without the CRD", got)
	}
}

// TestProfileCollection_MissingConfigMapOnFirstCreate is the key regression
// for the inputs-degradation model: a profile created while its ConfigMap
// input does not exist must still install with all rules in effect — a Block
// rule keeps protecting the pods it selects — while the inputs are marked
// unavailable until the ConfigMap appears.
func TestProfileCollection_MissingConfigMapOnFirstCreate(t *testing.T) {
	profile := newTestProfile("first-create", "ns-a", map[string]string{"app": "test"})
	profile.Spec.Inputs = []v1alpha1.SecurityProfileInput{
		{Name: "routing", ConfigMap: &v1alpha1.ConfigMapInputRef{Name: "missing"}},
	}
	profile.Spec.Rules = []v1alpha1.SecurityRule{{
		Name:    "deny-all",
		Match:   []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
		Actions: v1alpha1.SecurityRuleActions{Block: &v1alpha1.BlockAction{StatusCode: 403}},
	}}
	c := newProfileTestClient(profile)
	stop := t.Context().Done()

	store := NewStore()
	profiles := NewCollection(c, nil, krt.GlobalDebugHandler, stop)
	reg := store.RegisterCollection(profiles)
	c.Run(stop)
	if !reg.WaitUntilSynced(stop) {
		t.Fatal("profile collection handler never synced")
	}

	testsupport.Eventually(t, 5*time.Second, func() error {
		matched := store.ProfilesFor(inputs.Pod{Namespace: "ns-a", Labels: map[string]string{"app": "test"}})
		if len(matched) != 1 {
			return fmt.Errorf("matched profiles = %d, want 1 despite the missing ConfigMap", len(matched))
		}
		sp := matched[0]
		if len(sp.Rules) != 1 || sp.Rules[0].Actions.Block == nil {
			return fmt.Errorf("block rule not installed: %+v", sp.Rules)
		}
		if sp.InputsError == "" {
			return fmt.Errorf("expected InputsError to mark the missing ConfigMap")
		}
		if sp.Inputs != nil {
			return fmt.Errorf("expected no resolved inputs, got %#v", sp.Inputs)
		}
		return nil
	})

	// The krt dependency registered by the failed fetch recompiles the
	// profile when the ConfigMap appears.
	ctx := t.Context()
	if _, err := c.Kube().CoreV1().ConfigMaps("ns-a").Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "ns-a"},
		Data:       map[string]string{"k": "v"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		matched := store.ProfilesFor(inputs.Pod{Namespace: "ns-a", Labels: map[string]string{"app": "test"}})
		if len(matched) != 1 {
			return fmt.Errorf("matched profiles = %d, want 1", len(matched))
		}
		if matched[0].InputsError != "" {
			return fmt.Errorf("InputsError not cleared: %q", matched[0].InputsError)
		}
		if !reflect.DeepEqual(matched[0].Inputs, map[string]any{"routing": map[string]string{"k": "v"}}) {
			return fmt.Errorf("inputs = %#v", matched[0].Inputs)
		}
		return nil
	})
}

// TestProfileCollection_ProjectionErrorRejectsVersion pins the
// collection-time half of the credential-parameter failure semantics: an
// uncompilable parameter CEL expression rejects the profile version at the
// collection boundary — retaining the last-known-good version — instead of
// failing lazily on the first matching request, where the ext_proc provider's
// global failureModeAllow would decide the outcome.
func TestProfileCollection_ProjectionErrorRejectsVersion(t *testing.T) {
	regs, err := filter.Build(tokentransform.NewDefinition(tokentransform.Deps{}))
	if err != nil {
		t.Fatal(err)
	}

	good := newTestProfile("cred", "ns-a", map[string]string{"app": "test"})
	good.Spec.Rules = []v1alpha1.SecurityRule{{
		Name:  "sign",
		Match: []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
		Actions: v1alpha1.SecurityRuleActions{TokenTransformation: &v1alpha1.TokenTransformationAction{
			Type:          v1alpha1.TokenTransformationTypeApiKey,
			CredentialRef: v1alpha1.CredentialRef{Secret: &v1alpha1.SecretCredentialRef{Name: "creds"}},
			ApiKey:        &v1alpha1.ApiKeyConfig{ValueTemplate: "Bearer {{ .Token }}"},
		}},
	}}
	c := newProfileTestClient(good)
	agentsCS := c.AgentsAPI()
	stop := t.Context().Done()

	store := NewStore()
	profiles := NewCollection(c, regs, krt.GlobalDebugHandler, stop)
	reg := store.RegisterCollection(profiles)
	c.Run(stop)
	if !reg.WaitUntilSynced(stop) {
		t.Fatal("profile collection handler never synced")
	}

	testsupport.Eventually(t, 5*time.Second, func() error {
		if n := len(store.ProfilesFor(inputs.Pod{Namespace: "ns-a", Labels: map[string]string{"app": "test"}})); n != 1 {
			return fmt.Errorf("expected 1 match, got %d", n)
		}
		return nil
	})

	// An update whose credential parameter CEL does not compile is rejected
	// at the collection boundary; the store keeps serving the good version.
	ctx := t.Context()
	badCel := "this is not CEL ((("
	bad := good.DeepCopy()
	bad.Spec.Rules[0].Actions.TokenTransformation.CredentialRef = v1alpha1.CredentialRef{
		CredentialProvider: &v1alpha1.CredentialProviderRef{
			Name:       "provider",
			Parameters: map[string]v1alpha1.ValueSource{"tenant": {Cel: &badCel}},
		},
	}
	if _, err := agentsCS.AgentsV1alpha1().SecurityProfiles("ns-a").Update(ctx, bad, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testsupport.Eventually(t, 5*time.Second, func() error {
		compiled := profiles.GetKey("ns-a/cred")
		if compiled == nil || compiled.CompileError == "" {
			return fmt.Errorf("projection error has not rejected the update")
		}
		matched := store.ProfilesFor(inputs.Pod{Namespace: "ns-a", Labels: map[string]string{"app": "test"}})
		if len(matched) != 1 {
			return fmt.Errorf("expected last-known-good version to keep serving, got %d matches", len(matched))
		}
		if matched[0].Rules[0].Actions.TokenTransformation.CredentialRef.Secret == nil {
			return fmt.Errorf("store is serving the rejected version")
		}
		return nil
	})
}
