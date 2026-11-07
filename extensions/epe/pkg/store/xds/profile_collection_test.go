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

package xds

import (
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

func TestSandboxReplacementRetainsNewProfile(t *testing.T) {
	source := NewProfileSource(profilestore.NewXDSStore().ObserveAdmission, t.Context().Done())
	cms := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(t.Context().Done()))
	collection := source.Collection(cms.AsCollection(), krt.WithStop(t.Context().Done()))
	watch := source.Watches(nil)[1]
	var newest *sandboxProfiles
	for _, uid := range []string{"kruise:old", "kruise:new"} {
		value, err := watch.Transform(packed(&sandboxv1.Sandbox{
			Uid:        uid,
			Extensions: []*anypb.Any{packed(profilePayload("ns"))},
		}))
		if err != nil {
			t.Fatal(err)
		}
		newest = value.(*sandboxProfiles)
		watch.OnChange(uid, &xdsclient.Resource{Value: value}, nil)
	}
	// A delta publishes the replacement before removing the previous UID.
	watch.OnChange("kruise:old", nil, nil)
	testutil.Eventually(t, func() bool {
		profile := collection.GetKey(newest.profile.ResourceName())
		return profile != nil && profile.Meta.SandboxUID == "kruise:new"
	}, "old Sandbox deletion must retain its same-name replacement")
	watch.OnChange("kruise:new", nil, nil)
	testutil.Eventually(t, func() bool {
		return collection.GetKey(newest.profile.ResourceName()) == nil
	}, "deleting the current Sandbox removes its profile")
}

func TestProfileCollectionInputsNACKAndEviction(t *testing.T) {
	local := profilestore.NewXDSStore()
	source := NewProfileSource(local.ObserveAdmission, t.Context().Done())
	watches := source.Watches(nil)
	f := testSource()
	f.snapshot.Synced[model.SecurityProfileType], f.snapshot.Synced[model.SandboxType] = true, true
	f.snapshot.Resources[model.SecurityProfileType] = map[string]*xdsclient.Resource{}
	native := New(f)
	cms := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(t.Context().Done()))
	collection := source.Collection(cms.AsCollection(), krt.WithStop(t.Context().Done()))
	reg := local.RegisterCollection(collection, native.AcquireProfileReferences)
	t.Cleanup(reg.UnregisterHandler)
	if !reg.WaitUntilSynced(t.Context().Done()) {
		t.Fatal("profile collection did not sync")
	}
	resourceName := "namespaced/ns/policy"
	body := profilePayload("ns")
	body.PolicyJson = []byte(`{"inputs":[{"name":"settings","configMap":{"name":"settings"}}]}`)
	publish := func() error {
		t.Helper()
		value, err := watches[0].Transform(packed(body))
		current := f.snapshot.Resources[model.SecurityProfileType][resourceName]
		if err == nil {
			current = &xdsclient.Resource{Value: value}
			f.snapshot.Resources[model.SecurityProfileType][resourceName] = current
			f.notify()
		}
		watches[0].OnChange(resourceName, current, err)
		return err
	}
	if err := publish(); err != nil {
		t.Fatal(err)
	}
	subj := subject.Subject{Workload: subject.Workload{SecurityProfileReferences: []string{resourceName}}}
	missing, err := local.ResolveProfiles(t.Context(), subj)
	if err != nil || len(missing) != 1 || missing[0].InputsError == "" {
		t.Fatal("first request did not wait for dependency publication", missing, err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "settings"},
		Data:       map[string]string{"value": "first"},
	}
	cms.UpdateObject(cm)
	testutil.Eventually(t, func() bool {
		p := collection.GetKey("ns/policy")
		return p != nil && p.InputsError == ""
	}, "ConfigMap creation updates policy without a request")
	first, err := local.ResolveProfiles(t.Context(), subj)
	if err != nil || first[0].Inputs["settings"].(map[string]string)["value"] != "first" {
		t.Fatal("resolved inputs missing", err)
	}
	body.PolicyJson = []byte(`{"unsupported":true}`)
	if err := publish(); err == nil {
		t.Fatal("invalid version admitted")
	}
	cm = cm.DeepCopy()
	cm.Data["value"] = "second"
	cms.UpdateObject(cm)
	testutil.Eventually(t, func() bool {
		p := collection.GetKey("ns/policy")
		return p != nil && p.Inputs["settings"].(map[string]string)["value"] == "second"
	}, "NACK retains accepted source dependencies")
	second, err := local.ResolveProfiles(t.Context(), subj)
	if err != nil || second[0].Inputs["settings"].(map[string]string)["value"] != "second" ||
		first[0].Inputs["settings"].(map[string]string)["value"] != "first" {
		t.Fatal("dependency update changed an in-flight request", err)
	}
	cms.DeleteObject("ns/settings")
	testutil.Eventually(t, func() bool {
		p := collection.GetKey("ns/policy")
		return p != nil && p.InputsError != ""
	}, "missing ConfigMap invalidates accepted inputs after NACK")
	delete(f.snapshot.Resources[model.SecurityProfileType], resourceName)
	f.notify()
	watches[0].OnChange(resourceName, nil, nil)
	testutil.Eventually(t, func() bool {
		return len(source.profiles.List()) == 0 && len(collection.List()) == 0
	}, "eviction releases all derived profile state")
	cm = cm.DeepCopy()
	cm.Data["value"] = "after-eviction"
	cms.UpdateObject(cm)
	// A different accepted policy makes the dependency queue process subsequent work.
	body.PolicyJson = []byte(`{}`)
	body.Name = "other"
	resourceName = "namespaced/ns/other"
	if err := publish(); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(
		t,
		func() bool { return collection.GetKey("ns/other") != nil },
		"unrelated publication after eviction",
	)
	if collection.GetKey("ns/policy") != nil {
		t.Fatal("ConfigMap update resurrected an evicted policy")
	}
}
