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

package profilestore

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
)

func TestXDSInputsUseEPEConfigMapsAndPinRequestValues(t *testing.T) {
	profile, err := securityprofile.FromXDS(
		&securityv1.SecurityProfile{
			Name:      "policy",
			Namespace: "ns",
			PolicyJson: json.RawMessage(
				`{"inputs":[{"name":"settings","configMap":{"name":"settings"}},{"name":"inline","inline":{"value":"constant"}}]}`,
			),
		},
		"",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	source := krt.NewMutableCollection(nil, []securityprofile.Profile{*profile}, krt.WithStop(t.Context().Done()))
	cms := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(t.Context().Done()))
	matcher := NewStore(0)
	collection := NewSourceCollection(source.AsCollection(), cms.AsCollection(), krt.WithStop(t.Context().Done()))
	reg := matcher.RegisterCollection(collection)
	if !reg.WaitUntilSynced(t.Context().Done()) {
		t.Fatal("profile collection did not sync")
	}
	subj := subject.Subject{Workload: subject.Workload{SecurityProfileReferences: []string{"namespaced/ns/policy"}}}
	missing, err := matcher.ResolveProfiles(t.Context(), subj)
	if err != nil || len(missing) != 1 || missing[0].InputsError == "" || missing[0].Inputs != nil {
		t.Fatalf("missing input removed rules or retained partial values: %v %v", missing, err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"},
		Data:       map[string]string{"value": "first"},
	}
	cms.UpdateObject(cm)
	testutil.Eventually(t, func() bool {
		p := collection.GetKey(profile.ResourceName())
		return p != nil && p.InputsError == ""
	}, "input creation published without a request")
	first, err := matcher.ResolveProfiles(t.Context(), subj)
	if err != nil || first[0].InputsError != "" || first[0].Inputs["settings"].(map[string]string)["value"] != "first" {
		t.Fatalf("EPE input resolution: %v %v", first, err)
	}
	cm = cm.DeepCopy()
	cm.Data["value"] = "second"
	cms.UpdateObject(cm)
	testutil.Eventually(t, func() bool {
		p := collection.GetKey(profile.ResourceName())
		return p != nil && p.Inputs["settings"].(map[string]string)["value"] == "second"
	}, "input update published without a request")
	second, err := matcher.ResolveProfiles(t.Context(), subj)
	if err != nil || second[0].Inputs["settings"].(map[string]string)["value"] != "second" ||
		first[0].Inputs["settings"].(map[string]string)["value"] != "first" ||
		profile.Inputs != nil {
		t.Fatal("input update mutated an in-flight request or the shared profile", err)
	}
	cms.DeleteObject("ns/settings")
	testutil.Eventually(t, func() bool {
		p := collection.GetKey(profile.ResourceName())
		return p != nil && p.InputsError != ""
	}, "input deletion published without a request")
	deleted, err := matcher.ResolveProfiles(t.Context(), subj)
	if err != nil || deleted[0].InputsError == "" || deleted[0].Inputs != nil {
		t.Fatal("deleted input served stale values", err)
	}
}

func TestXDSRequestWaitsForAdmittedRevision(t *testing.T) {
	for _, outcome := range []string{"publish", "remove", "replace", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			profile, err := securityprofile.FromXDS(
				&securityv1.SecurityProfile{
					Name:       "policy",
					Namespace:  "ns",
					Uid:        "source",
					PolicyJson: []byte(`{}`),
				},
				"",
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			profile.Meta.AdmissionRevision = 1
			next := *profile
			next.Meta.AdmissionRevision = 2
			source := krt.NewMutableCollection(
				nil,
				[]securityprofile.Profile{*profile},
				krt.WithStop(t.Context().Done()),
			)
			var releases atomic.Int32
			acquire := func(context.Context, subject.Subject) ([]*securityprofile.Meta, func(), error) {
				return []*securityprofile.Meta{&next.Meta}, func() { releases.Add(1) }, nil
			}
			collection := NewSourceCollection(source.AsCollection(), nil, krt.WithStop(t.Context().Done()))
			matcher := NewXDSStore()
			reg := matcher.RegisterCollection(collection, acquire)
			t.Cleanup(collection.Registry.RegisterDeletes(matcher.NotifyKeys))
			if !reg.WaitUntilSynced(t.Context().Done()) {
				t.Fatal("profile collection did not sync")
			}
			type result struct {
				profiles []*securityprofile.Profile
				err      error
			}
			done := make(chan result, 1)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			go func() {
				profiles, err := matcher.ResolveProfiles(ctx, subject.Subject{})
				done <- result{profiles, err}
			}()
			testutil.Eventually(t, func() bool {
				matcher.mu.Lock()
				defer matcher.mu.Unlock()
				return len(matcher.pending) == 1
			}, "request waits for the admitted source revision")
			if releases.Load() != 0 {
				t.Fatal("released sources before publication")
			}
			select {
			case value := <-done:
				t.Fatalf("served old revision: %v", value)
			default:
			}
			published := next
			published.Meta.AdmissionRevision = 3
			switch outcome {
			case "publish":
				source.UpdateObject(published)
			case "remove":
				source.DeleteObject(profile.ResourceName())
			case "replace":
				published.Meta.SourceIdentity.UID = "replacement"
				source.UpdateObject(published)
			case "cancel":
				cancel()
			}
			var value result
			select {
			case value = <-done:
			case <-t.Context().Done():
				t.Fatal("profile request did not finish")
			}
			if outcome == "publish" {
				if value.err != nil || len(value.profiles) != 1 || value.profiles[0].Meta.AdmissionRevision != 3 {
					t.Fatal("admitted revision was not published", value.err)
				}
			} else if value.err == nil || len(value.profiles) != 0 {
				t.Fatal("unavailable candidate served a policy", value)
			}
			if outcome == "cancel" && !errors.Is(value.err, context.Canceled) {
				t.Fatal(value.err)
			}
			matcher.mu.Lock()
			pending := len(matcher.pending)
			matcher.mu.Unlock()
			if releases.Load() != 1 || pending != 0 {
				t.Fatal("request retained leases or waiters")
			}
		})
	}
}
