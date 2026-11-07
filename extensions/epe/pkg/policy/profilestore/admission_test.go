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
	"errors"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
)

func TestAdmissionRejectionRecoveryAndRemoval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   string
		sandbox bool
	}{
		{"namespaced/ns/policy", scopeNamespaced, false},
		{"global/policy", scopeGlobal, false},
		{"kruise:one", scopeSandbox, true},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			status := NewXDSStore()
			before := promtest.ToFloat64(profileCompileFailuresTotal.WithLabelValues(tc.scope))
			meta := securityprofile.Meta{Name: "policy"}
			if tc.scope == scopeNamespaced {
				meta.Namespace = "ns"
			}
			if tc.sandbox {
				meta.Match = securityprofile.MatchSandbox
			}
			failure := errors.New("invalid config")
			status.ObserveAdmission(meta, false, failure)
			if unenforcedCount(t, tc.scope) != 1 || staleCount(t, tc.scope) != 0 {
				t.Fatal("first rejection not reported")
			}
			// Evicting an invalid first version must not leave a permanent alarm.
			status.ObserveAdmission(meta, false, nil)
			if unenforcedCount(t, tc.scope) != 0 {
				t.Fatal("eviction retained alarm")
			}

			status.ObserveAdmission(meta, true, nil)
			status.ObserveAdmission(meta, true, failure)
			if staleCount(t, tc.scope) != 1 || unenforcedCount(t, tc.scope) != 0 {
				t.Fatal("retained version not reported")
			}
			status.ObserveAdmission(meta, true, nil)
			if staleCount(t, tc.scope) != 0 {
				t.Fatal("accepted recovery did not clear alarm")
			}
			status.ObserveAdmission(meta, true, failure)
			status.ObserveAdmission(meta, false, nil)
			if staleCount(t, tc.scope) != 0 || unenforcedCount(t, tc.scope) != 0 {
				t.Fatal("deletion retained alarm")
			}
			if got := promtest.ToFloat64(profileCompileFailuresTotal.WithLabelValues(tc.scope)) - before; got != 3 {
				t.Fatalf("compile failures = %v, want 3", got)
			}
		})
	}
}

func TestRejectedSourceInputsFollowConfigMapsWithoutRequests(t *testing.T) {
	profile, err := securityprofile.FromXDS(
		&securityv1.SecurityProfile{
			Name:       "policy",
			Namespace:  "ns",
			PolicyJson: []byte(`{"inputs":[{"name":"settings","configMap":{"name":"settings"}}]}`),
		},
		"",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	cms := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, krt.WithStop(t.Context().Done()))
	status := NewXDSStore()
	source := krt.NewMutableCollection(nil, []securityprofile.Profile{*profile}, krt.WithStop(t.Context().Done()))
	collection := NewSourceCollection(source.AsCollection(), cms.AsCollection(), krt.WithStop(t.Context().Done()))
	status.RegisterCollection(collection, nil)
	status.ObserveAdmission(profile.Meta, true, nil)
	testutil.Eventually(
		t,
		func() bool { return inputsUnavailableCount(t, scopeNamespaced) == 1 },
		"input status initial publication",
	)
	if inputsUnavailableCount(t, scopeNamespaced) != 1 {
		t.Fatal("missing input not reported on acceptance")
	}
	status.ObserveAdmission(profile.Meta, true, errors.New("bad update"))
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"}}
	cms.UpdateObject(cm)
	testutil.Eventually(
		t,
		func() bool { return inputsUnavailableCount(t, scopeNamespaced) == 0 },
		"input recovery without a request",
	)
	if staleCount(t, scopeNamespaced) != 1 {
		t.Fatal("ConfigMap update cleared rejected policy state")
	}
	cms.DeleteObject("ns/settings")
	testutil.Eventually(
		t,
		func() bool { return inputsUnavailableCount(t, scopeNamespaced) == 1 },
		"input deletion without a request",
	)
	status.ObserveAdmission(profile.Meta, false, nil)
	source.DeleteObject(profile.ResourceName())
	testutil.Eventually(t, func() bool {
		return inputsUnavailableCount(t, scopeNamespaced) == 0 && status.snapshot.Load().get(profile.Meta) == nil
	}, "eviction clears derived policy and input status")
	if inputsUnavailableCount(t, scopeNamespaced) != 0 || staleCount(t, scopeNamespaced) != 0 {
		t.Fatal("eviction retained degraded state")
	}
}
