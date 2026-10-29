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

package policystatus

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/test/util/assert"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	registry "github.com/openkruise/agentio/pkg/registry/kubernetes"
)

func mutable[T any](t *testing.T) krt.StaticCollection[T] {
	t.Helper()
	return krt.NewMutableCollection[T](nil, nil, krt.WithStop(t.Context().Done()))
}

func testController(t *testing.T, scoped bool) (*Controller, *registry.Registry) {
	t.Helper()
	r := &registry.Registry{
		SecurityProfileObjects:       mutable[*agents.SecurityProfile](t).AsCollection(),
		GlobalSecurityProfileObjects: mutable[*agents.GlobalSecurityProfile](t).AsCollection(),
		TrafficPolicyObjects:         mutable[*agents.TrafficPolicy](t).AsCollection(),
		GlobalTrafficPolicyObjects:   mutable[*agents.GlobalTrafficPolicy](t).AsCollection(),
		ConfigMaps:                   mutable[*corev1.ConfigMap](t).AsCollection(),
		Secrets:                      mutable[*corev1.Secret](t).AsCollection(),
		Pods:                         mutable[*corev1.Pod](t).AsCollection(),
		KubernetesServices:           mutable[*corev1.Service](t).AsCollection(),
		EndpointSlices:               mutable[*discoveryv1.EndpointSlice](t).AsCollection(),
	}
	c, err := New(kube.NewFakeClient(), r, "system", scoped,
		func(krt.HandlerContext, string) []netip.Addr { return nil }, t.Context().Done())
	assert.NoError(t, err)
	assert.Equal(t, c.results.WaitUntilSynced(t.Context().Done()), true)
	return c, r
}

func profileSource(t *testing.T, raw, namespace string) source {
	t.Helper()
	var spec agents.SecurityProfileSpec
	assert.NoError(t, json.Unmarshal([]byte(raw), &spec))
	kind, resource := "SecurityProfile", "securityprofiles"
	if namespace == "" {
		kind, resource = "GlobalSecurityProfile", "globalsecurityprofiles"
	}
	return *policySource(metav1.ObjectMeta{
		Name:       "test",
		Namespace:  namespace,
		UID:        "original",
		Generation: 3,
	}, kind, resource, &spec, nil)
}

func awaitResult(
	t *testing.T,
	results krt.Collection[result],
	key string,
	accepted, refs metav1.ConditionStatus,
	reason string,
) result {
	t.Helper()
	var got *result
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("last result: %+v", got)
		}
	})
	assert.EventuallyEqual(t, func() bool {
		got = results.GetKey(key)
		return got != nil && got.Conditions[0].Status == accepted &&
			got.Conditions[1].Status == refs && got.Conditions[1].Reason == reason
	}, true)
	assert.Equal(t, len(got.Conditions), 2)
	for _, condition := range got.Conditions {
		assert.Equal(t, got.Source.Metadata.Generation, condition.ObservedGeneration)
	}
	return *got
}

func TestSharedProfileValidation(t *testing.T) {
	c, _ := testController(t, false)
	for _, tc := range []struct {
		name  string
		spec  string
		valid bool
	}{
		{"empty", `{}`, true},
		{"audit CEL uses inputs and result", `{"audit":[{"name":"log","when":"result == 'error' && inputs.config.enabled == 'true'","webhook":{"url":"http://audit"}}]}`, true},
		{"audit CEL invalid", `{"audit":[{"name":"log","when":"unknownVariable","webhook":{"url":"http://audit"}}]}`, false},
		{"audit JSON template invalid", `{"audit": [{"name": "log", "webhook": {"url": "http://audit", "request": {"body": {"json": {"nested": {"text": "{{"}}}}}}]}`, false},
		{"regex invalid", `{"rules":[{"name":"r","match":[{"paths":[{"type":"Regex","value":"["}]}]}]}`, false},
		{"negative priority", `{"priority":-1}`, false},
		{"input union invalid", `{"inputs":[{"name":"config","inline":{"key":"value"},"configMap":{"name":"config"}}]}`, false},
		{"callout without phases", `{"rules":[{"name":"r","actions":{"httpCallout":{"provider":{"name":"scanner"}}}}]}`, false},
		{"token template invalid", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"{{"}}}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := profileSource(t, tc.spec, "demo")
			compiled := c.compileProfile(s)
			assert.Equal(t, tc.valid, compiled.Accepted.Status == metav1.ConditionTrue, compiled.Accepted.Message)
		})
	}
}

func TestProfileReferencesRecoverWithoutSpecChange(t *testing.T) {
	c, r := testController(t, false)
	maps := mutable[*corev1.ConfigMap](t)
	secrets := mutable[*corev1.Secret](t)
	r.ConfigMaps, r.Secrets = maps.AsCollection(), secrets.AsCollection()
	s := profileSource(
		t,
		`{"inputs":[{"name":"config","configMap":{"name":"config"}}],"rules":[{"name":"auth","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`,
		"demo",
	)
	profiles := krt.NewStaticCollection(nil, []compiledProfile{*c.compileProfile(s)}, krt.WithStop(t.Context().Done()))
	results := krt.NewCollection(profiles, c.profileStatus, krt.WithStop(t.Context().Done()))
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "ConfigMapNotFound")
	maps.UpdateObject(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "demo"}})
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "SecretNotFound")
	secrets.UpdateObject(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cred", Namespace: "demo"}})
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, "ResolvedRefs")
	maps.DeleteObject("demo/config")
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "ConfigMapNotFound")
}

func TestUnobservableProfileReferences(t *testing.T) {
	c, _ := testController(t, true)
	for _, tc := range []struct {
		name      string
		namespace string
		spec      string
		accepted  metav1.ConditionStatus
		status    metav1.ConditionStatus
		reason    string
	}{
		{"scoped secret", "demo", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"kind":"Secret","name":"cred"},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`, metav1.ConditionTrue, metav1.ConditionUnknown, "OutsideWatchScope"},
		{"global implicit secret", "", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`, metav1.ConditionTrue, metav1.ConditionUnknown, "RuntimeResolutionRequired"},
		{"credential provider", "demo", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"credentialProvider":{"name":"provider"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`, metav1.ConditionTrue, metav1.ConditionUnknown, "RuntimeResolutionRequired"},
		{"callout", "demo", `{"rules":[{"name":"r","actions":{"httpCallout":{"provider":{"name":"scanner"},"request":{}}}}]}`, metav1.ConditionTrue, metav1.ConditionUnknown, "RuntimeResolutionRequired"},
		{"disabled transform", "demo", `{"rules":[{"name":"r","actions":{"tokenTransformation":{"disabled":true}}}]}`, metav1.ConditionTrue, metav1.ConditionTrue, "ResolvedRefs"},
		{"invalid global configmap", "", `{"inputs":[{"name":"config","configMap":{"name":"config"}}]}`, metav1.ConditionFalse, metav1.ConditionUnknown, "NotChecked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := profileSource(t, tc.spec, tc.namespace)
			profiles := krt.NewStaticCollection(
				nil,
				[]compiledProfile{*c.compileProfile(s)},
				krt.WithStop(t.Context().Done()),
			)
			results := krt.NewCollection(profiles, c.profileStatus, krt.WithStop(t.Context().Done()))
			awaitResult(t, results, s.ResourceName(), tc.accepted, tc.status, tc.reason)
		})
	}
}

func TestTrafficReferencesAndValidation(t *testing.T) {
	c, r := testController(t, false)
	services := mutable[*corev1.Service](t)
	r.KubernetesServices = services.AsCollection()
	c.traffic.Services = r.KubernetesServices
	addresses := []netip.Addr(nil)
	dns := krt.NewStatic(&addresses, true, krt.WithStop(t.Context().Done()))
	c.traffic.Resolve = func(ctx krt.HandlerContext, _ string) []netip.Addr {
		return *krt.FetchOne(ctx, dns.AsCollection())
	}
	var spec agents.TrafficPolicySpec
	assert.NoError(
		t,
		json.Unmarshal(
			[]byte(
				`{"egress":{"rules":[{"action":"allow","to":[{"service":{"name":"api"}},{"fqdn":"api.example.com"}]}]}}`,
			),
			&spec,
		),
	)
	s := *policySource(metav1.ObjectMeta{Name: "test", Namespace: "demo", Generation: 3}, "TrafficPolicy", "trafficpolicies", nil, &spec)
	sources := krt.NewMutableCollection(nil, []source{s}, krt.WithStop(t.Context().Done()))
	results := krt.NewCollection(sources.AsCollection(), c.trafficStatus, krt.WithStop(t.Context().Done()))
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "ServiceNotFound")
	services.UpdateObject(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "demo"}})
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionUnknown, "DNSResolutionPending")
	resolvedAddresses := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	dns.Set(&resolvedAddresses)
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionTrue, "ResolvedRefs")
	invalid := spec.DeepCopy()
	invalid.Priority = -1
	s.Traffic = invalid
	sources.UpdateObject(s)
	awaitResult(t, results, s.ResourceName(), metav1.ConditionFalse, metav1.ConditionUnknown, "NotChecked")
}

func TestSourcesExcludeStatusUpdates(t *testing.T) {
	_, r := testController(t, false)
	profiles := mutable[*agents.SecurityProfile](t)
	globals := mutable[*agents.GlobalSecurityProfile](t)
	traffic := mutable[*agents.TrafficPolicy](t)
	globalTraffic := mutable[*agents.GlobalTrafficPolicy](t)
	r.SecurityProfileObjects, r.GlobalSecurityProfileObjects = profiles.AsCollection(), globals.AsCollection()
	r.TrafficPolicyObjects, r.GlobalTrafficPolicyObjects = traffic.AsCollection(), globalTraffic.AsCollection()
	sources := newSources(r, krt.NewOptionsBuilder(t.Context().Done(), "test", nil))
	globalMeta := metav1.ObjectMeta{Name: "test", Generation: 1}
	meta := globalMeta
	meta.Namespace = "demo"
	profiles.UpdateObject(&agents.SecurityProfile{ObjectMeta: meta})
	globals.UpdateObject(&agents.GlobalSecurityProfile{ObjectMeta: globalMeta})
	traffic.UpdateObject(&agents.TrafficPolicy{ObjectMeta: meta})
	globalTraffic.UpdateObject(&agents.GlobalTrafficPolicy{ObjectMeta: globalMeta})
	assert.EventuallyEqual(t, func() bool { return len(sources.List()) == 4 }, true)
	controller, err := New(kube.NewFakeClient(), r, "system", false,
		func(krt.HandlerContext, string) []netip.Addr { return nil }, t.Context().Done())
	assert.NoError(t, err)
	for _, key := range []string{"securityprofiles/demo/test", "globalsecurityprofiles//test", "trafficpolicies/demo/test", "globaltrafficpolicies//test"} {
		awaitResult(
			t,
			controller.results,
			key,
			metav1.ConditionTrue,
			metav1.ConditionTrue,
			"ResolvedRefs",
		)
	}
	before := sources.GetKey("securityprofiles/demo/test")
	meta.ResourceVersion = "2"
	profiles.UpdateObject(&agents.SecurityProfile{
		ObjectMeta: meta,
		Status:     agents.SecurityProfileStatus{ObservedGeneration: 1},
	})
	// Read the projected source after the input update: metadata used by validation stays identical.
	after := policySource(meta, "SecurityProfile", "securityprofiles", &agents.SecurityProfileSpec{}, nil)
	assert.Equal(t, before.Equals(*after), true)
}

func TestWriterStopsAndReplaysOnRestart(t *testing.T) {
	c, _ := testController(t, false)
	s := profileSource(t, `{}`, "demo")
	c.results = krt.NewStaticCollection(nil, []result{{Source: s}}, krt.WithStop(t.Context().Done()))
	// Missing objects are harmless; each new leader must replay the current collection.
	for i := range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			c.runWriter(ctx)
			close(done)
		}()
		assert.EventuallyEqual(t, func() bool {
			return len(c.client.Dynamic().(*dynamicfake.FakeDynamicClient).Actions()) > i
		}, true)
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("writer did not stop")
		}
	}
}

func TestSecretCacheSynchronizationUpdatesStatus(t *testing.T) {
	c, _ := testController(t, false)
	ready := false
	synced := krt.NewStatic(&ready, true, krt.WithStop(t.Context().Done()))
	c.secretsSynced = synced
	s := profileSource(
		t,
		`{"rules":[{"name":"r","actions":{"tokenTransformation":{"credentialRef":{"secret":{"name":"cred"}},"apiKey":{"valueTemplate":"Bearer {{ .Token }}"}}}}]}`,
		"demo",
	)
	profiles := krt.NewStaticCollection(nil, []compiledProfile{*c.compileProfile(s)}, krt.WithStop(t.Context().Done()))
	results := krt.NewCollection(profiles, c.profileStatus, krt.WithStop(t.Context().Done()))
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionUnknown, "CacheNotSynced")
	complete := true
	synced.Set(&complete)
	awaitResult(t, results, s.ResourceName(), metav1.ConditionTrue, metav1.ConditionFalse, "SecretNotFound")
}
